#!/usr/bin/env python3
"""Linux form of check-turnip-darwin-host.py: drive the Turnip darwin backend through a real Vulkan instance against the host copy of
the NativeAdreno kernel stack, for each GPU the kernel can report (HOSTSIM_GPU: a740 for sheng, a630 for fajita).

The Linux Turnip build (build-turnip-linux-host.py) compiles the unchanged tu_knl_darwin.cc against the harness's IOKit and mach headers
(drivers/NativeAdreno/tests/hostsim/linux/include); libhostiokit.so is preloaded and answers those calls from the real GPU context,
VM, ring, submit and user-client code over software SMMU/CP peers. The software CP retires every submission and executes nothing, so
this proves enumeration, device facts, BO/IOVA/CPU-map traffic, pipeline compilation (NIR to IR3 for the reported chip) and the
submit/fence path, never pixels. --disasm keeps the IR3 disassembly of every compiled shader per GPU."""
import argparse
import os
import platform
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--gpu', action='append', choices=('a740', 'a630'), help='GPU(s) to report (default: both)')
parser.add_argument('--disasm', action='store_true', help='Keep the IR3 disassembly (IR3_SHADER_DEBUG=disasm) in the logs')
args = parser.parse_args()
gpus = args.gpu or ['a740', 'a630']

kit = ROOT / 'drivers/NativeAdreno'
sim = kit / 'tests/hostsim'
linux = sim / 'linux'
out = ROOT / 'build/turnip-darwin-linux-host'
out.mkdir(parents=True, exist_ok=True)
smmu = ROOT / 'kits/ArmSmmu4K'
pm4 = ROOT / 'kits/AdrenoPM4'
library = ROOT / 'build/mesa-tu-linux/src/freedreno/vulkan/libvulkan_freedreno.so'
if not library.exists():
    sys.exit('Build the Linux host Turnip first: python3 scripts/build-turnip-linux-host.py')
CC, CXX = 'clang', 'clang++'


def run(cmd):
    subprocess.run([str(c) for c in cmd], check=True)


includes = out / 'host-include'
for name in ['IOKit/IOTypes.h', 'IOKit/IOReturn.h', 'IOKit/IOBufferMemoryDescriptor.h', 'IOKit/IOLib.h', 'kern/task.h']:
    path = includes / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text('#include "XnuMemoryFixture.h"\n')
objects = []
for stem in ['ArmSmmu4KContext', 'ArmSmmu4KProgram', 'ArmSmmu4KLive', 'ArmSmmu4KStreams']:  # not ArmSmmu4KMmio, the AArch64 MMIO binding; the host peer is software
    obj = out / (stem + '.o')
    run([CC, '-std=c11', '-O1', '-fPIC', '-c', smmu / (stem + '.c'), '-o', obj])
    objects.append(obj)
obj = out / 'AdrenoPM4.o'
run([CC, '-std=c11', '-O1', '-fPIC', '-c', pm4 / 'AdrenoPM4.c', '-o', obj])
objects.append(obj)
kernel_flags = ['-std=c++23', '-O1', '-fPIC', '-I', includes, '-I', sim.parent, '-I', kit, '-I', smmu, '-I', pm4]
service = out / 'host_gpu_service.o'
run([CXX, *kernel_flags, '-c', sim / 'host_gpu_service.cpp', '-o', service])
core = []
for name in ['NativeAdrenoMemory', 'NativeAdrenoSmmuMemory', 'NativeAdrenoVm', 'NativeAdrenoRing', 'NativeAdrenoSubmit',
             'NativeAdrenoUserClient', 'NativeAdrenoTimer', 'NativeAdrenoSmmuContext', 'NativeAdrenoGpuContext']:
    obj = out / (name + '.o')
    source = kit / (name + '.cpp')
    text = source.read_text()
    if platform.machine() not in ('aarch64', 'arm64') and 'dsb sy' in text:
        # The kernel code's AArch64 barriers (submit, write-combine pool): a host full fence stands in on x86. The copy stays in
        # build/, beside the kernel's own include directory so its includes resolve the same way.
        source = out / 'portable' / (name + '.cpp')
        source.parent.mkdir(exist_ok=True)
        source.write_text(text.replace('__asm__ volatile("dsb sy":::"memory")', '__atomic_thread_fence(__ATOMIC_SEQ_CST)'))
    run([CXX, *kernel_flags, '-c', source, '-o', obj])
    core.append(obj)
shim_obj = out / 'host_iokit_shim_linux.o'
run([CXX, '-std=c++17', '-O1', '-fPIC', '-I', linux / 'include', '-c', linux / 'host_iokit_shim_linux.cpp', '-o', shim_obj])
shim = out / 'libhostiokit.so'
run([CXX, '-shared', '-o', shim, service, shim_obj, *core, *objects, '-lpthread'])
vk_include = ROOT / '.cache/mesa-work/include'
smoke = out / 'vulkan_smoke'
run([CC, '-std=c11', '-O1', '-I', vk_include, sim / 'vulkan_smoke.c', '-o', smoke, '-ldl'])
subprocess.run([sys.executable, ROOT / 'scripts/gen-turnip-smoke-shaders.py'], check=True)
plugin_smoke = out / 'plugin_smoke'
run([CXX, '-std=c++17', '-O1', '-I', ROOT / 'drivers/NativeMetal', '-I', vk_include, '-I', ROOT / 'build/turnip-smoke',
     linux / 'plugin_smoke_linux.cpp', '-o', plugin_smoke, '-ldl', '-lpthread'])

expect = {'a740': ('Turnip Adreno (TM) 740', 0x43050a01), 'a630': ('Turnip Adreno (TM) 630', 0x06030002)}
failures = 0
for gpu in gpus:
    env = {k: v for k, v in os.environ.items() if not k.startswith(('IR3_', 'FD_', 'TU_', 'MESA_'))}
    env.update(LD_PRELOAD=str(shim), HOSTSIM_GPU=gpu, MESA_LOG='')
    if args.disasm:
        env['IR3_SHADER_DEBUG'] = 'disasm'
    for name, program in [('vulkan', smoke), ('plugin', plugin_smoke)]:
        result = subprocess.run([str(program), str(library)], env=env, capture_output=True, text=True, timeout=600)
        log = out / ('%s-%s.log' % (gpu, name))
        log.write_text(result.stdout + result.stderr)
        device = re.search(r'^device: (.*) \(vendor 0x([0-9a-f]+) device 0x([0-9a-f]+)\)', result.stdout, re.M)
        shaders = len(re.findall(r'^(?:MESA: info: )?; \w+ prog \d+', result.stdout + result.stderr, re.M))
        ok = result.returncode == 0 and (name != 'vulkan' or ('PASS' in result.stdout and device and device.group(1) == expect[gpu][0]))
        print('%s: %s %s smoke%s%s; log %s' % ('PASS' if ok else 'FAIL', gpu, name,
              ' (%s, device id 0x%s)' % (device.group(1), device.group(3)) if device else '',
              ', %d shader disassemblies' % shaders if args.disasm else '', log))
        if not ok:
            failures += 1
            print('\n'.join((result.stdout + result.stderr).splitlines()[-15:]))
if failures:
    sys.exit('%d Linux host Turnip run(s) failed' % failures)
print('PASS: Turnip darwin backend on Linux drove instance, device, memory, pipelines and submissions for %s over the host kernel stack; '
      'no shader executed' % ', '.join(gpus))
