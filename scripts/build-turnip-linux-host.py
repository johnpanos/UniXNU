#!/usr/bin/env python3
"""Build the pinned Turnip with the Darwin kernel backend for the Linux host, for check-turnip-darwin-linux-host.py.

The Mac build (build-turnip-darwin.py --target host) needs xcrun; this one compiles the same patched Mesa tree with the host clang, the
unchanged tu_knl_darwin.cc taking IOKit/IOKitLib.h and mach/mach.h from the host harness (patch turnip-darwin-linux-host.patch). The
library leaves those IOKit calls undefined; the check preloads libhostiokit.so, which answers them. It never talks to a GPU. Fetches the
pinned Mesa commit into .cache/mesa-work and applies the recorded patches when the tree is absent. Output: build/mesa-tu-linux."""
import json
import os
from pathlib import Path
import subprocess
import sys
from mesa_patch_identity import validate_recorded_patches

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / '.cache/mesa-work'
OUT = ROOT / 'build/mesa-tu-linux'
pins = json.loads((ROOT / 'scripts/data/adreno-compiler-inputs.json').read_text())
if not (SOURCE / '.git').exists():
    SOURCE.mkdir(parents=True, exist_ok=True)
    subprocess.run(['git', 'init', '-q', str(SOURCE)], check=True)
    subprocess.run(['git', '-C', str(SOURCE), 'fetch', '-q', '--depth', '1', pins['mesa']['repository'], pins['mesa']['commit']], check=True)
    subprocess.run(['git', '-C', str(SOURCE), 'checkout', '-q', 'FETCH_HEAD'], check=True)
    for patch in pins['patches']:
        subprocess.run(['git', '-C', str(SOURCE), 'apply', str(ROOT / patch)], check=True)
if subprocess.check_output(['git', '-C', str(SOURCE), 'rev-parse', 'HEAD'], text=True).strip() != pins['mesa']['commit']:
    sys.exit('Pinned Mesa source differs')
validate_recorded_patches(ROOT, SOURCE, pins)
options = ['-Dgallium-drivers=', '-Dvulkan-drivers=freedreno', '-Dfreedreno-kmds=darwin',
           '-Dtu-darwin-abi-dir=' + str(ROOT / 'drivers/NativeAdreno'),
           '-Dtu-darwin-host-include=' + str(ROOT / 'drivers/NativeAdreno/tests/hostsim/linux/include'),
           '-Dplatforms=', '-Dglx=disabled', '-Degl=disabled', '-Dgbm=disabled', '-Dopengl=false', '-Dgles1=disabled',
           '-Dgles2=disabled', '-Dllvm=disabled', '-Dshared-glapi=disabled', '-Dxmlconfig=disabled', '-Dshader-cache=disabled',
           '-Dtools=', '-Dbuild-tests=false', '-Dvideo-codecs=', '-Dvulkan-layers=', '-Dexpat=disabled', '-Dvalgrind=disabled',
           '-Dlibunwind=disabled', '-Dlmsensors=disabled', '-Db_lundef=false', '-Dtu-builtin-source-id=linux-host',
           '-Dtu-builtin-pack-header=']
env = {k: v for k, v in os.environ.items() if not k.startswith(('IR3_', 'FD_MESA_', 'NIR_', 'MESA_SHADER_', 'TU_'))}
env.update(CC='clang', CXX='clang++')
log = ROOT / '.cache/mesa-tu-linux-configure.log'
command = (['meson', 'configure', str(OUT)] if (OUT / 'build.ninja').exists() else
           ['meson', 'setup', str(OUT), str(SOURCE), '--wrap-mode=nodownload']) + options
with log.open('w') as stream:
    if subprocess.run(command, env=env, stdout=stream, stderr=subprocess.STDOUT).returncode:
        sys.exit('Configure failed; see ' + str(log))
build_log = ROOT / '.cache/mesa-tu-linux-build.log'
with build_log.open('w') as stream:
    if subprocess.run(['ninja', '-C', str(OUT)], env=env, stdout=stream, stderr=subprocess.STDOUT).returncode:
        sys.exit('Build failed; see ' + str(build_log))
library = OUT / 'src/freedreno/vulkan/libvulkan_freedreno.so'
symbols = subprocess.run(['nm', '-D', '--defined-only', str(library)], capture_output=True, text=True).stdout
if ' T vk_icdGetInstanceProcAddr' not in symbols:
    sys.exit('The library does not export vk_icdGetInstanceProcAddr')
print('PASS: Turnip with the darwin kernel backend builds for the Linux host (%d bytes); no GPU or IOKit service was exercised'
      % library.stat().st_size)
