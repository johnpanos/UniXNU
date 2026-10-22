#!/usr/bin/env python3
"""Build libclang_rt.cc_kext_ios.a for the kernel step on Linux hosts (Xcode ships it; XNU links -lcc_kext).

compiler-rt's Darwin recipe (cmake/Modules/CompilerRTDarwinUtils.cmake, which runs only on a Darwin host): the
builtins of arm64 without the iOS exclusions, plus the kernel profile runtime, compiled -mkernel -DKERNEL_USE.
The headers an SDK would give are open ones: XNU's in .cache/fakeroot and its Libsyscall gethostuuid.h, then
Libc's, libpthread's, libdispatch's, libmalloc's, dyld's and libplatform's, LLVM's SipHash (emupac.cpp) and the stand-in
TargetConditionals.h. Run after installhdrs. Output: build/cc-kext/libclang_rt.cc_kext_ios.a.
"""
import os
import re
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RT = ROOT / 'refer/compiler-rt'
BUILTINS = RT / 'lib/builtins'
OUT = ROOT / 'build/cc-kext'
FAKEROOT = ROOT / '.cache/fakeroot'


def cmake_list(text, name):
    """The plain file entries of set(NAME ...) in a CMake file (variable references dropped)."""
    body = re.search(r'\n\s*set\(' + name + r'(?:\s|\n)(.*?)\)', text, re.S).group(1)
    return [word for word in body.split() if not word.startswith('$')]


def sources():
    builtins = (BUILTINS / 'CMakeLists.txt').read_text()
    darwin = (RT / 'cmake/Modules/CompilerRTDarwinUtils.cmake').read_text()
    # GENERIC_SOURCES as the CMake file extends it for an Apple target, then aarch64_SOURCES' own files.
    files = cmake_list(builtins, 'GENERIC_TF_SOURCES') + cmake_list(builtins, 'GENERIC_SOURCES')
    files += ['emutls.c', 'enable_execute_stack.c', 'eprintf.c', 'clear_cache.c']
    files += [f for f in re.search(r'if\(APPLE\)\s*set\(GENERIC_SOURCES\s*\$\{GENERIC_SOURCES\}(.*?)\)', builtins, re.S).group(1).split()]
    files += cmake_list(builtins, 'aarch64_SOURCES')
    excluded = set((BUILTINS / 'Darwin-excludes/ios.txt').read_text().split())
    files = [f for f in dict.fromkeys(files) if Path(f).stem not in excluded]
    profile = cmake_list(darwin, 'PROFILE_SOURCES')
    return [BUILTINS / f for f in files] + [Path(os.path.normpath(BUILTINS / f)) for f in profile]


def main():
    sdk = subprocess.check_output(['xcrun', '--sdk', 'iphoneos', '--show-sdk-path'], text=True).strip()
    flags = ['-arch', 'arm64', f'-miphoneos-version-min={os.environ.get("UNIXNU_XNU_IOS_MIN", "17.0")}', '-isysroot', sdk,
             '-fPIC', '-O3', '-fvisibility=hidden', '-DVISIBILITY_HIDDEN', '-Wall', '-fomit-frame-pointer',
             '-mkernel', '-DKERNEL_USE', '-I', str(RT / 'include'),
             # XNU's headers first (sys/cdefs.h is XNU's in an SDK too), then Libc's and libplatform's.
             '-isystem', str(FAKEROOT / 'usr/include'), '-isystem', str(ROOT / 'refer/Libc'),
             # libpthread's include/pthread is flattened into an SDK's usr/include.
             '-isystem', str(ROOT / 'refer/libpthread/include'), '-isystem', str(ROOT / 'refer/libpthread/include/pthread'),
             '-isystem', str(ROOT / 'refer/libdispatch'), '-isystem', str(ROOT / 'refer/dyld'),
             '-isystem', str(ROOT / 'refer/libmalloc'), '-isystem', str(FAKEROOT / 'usr/local/include'),
             '-isystem', str(OUT / 'include'), '-I', str(ROOT / 'refer/llvm-third-party/siphash/include'),
             '-include', str(OUT / 'include/cc-kext-cdefs.h')]
    # gethostuuid.h is Libsyscall's (refer/xnu/libsyscall/wrappers); only it, the rest of that directory is not SDK API.
    (OUT / 'include').mkdir(parents=True, exist_ok=True)
    (OUT / 'include/gethostuuid.h').write_bytes((ROOT / 'refer/xnu/libsyscall/wrappers/gethostuuid.h').read_bytes())
    # The libmalloc headers name sys/cdefs.h macros that older XNU (xnu-8796) does not define yet; defined as in xnu-10063.
    (OUT / 'include/cc-kext-cdefs.h').write_text('#include <sys/cdefs.h>\n#ifndef __alloc_align\n#if __has_attribute(alloc_align)\n'
                                                 '#define __alloc_align(n) __attribute__((alloc_align(n)))\n#else\n#define __alloc_align(n)\n#endif\n#endif\n')
    files = sources()

    def compile(source):
        obj = OUT / (source.name.replace('.', '_') + '.o')
        result = subprocess.run(['xcrun', '-sdk', 'iphoneos', 'clang', *flags, '-c', str(source), '-o', str(obj)],
                                capture_output=True, text=True)
        return source, obj, result

    failed = []
    objects = []
    with ThreadPoolExecutor() as pool:
        for source, obj, result in pool.map(compile, files):
            if result.returncode:
                failed.append(f'{source.relative_to(RT)}:\n{result.stderr.strip()[-1500:]}')
            objects.append(obj)
    if failed:
        raise SystemExit('cc_kext sources that did not compile:\n' + '\n'.join(failed))
    archive = OUT / 'libclang_rt.cc_kext_ios.a'
    archive.unlink(missing_ok=True)
    subprocess.run(['xcrun', 'libtool', '-static', '-o', str(archive), *map(str, objects)], check=True)
    print(f'{archive}: {len(objects)} objects')


if __name__ == '__main__':
    main()
