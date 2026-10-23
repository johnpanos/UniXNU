"""XNU kernel: build from the patched Apple source, then prelink against the original kernelcache."""
import os
import shlex
import shutil
import subprocess
from pathlib import Path

from . import ipsw
from .util import MACOS, Error, expand, install, log, run, sha256_file, tool


def xnu_env(ctx):
    """CONFIG_XNU_* of the defconfig become XNU_* variables of the legacy kernel build script."""
    env = {}
    for key, value in ctx.need_config().items():
        if not key.startswith('XNU_'):
            continue
        if isinstance(value, str):
            value = value.replace('{tree}', str(ctx.tree))
        env[key] = '1' if value is True else '0' if value is False else str(value)
    return env


def version_env(modules):
    """Source versions of the Apple references, from feeds.toml, for the kernel scripts."""
    env = {}
    for name, prefix in (('xnu', 'XNU'), ('libplatform', 'LIBPLATFORM'), ('libdispatch', 'LIBDISPATCH'), ('AvailabilityVersions', 'AVAILABILITYVERSIONS'),
                         ('libpthread', 'LIBPTHREAD')):
        module = modules.get(('refer', name))
        entry = module.source if module and module.source else {}
        if entry.get('ref'):
            env[f'UNIXNU_{prefix}_TAG'] = entry['ref']
        if entry.get('commit'):
            env[f'UNIXNU_{prefix}_COMMIT'] = entry['commit']
    xnu = (modules.get(('refer', 'xnu')) or None) and modules[('refer', 'xnu')].source or {}
    for key, variable in (('darwin', 'UNIXNU_XNU_DARWIN'), ('version', 'UNIXNU_XNU_VERSION'),
                          ('driverkit_tag', 'UNIXNU_DRIVERKIT_TAG'), ('trustcache_tag', 'UNIXNU_TRUSTCACHE_TAG'),
                          ('ios_min', 'UNIXNU_XNU_IOS_MIN'), ('patch_series', 'UNIXNU_XNU_PATCH_SERIES')):
        if xnu.get(key):
            env[variable] = xnu[key]
    return env


def toolchain_path(path=None):
    """PATH with the Homebrew LLVM and LLD first, as the archive builders expect."""
    extra = [d for d in ('/opt/homebrew/opt/llvm/bin', '/opt/homebrew/opt/lld/bin', '/usr/local/opt/llvm/bin', '/usr/local/opt/lld/bin')
             if Path(d).is_dir()]
    return os.pathsep.join(extra + [path or os.environ.get('PATH', '')])


HOST = Path(__file__).resolve().parent / 'host'


def need_linux_host():
    """The iig and host tools of a Linux host; checked before anything is fetched. Returns the iig."""
    # iig output defines the DriverKit methods of OSObject and IOService, so their vtables; no approximation is used.
    # UNIXNU_IIG_OUTPUTS replays the files Apple's iig made in a macOS build (unixnu-iig-outputs of the workflow).
    outputs = os.environ.get('UNIXNU_IIG_OUTPUTS')
    if outputs and not (expand(outputs) / 'manifest.json').is_file():
        raise Error(f'UNIXNU_IIG_OUTPUTS: {outputs} has no manifest.json (scripts/export-iig-outputs.py makes it)')
    iig = os.environ.get('UNIXNU_IIG') or (str(HOST / 'iig-replay') if outputs else shutil.which('iig'))
    if not iig:
        raise Error('the kernel step needs iig, the IOKit interface generator of Xcode, which has no Linux equivalent: '
                    'set UNIXNU_IIG_OUTPUTS to the unixnu-iig-outputs artifact of the "macOS build" workflow '
                    '(or UNIXNU_IIG to an iig for this host), or build the kernel on macOS')
    for name in ('clang', 'ld64.lld', 'llvm-lipo', 'llvm-libtool-darwin', 'llvm-otool', 'llvm-nm', 'llvm-strip', 'dsymutil',
                 'flex', 'bison', 'm4', 'perl'):
        tool(name, install('clang llvm lld flex bison m4 perl'))
    if not Path('/bin/csh').is_file():
        raise Error(f'XNU runs SETUP/config/doconf with /bin/csh: {install("tcsh")}')
    ld64 = os.environ.get('UNIXNU_LD64')
    if not ld64 or not os.access(expand(ld64), os.X_OK):
        # ld64.lld ignores -static, -segaddr, -segment_order, -image_base and -alias_list of the kernel link.
        raise Error('the kernel link needs Apple\'s ld64: build it with scripts/build-ld64-linux.sh DIR and set '
                    'UNIXNU_LD64=DIR/bin/arm64-apple-darwin-ld')
    # kalloc_type uses Apple clang's __builtin_xnu_type_* without a fallback.
    clang = os.environ.get('UNIXNU_XNU_CLANG', 'clang')
    probe = subprocess.run([clang, '-target', 'arm64-apple-ios17.0', '-fsyntax-only', '-x', 'c', '-'], capture_output=True,
                           input='_Static_assert(__builtin_xnu_type_summary(void *) != 0, "");\n', text=True)
    if probe.returncode:
        raise Error(f'{clang} lacks the __builtin_xnu_type_* builtins XNU needs: build one with '
                    'scripts/build-xnu-clang-linux.sh DIR and set UNIXNU_XNU_CLANG=DIR/bin/clang')
    return iig


def host_env(ctx, env):
    """Linux hosts: the xcrun, ditto, sw_vers and plutil of scripts/unixnu/host, mig built from bootstrap_cmds, and
    the make overrides for the macOS paths XNU names directly. macOS keeps Xcode's tools."""
    iig = need_linux_host()
    env = dict(env, UNIXNU_LD64=str(expand(os.environ['UNIXNU_LD64'])))
    if os.environ.get('UNIXNU_IIG_OUTPUTS'):
        env = dict(env, UNIXNU_IIG_OUTPUTS=str(expand(os.environ['UNIXNU_IIG_OUTPUTS'])))   # read from other directories
    run(['bash', ctx.tree / 'scripts/build-host-tools-linux.sh'], cwd=ctx.tree, log_file=ctx.logs / 'host-tools.log')
    sdks = ctx.tree / '.cache/host-sdk'
    for name in ('iPhoneOS.platform', 'MacOSX.platform'):
        (sdks / name).mkdir(parents=True, exist_ok=True)
    # The stand-in SDKs: the few open headers of scripts/unixnu/host/sdk, never Apple's SDKs. Its headers take their
    # values from the compile target, so both platforms share them.
    for name in ('iPhoneOS.sdk', 'MacOSX.sdk'):
        shutil.copytree(HOST / 'sdk', sdks / name, dirs_exist_ok=True)
    bin_dir = ctx.tree / 'build/host-tools/bin'
    make = {'XCRUN': HOST / 'xcrun', 'HOST_CC': HOST / 'host-cc', 'HOST_FLEX': shutil.which('flex'), 'HOST_BISON': shutil.which('bison'),
            'HOST_GM4': shutil.which('m4'), 'HOST_OS_VERSION': '14.0', 'PLUTIL': HOST / 'plutil', 'DO_CTFMERGE': '0',
            'HOST_CODESIGN': shutil.which('true'),   # ad-hoc signing of the host tools is a macOS requirement
            # XNU reads these from /usr/sbin/sysctl hw.* to size its jobs.
            'SYSCTL_HW_PHYSICALCPU': os.cpu_count(), 'SYSCTL_HW_LOGICALCPU': os.cpu_count(),
            'MEMORY_SIZE': os.sysconf('SC_PAGE_SIZE') * os.sysconf('SC_PHYS_PAGES')}
    return dict(env, PATH=os.pathsep.join([str(HOST), str(bin_dir), env['PATH']]), UNIXNU_HOST_SDKS=str(sdks), UNIXNU_IIG=iig,
                UNIXNU_MIG=str(bin_dir / 'mig'), UNIXNU_MIGCOM=str(bin_dir / 'migcom'),
                UNIXNU_HOST_INCLUDE=str(ctx.tree / 'build/host-tools/include'),
                XNU_HOST_PATCHES='linux',   # patches/xnu-linux
                XNU_HOST_MAKE_ARGS=' '.join(f'{key}={value}' for key, value in make.items()))


def build_archives(ctx, env):
    """Run the board's archive builders ([kernel] archives of board.toml), in order, then check the prebuilt archives.

    Each entry is a script of the build tree with its arguments. The kernel link needs their archives, and some of
    them read the compile records that an XNU pass leaves behind. A configuration opts in with
    CONFIG_XNU_BUILD_ARCHIVES; the bootstrap pass and first-console configurations have no archives to build.
    """
    if not ctx.need_config().get('XNU_BUILD_ARCHIVES'):
        return
    config = ctx.need_config()
    entries = []
    # An entry is "script args", or { run = "script args", when = "XNU_NAME" or [...] }: run only when the
    # defconfig turns all of those on, so one board list serves a reduced configuration (a first prelink candidate).
    for entry in ctx.board.get('kernel', {}).get('archives', []):
        if isinstance(entry, dict):
            when = entry.get('when', [])
            when = [when] if isinstance(when, str) else when
            if not entry.get('run') or any(not name.startswith('XNU_') for name in when):
                raise Error(f'[kernel] archives: a table needs run and XNU_* names in when: {entry}')
            if not all(config.get(name) for name in when):
                log(f'kernel: archive skipped ({", ".join(n for n in when if not config.get(n))} off): {entry["run"]}')
                continue
            entry = entry['run']
        entries.append(entry)
    env = dict(env, PATH=toolchain_path(env.get('PATH')))
    # The original kernelcache the kernel is prelinked with ([kernel.prelink] kernelcache_sha256): builders that bind
    # recorded addresses of its kexts select the record of that kernelcache by it and refuse any other.
    pinned = ctx.board.get('kernel', {}).get('prelink', {}).get('kernelcache_sha256')
    if pinned:
        env['UNIXNU_KERNELCACHE_SHA256'] = pinned.lower()
    for index, entry in enumerate(entries, 1):
        parts = shlex.split(entry)
        script = ctx.tree / 'scripts' / parts[0]
        if not script.is_file():
            raise Error(f'[kernel] archives: {script} missing')
        log(f'kernel: archive {index}/{len(entries)}: {entry}')
        run(['python3', script, *parts[1:]], cwd=ctx.tree, env=env, log_file=ctx.logs / f'archive-{index:02d}-{Path(parts[0]).stem}.log')
    # Archives that no builder produces (they need inputs outside the repositories) must be supplied.
    for key, value in sorted(xnu_env(ctx).items()):
        # The archive of a component the defconfig turns off is not needed (XNU_NATIVE_VIRTIO_BLOCK_ARCHIVE and the like).
        if key.endswith('_ARCHIVE') and config.get(key.removesuffix('_ARCHIVE')) is False:
            continue
        if key.endswith('_ARCHIVE') and value.endswith('.a') and not Path(value).is_file():
            raise Error(f'{key}: {value} not found; no builder makes it, supply the archive')


def build(ctx, modules):
    log('kernel: XNU')
    for name in ('git', 'make', 'clang', 'cmake', 'ninja', 'unifdef'):
        tool(name, install(name, 'ninja-build' if name == 'ninja' else None))
    if MACOS:
        tool('xcodebuild', 'the kernel step builds with the Xcode iphoneos SDK')
    script = ctx.tree / 'scripts/build-xnu-4k-baseline.sh'
    if not script.is_file():
        raise Error(f'{script} missing')
    env = dict(os.environ) if MACOS else host_env(ctx, dict(os.environ))
    env.update(xnu_env(ctx))
    env.update(version_env(modules))
    env['JOBS'] = str(ctx.jobs)
    record = ctx.tree / 'build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837/osfmk/DEVELOPMENT/startup.o.json'
    if not record.is_file():
        # The archive builders and the boot progress layer read compile records of the XNU build, which only an earlier
        # pass leaves behind. A first build from scratch therefore runs one pass without them; XNU_BOOTSTRAP makes it
        # skip the archive checks and link without the archives, so it stops at the link and only the records are
        # required of it.
        log('kernel: bootstrap pass for the compile records')
        subprocess_env = {**env, 'XNU_BOOT_PROGRESS': '0', 'XNU_BOOTSTRAP': '1'}
        try:
            run(['bash', script], cwd=ctx.tree, env=subprocess_env, log_file=ctx.logs / 'kernel-bootstrap.log')
        except Error:
            if not record.is_file():
                raise
    storage = ctx.tree / 'build/storage-abi/include/IOKit/storage'
    if (ctx.tree / 'refer/IOStorageFamily').is_dir() and not storage.is_dir():
        log('kernel: prepare storage headers')
        run(['python3', ctx.tree / 'scripts/prepare-storage-headers.py'], cwd=ctx.tree, env=env,
            log_file=ctx.logs / 'storage-headers.log')
    build_archives(ctx, env)
    run(['bash', script], cwd=ctx.tree, env=env, log_file=ctx.logs / 'kernel.log')


def prelink(ctx):
    """Produce out/<device>/kernel/kernel.macho from the XNU build and the original kernelcache."""
    log('kernel: prelink')
    spec = ctx.board.get('kernel', {}).get('prelink')
    if not spec:
        raise Error('board.toml has no [kernel.prelink]')
    cache = ctx.option('kernelcache', 'UNIXNU_KERNELCACHE') or (expand(ctx.tree / spec['kernelcache']) if spec.get('kernelcache') else None)
    if not cache:
        # Not given: take it from the IPSW (--ipsw PATH_OR_URL, or the url of board.toml [ipsw]).
        cache = ipsw.kernelcache(ctx, ipsw.Ipsw(ctx))
    if not cache.is_file():
        raise Error(f'kernelcache not found: {cache}')
    wanted = spec.get('kernelcache_sha256')
    if wanted and sha256_file(cache) != wanted:
        raise Error(f'{cache} does not match the kernelcache this board was qualified against (sha256 {wanted})')
    kernel = ctx.tree / spec['kernel']
    if not kernel.is_file():
        raise Error(f'{kernel} not found; run "unixnu build kernel" first')
    output = ctx.work / 'kernel/kernel.macho'
    output.parent.mkdir(parents=True, exist_ok=True)
    # emit_prelink refuses to overwrite; a rebuild replaces the previous candidate and its record.
    for stale in (output, output.with_suffix('.json')):
        stale.unlink(missing_ok=True)
    command = ['python3', ctx.tree / spec['tool'], '--kernel', kernel, '--prelinked', cache,
               f'--slide={spec["slide"]}', '--output', output]
    for root in spec.get('roots', []):
        command += ['--root', root]
    if spec.get('early_security_init'):
        command += ['--early-security-init', spec['early_security_init']]
    command += spec.get('extra_args', [])
    run(command, cwd=ctx.tree, log_file=ctx.logs / 'prelink.log')
    log(f'kernel: {output} sha256 {sha256_file(output)}')
    return output
