"""Assemble the build tree from the resolved modules.

out/<device>/tree/ has the layout of this repository (drivers/ kits/ patches/ scripts/ package/)
plus refer/, build/ and .cache/ for the scripts that expect them. Modules are symbolic links to
their sources, so edits to a local module take effect on the next build; scripts are copied, since
they locate the tree from their own real path. The device package appears as kits/<kit>.

A patch directory of the device repository that this repository also has (patches/xnu, patches/xnu-8796)
adds to it rather than replacing it: the tree gets a directory of links to every patch of both, the device's
file winning on a name clash. Without this a device's patches/xnu would leave the tree with the device's
patches only, and a fresh XNU work tree would never get the UniXNU series.
"""
import shutil
from pathlib import Path

from .util import Error, log


def _clear_links(directory):
    if directory.is_dir():
        for entry in directory.iterdir():
            if entry.is_symlink():
                entry.unlink()


def _link(target, link):
    link.parent.mkdir(parents=True, exist_ok=True)
    if link.is_symlink() or link.exists():
        link.unlink()
    link.symlink_to(Path(target).resolve())


def _merge_patches(base, device, link):
    """tree/patches/<name>: links to the files of base, then of device (which wins on a clash)."""
    if link.is_symlink():
        link.unlink()
    elif link.is_dir():
        shutil.rmtree(link)   # a merged directory of an earlier assembly: links only
    link.mkdir(parents=True)
    for source in (base, device):
        for path in sorted(Path(source).iterdir()):
            if path.name.startswith('.'):
                continue
            target = link / path.name
            if target.is_symlink():
                target.unlink()
            target.symlink_to(path.resolve())


def _copy_scripts(source, destination):
    for path in sorted(Path(source).rglob('*')):
        relative = path.relative_to(source)
        if path.is_dir() or '__pycache__' in path.parts or relative.parts[0] == 'unixnu':
            continue
        target = destination / relative
        if target.exists() and target.stat().st_size == path.stat().st_size and target.stat().st_mtime >= path.stat().st_mtime:
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, target)


def assemble(ctx, modules):
    log(f'tree {ctx.tree}')
    tree = ctx.tree
    tree.mkdir(parents=True, exist_ok=True)
    for folder in ('drivers', 'kits', 'patches', 'refer'):
        _clear_links(tree / folder)
        (tree / folder).mkdir(exist_ok=True)
    for merged in (tree / 'patches').iterdir():
        if merged.is_dir() and not merged.is_symlink():
            shutil.rmtree(merged)   # merged patch directories (_merge_patches) are rebuilt below
    for name in ('build', '.cache'):
        (tree / name).mkdir(exist_ok=True)
    # Proprietary files (device repository: scripts/extract-files.py) stay in the device repository and are shared by every tree.
    firmware = ctx.device / '.cache/firmware'
    firmware.mkdir(parents=True, exist_ok=True)
    link = tree / '.cache/firmware'
    if link.is_symlink():
        link.unlink()
    if not link.exists():
        link.symlink_to(firmware)
    kit = ctx.board.get('board', {}).get('kit', ctx.name)
    for (kind, name), module in sorted(modules.items()):
        if module.path is None:
            if kind == 'refer':
                continue   # fetched when a step needs it
            raise Error(f'{kind} {name} has no source yet; run "unixnu fetch"')
        if kind == 'package':
            if name == 'main':
                _link(module.path, tree / 'package')
            else:
                _link(module.path, tree / 'kits' / kit)
        elif kind == 'patch' and module.origin == 'device' and (ctx.root / 'patches' / name).is_dir() and \
                (ctx.root / 'patches' / name).resolve() != Path(module.path).resolve():
            _merge_patches(ctx.root / 'patches' / name, module.path, tree / 'patches' / name)
        else:
            _link(module.path, tree / {'driver': 'drivers', 'kit': 'kits', 'patch': 'patches', 'refer': 'refer'}[kind] / name)
    if not (tree / 'package').is_symlink():
        raise Error('no package module: this repository or --local-package must provide package/')
    (tree / 'scripts').mkdir(exist_ok=True)
    for base in (ctx.root, ctx.device):
        if (base / 'scripts').is_dir():
            _copy_scripts(base / 'scripts', tree / 'scripts')
    return tree
