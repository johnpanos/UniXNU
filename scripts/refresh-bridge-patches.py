#!/usr/bin/env python3
"""refresh-bridge-patches.py: rebase NativeMetal's recorded translator patches (drivers/NativeMetal/bridge/patches, the list in
build-native-metal-bridge.py) onto the translator pin in scripts/data/gpu-metal-vulkan-inputs.json.

After a pin bump the patches still apply, but with hunk offsets (or fuzz), and build-native-metal-bridge.py refuses the result
("Translator patch result differs from its exact recorded source"). This checks the pinned source out clean in
.cache/gpu-reference/metal2vulkan (fetching it if needed), applies each patch in order with `git apply --3way` semantics off (plain
apply, then `patch -p1 --fuzz=3` if that fails), and rewrites each patch's per-file blocks with the diff git now gives, so the recorded
patches are exactly the pinned source's. A patch that does not apply at all stops it (resolve by hand). Then the source is reset clean.

    python3 scripts/refresh-bridge-patches.py [--check]     # --check: only report which patches need a refresh
Commit the changed patches in drivers/NativeMetal with the pin bump."""
import argparse, json, re, subprocess, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / '.cache/gpu-reference/metal2vulkan'
PATCH_DIR = ROOT / 'drivers/NativeMetal/bridge/patches'
ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
ap.add_argument('--check', action='store_true')
a = ap.parse_args()

pins = json.loads((ROOT / 'scripts/data/gpu-metal-vulkan-inputs.json').read_text())['translator']
names = re.findall(r"'(\d{4}-[^']+\.patch)'", (ROOT / 'scripts/build-native-metal-bridge.py').read_text().split('PATCHES = [', 1)[1].split(']]', 1)[0])
git = lambda *args, **kw: subprocess.run(['git', '-C', str(SOURCE), *args], check=kw.pop('check', True), text=True, capture_output=True, **kw)
if not (SOURCE / '.git').exists() or git('rev-parse', 'HEAD', check=False).stdout.strip() != pins['commit']:
    SOURCE.mkdir(parents=True, exist_ok=True)
    subprocess.run(['git', 'init', '-q', str(SOURCE)], check=True)
    git('fetch', '-q', '--depth', '1', pins['repository'], pins['commit'])
    git('checkout', '-q', '--force', 'FETCH_HEAD')
git('checkout', '-q', '--', '.')
git('clean', '-qfd')
blocks = lambda text: [b for b in re.split(r'(?=^diff --git )', text, flags=re.M) if b]
changed = []
for name in names:
    path = PATCH_DIR / name
    text = path.read_text()
    before = git('diff', 'HEAD', '--').stdout
    r = git('apply', str(path), check=False)
    how = 'exact'
    if r.returncode:
        r = subprocess.run(['patch', '-p1', '--fuzz=3', '-s', '-i', str(path)], cwd=SOURCE, text=True, capture_output=True)
        how = 'fuzz'
        if r.returncode:
            git('checkout', '-q', '--', '.')
            sys.exit('refresh-bridge-patches: %s does not apply to %s:\n%s' % (name, pins['commit'][:12], r.stdout + r.stderr))
    after = git('diff', 'HEAD', '--').stdout
    now = {b.splitlines()[0]: b for b in blocks(after) if b.startswith('diff --git')}
    old = {b.splitlines()[0]: b for b in blocks(before) if b.startswith('diff --git')}
    out = ''.join(now.get(b.splitlines()[0], b) if b.startswith('diff --git') and now.get(b.splitlines()[0]) != old.get(b.splitlines()[0]) else b
                  for b in blocks(text))
    if out != text:
        changed.append(name)
        print('%s: refreshed (%s)' % (name, how))
        if not a.check:
            path.write_text(out)
    else:
        print('%s: unchanged' % name)
git('checkout', '-q', '--', '.')
git('clean', '-qfd')
print('%d of %d patches %s for translator %s' % (len(changed), len(names), 'need a refresh' if a.check else 'refreshed', pins['commit'][:12]))
