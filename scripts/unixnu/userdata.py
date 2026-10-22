"""Userdata payload: the raw image for the device's `userdata` partition.

It holds the unchanged OS and SystemOS disk images of the IPSW, byte for byte, behind a small manifest
(the SHNGROOT layout the native UFS root driver reads):

    0x000000  manifest block (4096 bytes), zero padding to 1 MiB
    0x100000  window "OS"        the whole attached OS disk image, 1 MiB aligned
    ....      window "SystemOS"  the whole attached SystemOS disk image, 1 MiB aligned

Manifest (little endian): "SHNGROOT", u32 version=1, u32 count, u64 image_bytes, then `count` 128-byte entries
{char name[32], u64 offset, u64 size, u32 block_size=512, u32 flags(1=read-only), u8 sha256[32], 40 reserved},
and at byte 4064 the SHA-256 of bytes 0..4063.

A second root image in the same partition sets [userdata] base_mib: it starts that far into userdata, after the first
one. Its manifest is version 2, which adds u64 base_bytes at byte 4056 (hashed); offsets stay relative to the manifest,
and NativeUfs reads it with native-ufs-root-base=<base_mib>. Besides the raw image the step then writes an Android
sparse image whose first base_mib MiB are DONT_CARE, so "fastboot flash userdata" writes only this image's region and
leaves the first image and the end of the partition (Data store, log) as they are.

The images come from the IPSW (a local file or a remote URL, see ipsw.py) and are checked against the pins of
board.toml. On macOS the disk images are attached read-only without mounting (hdiutil). Elsewhere a UDIF image
is expanded from its block table and a raw image is read as it is, which gives the same bytes. Nothing is flashed:
the report prints the fastboot command, to be run by the user.
"""
import bz2
import hashlib
import json
import lzma
import plistlib
import re
import shutil
import struct
import subprocess
import zlib

from .ipsw import Ipsw
from .util import MACOS, Error, install, log, run, sha256_file

MIB = 1 << 20
CHUNK = 8 * MIB
SECTOR = 512
# UDIF block chunk types: zero fill, raw, ignored, zlib, bzip2, LZFSE, LZMA, comment and end of table.
ZERO, RAW, IGNORE, ZLIB, BZIP2, LZFSE, LZMA, COMMENT, END = 0, 1, 2, 0x80000005, 0x80000006, 0x80000007, 0x80000008, 0x7ffffffe, 0xffffffff


def paths(ctx):
    out = ctx.work / 'userdata'
    return out, out / 'userdata-root.img', out / 'userdata-root.json'


def udif(dmg):
    """The koly trailer of a UDIF image, or None for a raw image."""
    with open(dmg, 'rb') as handle:
        handle.seek(-512, 2)
        koly = handle.read(512)
    return koly if koly[:4] == b'koly' else None


def image_size(dmg):
    if MACOS:
        info = subprocess.run(['hdiutil', 'imageinfo', '-plist', str(dmg)], capture_output=True, check=True).stdout
        return plistlib.loads(info)['Size Information']['Total Bytes']
    koly = udif(dmg)
    return struct.unpack_from('>Q', koly, 0x1ec)[0] * SECTOR if koly else dmg.stat().st_size


def udif_chunks(handle, koly):
    """The block chunks in disk order, each (type, first byte, byte count, data offset, data length, block index),
    and the CRC32 of each block table, which covers its expanded data except the ignored chunks (None if not CRC32)."""
    xml_offset, xml_length = struct.unpack_from('>QQ', koly, 0xd8)
    handle.seek(xml_offset)
    chunks, crcs = [], []
    for block_index, block in enumerate(plistlib.loads(handle.read(xml_length))['resource-fork']['blkx']):
        mish = block['Data']
        if mish[:4] != b'mish':
            raise Error('UDIF block table without mish header')
        first, data_offset = struct.unpack_from('>Q', mish, 8)[0], struct.unpack_from('>Q', mish, 0x18)[0]
        kind, _ = struct.unpack_from('>II', mish, 0x40)
        crcs.append(struct.unpack_from('>I', mish, 0x48)[0] if kind == 2 else None)
        for index in range(struct.unpack_from('>I', mish, 0xc8)[0]):
            kind, _, sector, count, offset, length = struct.unpack_from('>IIQQQQ', mish, 0xcc + 40 * index)
            if kind not in (COMMENT, END):
                chunks.append((kind, (first + sector) * SECTOR, count * SECTOR, data_offset + offset, length, block_index))
    return sorted(chunks, key=lambda chunk: chunk[1]), crcs


def lzfse(data):
    decoder = shutil.which('lzfse')
    if not decoder:
        raise Error(f'lzfse not found on PATH ({install("lzfse")}); it decodes the UDIF disk image')
    return subprocess.run([decoder, '-decode'], input=data, capture_output=True, check=True).stdout


def read_image(dmg, size):
    """The bytes of the attached disk image, in pieces: expanded UDIF chunks, or the raw file."""
    koly = udif(dmg)
    with open(dmg, 'rb') as handle:
        if not koly:
            while data := handle.read(CHUNK):
                yield data
            return
        chunks, want = udif_chunks(handle, koly)
        crcs = [0] * len(want)
        cursor = 0
        for kind, start, count, offset, length, block in chunks:
            if start != cursor:
                raise Error(f'{dmg.name}: UDIF chunks leave a gap or overlap at {cursor:#x}')
            if kind in (ZERO, IGNORE):
                data = bytes(count)
            else:
                handle.seek(offset)
                packed = handle.read(length)
                decode = {RAW: bytes, ZLIB: zlib.decompress, BZIP2: bz2.decompress, LZFSE: lzfse, LZMA: lzma.decompress}.get(kind)
                if not decode:
                    raise Error(f'{dmg.name}: UDIF chunk type {kind:#x} is not supported')
                data = decode(packed)
            if len(data) != count:
                raise Error(f'{dmg.name}: UDIF chunk at {start:#x} expands to {len(data)} bytes, not {count}')
            if kind != IGNORE:
                crcs[block] = zlib.crc32(data, crcs[block])
            yield data
            cursor += count
        if cursor != size:
            raise Error(f'{dmg.name}: UDIF chunks cover {cursor} bytes of {size}')
        for block, (got, expected) in enumerate(zip(crcs, want)):
            if expected is not None and got != expected:
                raise Error(f'{dmg.name}: UDIF block table {block} CRC32 {got:08x}, expected {expected:08x}')


def attach(dmg):
    """Attach read-only without mounting; return the whole-disk device."""
    out = subprocess.run(['hdiutil', 'attach', '-nomount', '-readonly', '-noverify', '-noautofsck', str(dmg)],
                         capture_output=True, text=True, check=True).stdout
    for line in out.splitlines():
        match = re.match(r'(/dev/disk\d+)\s', line)
        if match:
            return match.group(1)
    raise Error('could not find the attached disk device')


SPARSE_MAGIC, RAW_CHUNK, DONT_CARE_CHUNK = 0xed26ff3a, 0xcac1, 0xcac3
SPARSE_RAW_BLOCKS = 16384           # 64 MiB raw chunks; fastboot splits the image for the device's download size anyway
# The end of userdata a root image keeps clear of: NativeUfs' default reserve (sheng-log-reserve, 1 GiB) and its 4 MiB guard.
END_RESERVE = 1024 * MIB + 4 * MIB


def write_sparse(raw, sparse, base, block=4096):
    """An Android sparse image of `raw` placed `base` bytes into the partition: DONT_CARE up to the base, then raw chunks."""
    size = raw.stat().st_size
    if base % block or size % block:
        raise Error('sparse image: the base and the image must be whole 4096-byte blocks')
    blocks = size // block
    chunks = ([(DONT_CARE_CHUNK, base // block)] if base else []) + \
        [(RAW_CHUNK, min(SPARSE_RAW_BLOCKS, blocks - at)) for at in range(0, blocks, SPARSE_RAW_BLOCKS)]
    with raw.open('rb') as source, sparse.open('wb') as target:
        target.write(struct.pack('<IHHHHIIII', SPARSE_MAGIC, 1, 0, 28, 12, block, base // block + blocks, len(chunks), 0))
        for kind, count in chunks:
            payload = count * block if kind == RAW_CHUNK else 0
            target.write(struct.pack('<HHII', kind, 0, count, 12 + payload))
            done = 0
            while done < payload:
                data = source.read(min(CHUNK, payload - done))
                if not data:
                    raise Error(f'sparse image: {raw} ended early')
                target.write(data)
                done += len(data)
    return len(chunks)


def build(ctx, dry_run=False):
    log('userdata payload')
    spec = ctx.board.get('userdata')
    if not spec:
        raise Error('board.toml has no [userdata]')
    source = Ipsw(ctx)
    capacity = (spec['last_lba'] - spec['first_lba'] + 1) * spec.get('lba_bytes', 4096)
    base = int(spec.get('base_mib', 0)) * MIB
    if base >= capacity:
        raise Error(f'[userdata] base_mib {base // MIB} is past the end of the partition ({capacity // MIB} MiB)')
    if dry_run:
        for window in spec['windows']:
            name, size, _ = source.info(window['component'])
            log(f'userdata: {window["name"]} would be extracted from {name} ({size >> 20} MiB)')
        log('userdata: dry run, nothing extracted or written')
        return None
    sources = [(window['name'], source.extract(window['component'])) for window in spec['windows']]
    layout, cursor = [], MIB
    for name, dmg in sources:
        size = image_size(dmg)
        layout.append((name, cursor, size))
        cursor += (size + MIB - 1) // MIB * MIB
    total = cursor
    log(f'userdata: image {total} bytes ({total / 2**30:.2f} GiB) at {base // MIB} MiB in a partition of {capacity} bytes')
    if base + total > capacity - END_RESERVE:
        raise Error(f'the image ends at {(base + total) / 2**30:.2f} GiB, inside the last {END_RESERVE // MIB} MiB of the userdata '
                    'partition (the Data store and log reserve of NativeUfs) or past it')
    for name, dmg in sources:
        log(f'userdata: {name} from {dmg.name}')
    out, image, report = paths(ctx)
    out.mkdir(parents=True, exist_ok=True)
    entries = []
    with image.open('wb') as target:
        target.truncate(total)
        for (name, offset, size), (_, dmg) in zip(layout, sources):
            digest = hashlib.sha256()
            target.seek(offset)
            if MACOS:
                device = attach(dmg)
                try:
                    raw = device.replace('/dev/disk', '/dev/rdisk')
                    done = 0
                    with open(raw, 'rb', buffering=0) as handle:
                        while done < size:
                            want = min(CHUNK, size - done)
                            data = handle.read(want)
                            if len(data) != want:
                                raise Error(f'short read from {raw} at {done}')
                            digest.update(data)
                            target.write(data)
                            done += want
                finally:
                    subprocess.run(['hdiutil', 'detach', device], capture_output=True)
            else:
                for data in read_image(dmg, size):
                    digest.update(data)
                    target.write(data)
            entries.append((name, offset, size, digest.digest()))
            log(f'userdata: {name} {size} bytes at {offset:#x} sha256 {digest.hexdigest()}')
        header = bytearray(4096)
        header[0:8] = b'SHNGROOT'
        struct.pack_into('<IIQ', header, 8, 2 if base else 1, len(entries), total)
        for index, (name, offset, size, digest) in enumerate(entries):
            struct.pack_into('<32sQQII32s40s', header, 24 + 128 * index, name.encode(), offset, size, 512, 1, digest, bytes(40))
        if base:
            struct.pack_into('<Q', header, 4056, base)   # version 2: the base this manifest is valid at
        header[4064:4096] = hashlib.sha256(bytes(header[:4064])).digest()
        target.seek(0)
        target.write(header)
    flashed = image
    if base:
        flashed = image.with_suffix('.simg')
        count = write_sparse(image, flashed, base)
        log(f'userdata: {flashed}: sparse, {base // MIB} MiB DONT_CARE then the image ({count} chunks)')
    data = {'image_bytes': total, 'image_sha256': sha256_file(image), 'manifest_sha256': hashlib.sha256(bytes(header)).hexdigest(),
            'manifest_version': 2 if base else 1, 'base_bytes': base, 'kernel_arg': f'native-ufs-root-base={base // MIB}' if base else None,
            'windows': [{'name': n, 'offset': o, 'size': s, 'sha256': d.hex()} for n, o, s, d in entries],
            'userdata_bytes': capacity, 'flash_command': f'fastboot flash userdata {flashed}',
            'sparse_sha256': sha256_file(flashed) if base else None,
            'source': 'remote' if source.remote else 'local', 'hardware_tested': False}
    report.write_text(json.dumps(data, indent=2) + '\n')
    log(f'userdata: {image}')
    log(f'flash it yourself with: {data["flash_command"]}')
    return image
