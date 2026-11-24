#!/usr/bin/env python3
"""Exercise the extras filesystem plugins through radare2's mount commands."""

import json
import lzma
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import zlib


UNKNOWN = (1 << 64) - 1
PREFIX = b"prefix".ljust(64, b"\0")
BLOCK = 4096


def squash_image(codec):
    compress = zlib.compress if codec == 1 else lzma.compress

    def meta(data):
        stored = compress(data)
        if len(stored) < len(data):
            return struct.pack("<H", len(stored)) + stored
        return struct.pack("<H", len(data) | 0x8000) + data

    def inode(kind, number, payload):
        return struct.pack("<4H2I", kind, 0o644, 0, 0, 42, number) + payload

    def directory(reference, number, kind, name):
        return struct.pack("<3IHhHH", 0, reference >> 16, number, reference & 0xFFFF,
                           0, kind, len(name) - 1) + name

    raw = bytes(range(256)) * 16
    packed = b"Z" * BLOCK
    tail = b"tail"
    encoded = compress(packed)
    fragment = b"other" + tail
    payload = raw + encoded + fragment
    file_id = 8192 - 12
    sub_id = 32
    root_dir = directory(sub_id, 2, 1, b"sub")
    sub_dir = directory(file_id, 3, 2, b"file")
    root = inode(1, 1, struct.pack("<IIHHI", 0, 2, len(root_dir) + 3, 0, 4))
    sub = inode(1, 2, struct.pack("<IIHHI", 0, 2, len(sub_dir) + 3, len(root_dir), 1))
    blocks = struct.pack("<III", BLOCK | (1 << 24), 0, len(encoded))
    file = inode(9, 3, struct.pack("<QQQIIII", 96, BLOCK * 3 + len(tail), BLOCK,
                                 1, 0, len(fragment) - len(tail), 0xFFFFFFFF) + blocks)
    inodes = (root + sub).ljust(file_id, b"\0") + file
    inode_table = meta(inodes[:8192]) + meta(inodes[8192:])
    directory_table = meta(root_dir + sub_dir)
    fragment_table = meta(struct.pack("<QII", 96 + len(raw) + len(encoded),
                                      len(fragment) | (1 << 24), 0))
    inode_at = 96 + len(payload)
    dir_at = inode_at + len(inode_table)
    frag_at = dir_at + len(directory_table)
    frag_index = frag_at + len(fragment_table)
    ids_at = frag_index + 8
    id_table = meta(struct.pack("<I", 123))
    id_index = ids_at + len(id_table)
    used = id_index + 8
    superblock = struct.pack("<5I6H8Q", 0x73717368, 3, 42, BLOCK, 1, codec, 12, 0,
                             1, 4, 0, 0, used, id_index, UNKNOWN, inode_at, dir_at,
                             frag_index, UNKNOWN)
    image = (superblock + payload + inode_table + directory_table + fragment_table
             + struct.pack("<Q", frag_at) + id_table + struct.pack("<Q", ids_at))
    assert len(image) == used
    return image, raw + bytes(BLOCK) + packed + tail, file_id, 96 + len(raw) + len(encoded)


def jffs_image(endian):
    def pack(fmt, *fields):
        return struct.pack(endian + fmt, *fields)

    def crc(data):
        return pack("I", zlib.crc32(data, 0xFFFFFFFF) ^ 0xFFFFFFFF)

    def header(kind, length):
        raw = pack("HHI", 0x1985, kind, length)
        return raw + crc(raw)

    def record(data, accurate):
        if not accurate:
            data = data[:2] + pack("H", struct.unpack(endian + "H", data[2:4])[0] & ~0x2000) + data[4:]
        return data + b"\xff" * (-len(data) % 4)

    def name(parent, version, ino, value, kind=8, accurate=True):
        raw = header(0xE001, 40 + len(value)) + pack("IIIIBBH", parent, version, ino, 42,
                                                   len(value), kind, 0)
        return record(raw + crc(raw) + crc(value) + value, accurate)

    def inode(ino, version, size, offset=0, data=b"", codec=0, decoded=0, mode=0o100644,
              accurate=True, corrupt=False):
        stored = zlib.compress(data) if codec == 6 else data
        raw = header(0xE002, 68 + len(stored))
        raw += pack("IIIHH7IBBH", ino, version, mode, 1000, 2000, size, 0, 42, 0, offset,
                    len(stored), decoded or len(data), codec, 0, 0)
        checksum = crc(stored)
        if corrupt:
            stored = b"?" + stored[1:]
        return record(raw + checksum + crc(raw) + stored, accurate)

    image = b"".join([
        header(0x2003, 12), name(1, 1, 2, b"sub", 4), inode(2, 1, 0, mode=0o40755),
        name(2, 1, 3, b"live"), inode(3, 5, 12, 10, b"yz"), inode(3, 1, 12, 0, b"ABCDEFGHIJKL"),
        inode(3, 2, 12, 4, b"xxx", 6), inode(3, 3, 7), inode(3, 4, 12, 7, codec=1, decoded=5),
        name(2, 2, 7, b"rtime"), inode(7, 1, 6, 0, b"r\x05", 2, decoded=6),
        name(2, 3, 8, b"link", 10), inode(8, 1, 0, 0, b"live", mode=0o120777),
        name(1, 2, 3, b"alias"), name(1, 3, 0, b"alias"),
        name(1, 4, 4, b"gone", accurate=False), name(1, 5, 0, b"gone"),
        inode(4, 1, 9, 0, b"recovered", accurate=False),
        name(1, 6, 5, b"badgone"), name(1, 7, 0, b"badgone"),
        inode(5, 1, 3, 0, b"bad", corrupt=True),
        name(1, 8, 6, b"gap"), name(1, 9, 0, b"gap"), inode(6, 1, 4, 2, b"??"),
    ])
    return image + b"\xff" * (-len(image) % BLOCK)


def run_r2(directory, image, *commands, allow_error=False):
    plugin_dir = Path(__file__).resolve().parent.parent / "p"
    cmd = [R2, "-N", "-n", "-q", "-e", "scr.color=0"]
    for name in ("fs_jffs2", "fs_squash"):
        cmd.extend(("-i", str(plugin_dir / f"{name}.{LIBEXT}")))
    for command in commands:
        cmd.extend(("-c", command))
    result = subprocess.run(cmd + [str(image)], cwd=directory,
                            env={**os.environ, "XDG_DATA_HOME": str(directory / "xdg")},
                            capture_output=True, check=False)
    if not allow_error:
        assert result.returncode == 0 and not result.stderr, (cmd, result.stdout, result.stderr)
    return result


def test_squash(directory, codec):
    data, contents, file_id, fragment_at = squash_image(codec)
    image = directory / "squash.img"
    image.write_bytes(PREFIX + data + data)
    first = len(PREFIX)
    second = first + len(data)
    out = run_r2(directory, image, f"m /a squash {first}", f"m /b squash {second}",
                 "mdj /a", "mdj /a/sub", "miej /a/sub/file", f"miej /a {file_id}",
                 "miej /b/sub/file", "mfuj /b all", "b 128",
                 f"mg /a/sub/file {BLOCK - 3} {BLOCK * 2}", "mc /b/sub/file")
    lines = out.stdout.split(b"\n", 6)
    root, sub, ext, by_id, at_second, allocated = map(json.loads, lines[:6])
    assert [(entry["name"], entry["id"]) for entry in root] == [("sub", 32)]
    assert [(entry["name"], entry["id"], entry["size"]) for entry in sub] == [
        ("file", file_id, len(contents))]
    assert ext == by_id and ext["status"] == "complete"
    assert [(e["logical"], e["physical"], e["size"], e["flags"]) for e in ext["ranges"]] == [
        (0, first + 96, BLOCK, 2), (BLOCK, UNKNOWN, BLOCK, 64),
        (2 * BLOCK, UNKNOWN, BLOCK, 16), (3 * BLOCK, first + fragment_at + 5, 4, 2)]
    assert at_second["ranges"][0]["physical"] == second + 96
    assert allocated["ranges"] == [{"logical": 0, "physical": second, "size": len(data), "flags": 2}]
    assert (directory / "file").read_bytes() == contents[BLOCK - 3:3 * BLOCK - 3]
    assert lines[6] == contents + b"\n"

    image.write_bytes(PREFIX + data[:-1])
    result = run_r2(directory, image, f"m /bad squash {first}", "mj", allow_error=True)
    assert json.loads(result.stdout)["mountpoints"] == []


def test_jffs(directory, endian):
    data = jffs_image(endian)
    image = directory / "jffs.img"
    offset = len(PREFIX)
    image.write_bytes(PREFIX + data + b"outside partition")
    mount = f"m /j jffs2 {offset} size={len(data)}"
    out = run_r2(directory, image, mount, "mdj /j", "mdxj /j", "mdj /j/sub",
                 "miej /j/sub/live", "mfuj /j all", "mg /j/sub/live 3 8",
                 "mc /j/sub/rtime", "mc /j/sub/link")
    lines = out.stdout.splitlines()
    root, deleted, sub, ext, ranges = map(json.loads, lines[:5])
    assert [(entry["name"], entry["id"]) for entry in root] == [("sub", 2)]
    assert [(entry["name"], entry["id"]) for entry in sub] == [("live", 3), ("rtime", 7)]
    assert lines[5:] == [b"rrrrrr", b"live"]
    ids = {entry["name"]: entry["id"] for entry in deleted}
    assert set(ids) == {"alias", "gone", "badgone", "gap"}
    assert next(entry for entry in deleted if entry["name"] == "alias")["flags"] == 9
    assert [(e["logical"], e["size"], e["flags"]) for e in ext["ranges"]] == [
        (0, 4, 2), (4, 3, 16), (7, 3, 64), (10, 2, 2)]
    assert ranges["ranges"][-1]["flags"] == 1
    assert sum(e["size"] for e in ranges["ranges"]) == len(data)
    assert (directory / "live").read_bytes() == b"Dxxx\0\0\0y"
    recovered = run_r2(directory, image, mount, f"miej /j {ids['gone']}",
                       f"mgx /j {ids['gone']} recovered", "e fs.cwd=/j", "e search.in=fs.deleted",
                       "/xj 7265636f7665726564")
    recovered_ranges, hits = map(json.loads, recovered.stdout.splitlines())
    assert recovered_ranges["flags"] == 1
    assert (directory / "recovered").read_bytes() == b"recovered"
    assert [hit["addr"] for hit in hits] == [recovered_ranges["ranges"][0]["physical"]]
    for rejected in ("alias", "badgone", "gap"):
        out = run_r2(directory, image, mount, f"mgx /j {ids[rejected]} rejected", allow_error=True)
        assert b"Cannot open a recoverable file entry" in out.stderr
        assert not (directory / "rejected").exists()


R2 = os.environ.get("R2", "r2")
LIBEXT = os.environ.get("LIBEXT") or subprocess.check_output([R2, "-H", "LIBEXT"], text=True).strip()

if __name__ == "__main__":
    with tempfile.TemporaryDirectory() as tmp:
        directory = Path(tmp)
        for compressor in (1, 4):
            test_squash(directory, compressor)
        for byte_order in ("<", ">"):
            test_jffs(directory, byte_order)
