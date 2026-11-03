#!/usr/bin/env python3
"""Pack the upstream RGBA PNG pictograms into code-native monochrome rows."""
from pathlib import Path
import struct
import zlib

ROOT = Path(__file__).resolve().parent.parent


def rows(path):
    data = path.read_bytes()
    assert data[:8] == b"\x89PNG\r\n\x1a\n"
    at = 8
    packed = bytearray()
    while at < len(data):
        length = struct.unpack_from(">I", data, at)[0]
        kind, payload = data[at + 4:at + 8], data[at + 8:at + 8 + length]
        if kind == b"IHDR":
            assert struct.unpack(">IIBBBBB", payload) == (22, 18, 8, 6, 0, 0, 0)
        if kind == b"IDAT":
            packed.extend(payload)
        at += 12 + length
    raw = zlib.decompress(packed)
    stride = 22 * 4
    previous = bytearray(stride)
    result = []
    for y in range(18):
        start = y * (stride + 1)
        mode = raw[start]
        scan = bytearray(raw[start + 1:start + 1 + stride])
        for x in range(stride):
            left = scan[x - 4] if x >= 4 else 0
            up = previous[x]
            corner = previous[x - 4] if x >= 4 else 0
            guess = left + up - corner
            distances = (abs(guess - left), abs(guess - up), abs(guess - corner))
            paeth = (left, up, corner)[distances.index(min(distances))]
            scan[x] = (scan[x] + (0, left, up, (left + up) // 2, paeth)[mode]) & 255
        result.append(sum(1 << x for x in range(22)
                          if scan[x * 4 + 3] >= 128 and sum(scan[x * 4:x * 4 + 3]) < 384))
        previous = scan
    return result


names = ("Food", "Light", "Game", "Medicine", "Toilet", "Status", "Discipline", "Attention")
output = "/* Packed from the PNG assets in assets/icons by scripts/build-icons.py; see assets/icons/README.md. */\n\n"
output += "static const ut32 tama_icon_pixels[8][18] = {\n"
for index, name in enumerate(names, 1):
    output += "\t// " + name + "\n\t{ " + ", ".join(f"0x{row:06x}" for row in rows(ROOT / "assets/icons" / f"{index}.png")) + " },\n"
output += "};\n"
(ROOT / "icons.inc.c").write_text(output)
