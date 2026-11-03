#!/usr/bin/env python3
"""Fetch P1/P2 word lists locally and build expanded 12-bit instruction images."""
import hashlib
from pathlib import Path
import re
import struct
import urllib.request

ROMS = {
    "p1": ("iN0pfyr7", "48a716bbae6395ad8b5f43c1a6f57f84ce8abffcdfda0786007b75c2e3a35665"),
    "p2": ("TXkwnBZA", "a1dfc57fef2bc5c0284600f086bfb94ed42795709ee0466779af2d9a7e7a5769"),
}
root = Path(__file__).resolve().parent.parent / "roms"
root.mkdir(exist_ok=True)
for name, (paste, digest) in ROMS.items():
    url = f"https://pastebin.com/raw/{paste}"
    request = urllib.request.Request(url, headers={"User-Agent": "curl/8.7.1"})
    with urllib.request.urlopen(request, timeout=30) as response:
        source = response.read().decode("utf-8")
    # Reject error pages, extra text and values outside the 12-bit word range.
    if re.sub(r"0x[0-9a-fA-F]+|[\s,]", "", source):
        raise ValueError(f"{url}: expected comma-separated hexadecimal words")
    words = [int(word, 16) for word in re.findall(r"0x([0-9a-fA-F]+)", source)]
    if len(words) != 6144 or max(words) > 0xFFF:
        raise ValueError(f"{url}: expected 6144 12-bit words")
    binary = struct.pack("<6144H", *words)
    if hashlib.sha256(binary).hexdigest() != digest:
        raise ValueError(f"{url}: ROM checksum changed")
    output = root / f"{name}.bin"
    output.write_bytes(binary)
    print(f"{output}: {len(binary)} bytes, sha256 {digest}")
