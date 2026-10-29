#!/usr/bin/env python3
"""Convert little-endian 32-bit firmware storage to the MD32 instruction stream.

This reverses each storage word, not each variable-length instruction. It is
for older VPU/MD32 firmware blobs; do not apply it to the supplied uSIP files.
"""
import argparse
from pathlib import Path

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('input', type=Path)
p.add_argument('output', type=Path)
args = p.parse_args()
data = args.input.read_bytes()
if len(data) % 4:
    p.error('input size must be a multiple of four bytes')
if args.input.resolve() == args.output.resolve():
    p.error('use a separate output file')
args.output.write_bytes(b''.join(data[i:i + 4][::-1] for i in range(0, len(data), 4)))
