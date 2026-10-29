#!/usr/bin/env python3
"""Differentially verify native decoding against the emulated vendor binary."""
import argparse
import collections
import json
import random
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from vendor_oracle import Oracle
from extract_opcodes import tables


def normalize(text, addr):
    text = text.split(';')[0].strip().replace('#', '')
    text = re.sub(r'\s+', ' ', text)
    # The vendor prints sign-extended immediates as unsigned 64-bit hex.
    text = re.sub(r'0x[0-9a-f]+', lambda m: '-0x%x' % ((1 << 64) - int(m.group(), 16))
                  if int(m.group(), 16) >= 1 << 63 else m.group(), text)
    chunks = text.split(' | ')
    for i, chunk in enumerate(chunks):
        name = chunk.split(' ')[0]
        if re.fullmatch(r'(?:beq|bne|bleu?|bltu?|j|jal|do)(?:16)?(?:\.d[12])?', name):
            m = re.search(r'(-?0x[0-9a-f]+)$', chunk)
            if m:
                dest = (addr + int(m.group(), 16)) & 0xffffffff
                chunks[i] = chunk[:m.start()] + hex(dest)
    text = ' | '.join(chunks)
    return re.sub(r'(?<!-)0x0*([0-9a-f]+)', lambda m: hex(int(m.group(), 16)), text)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('objdump')
    p.add_argument('--quick', action='store_true')
    p.add_argument('--firmware', type=Path, help='Canonical big-endian MD32 code')
    args = p.parse_args()
    vendor = Oracle(args.objdump)
    rng = random.Random(0x4d443332)
    cases = []
    firmware_results = {}
    # All standalone 16-bit encodings, with a fixed second halfword, also
    # exercise every pair-prefix encoding and illegal short instruction.
    for h in range(0x10000) if not args.quick else range(0, 0x10000, 79):
        cases.append(((h << 16) | 0x203f, 0x1000))
    # Exercise every named opcode with randomized operands, including all
    # reserved bits constrained by the vendor's mask.
    for row in tables(vendor.elf):
        for _ in range(12 if args.quick else 100):
            word = row['opcode'] | (rng.getrandbits(32) & ~row['mask'])
            if row['group'] != 1:
                word = ((word & 0xffff) << 16) | 0x8000
            cases.append((word, rng.randrange(0, 0x100000000) & ~1))
    # Packed pairs: no byte-order assumptions or previous-decode state.
    for _ in range(200 if args.quick else 10000):
        prefix = rng.choice([0x4000, 0x6000]) | rng.randrange(0x1000)
        suffix = rng.choice([0x2000, 0x6000]) | rng.randrange(0x2000) | rng.choice([0, 0x8000])
        cases.append(((prefix << 16) | suffix, 0x1000))
    if args.firmware:
        data = args.firmware.read_bytes()
        offset = 0
        # Use the vendor's instruction boundaries, not those of our decoder.
        while offset + 4 <= len(data):
            code = data[offset:offset + 4]
            cases.append((int.from_bytes(code, 'big'), offset))
            size, text = vendor.decode(code, offset)
            firmware_results[len(cases) - 1] = (size, text)
            offset += size
            if len(firmware_results) % 10000 == 0:
                print("Scanned", len(firmware_results), "firmware instructions", flush=True)
    inp = ''.join('%08x 4 %x\n' % item for item in cases)
    native = subprocess.run([str(ROOT / 'test/test_md32'), '--stream'],
                            input=inp, text=True, capture_output=True, check=True).stdout.splitlines()
    assert len(native) == len(cases)
    failures = []
    counts = collections.Counter()
    for i, ((word, addr), line) in enumerate(zip(cases, native)):
        fields = line.split('\t')
        valid, size = map(int, fields[:2])
        expected_size, expected = firmware_results.get(i) or vendor.decode(word.to_bytes(4, 'big'), addr)
        expected_valid = 'illegal' not in expected
        counts['valid' if expected_valid else 'illegal'] += 1
        actual = fields[6]
        # Normalise our absolute target formatting without adding PC twice.
        actual = re.sub(r'0x[0-9a-f]+', lambda m: hex(int(m.group(), 16)), actual)
        if bool(valid) != expected_valid or size != expected_size or (valid and
                actual != normalize(expected, addr)):
            failures.append((hex(word), hex(addr), size, actual, expected_size, expected))
            if len(failures) <= 15:
                print('MISMATCH:', failures[-1], flush=True)
        if (i + 1) % 10000 == 0:
            print('Compared', i + 1, 'instructions;', len(failures), 'mismatches', flush=True)
    print(json.dumps(dict(cases=len(cases), mismatches=len(failures), **counts)), flush=True)
    if failures:
        Path('/tmp/md32-oracle-mismatches.json').write_text(json.dumps(failures, indent=2))
        raise SystemExit(1)


if __name__ == '__main__':
    main()
