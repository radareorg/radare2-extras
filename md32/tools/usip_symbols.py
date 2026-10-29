#!/usr/bin/env python3
"""Emit r2 symbol flags from the supplied uSIP function inventory.

This needs only the supplied r2pkg bundle, not the original private dsp.bin or
DbgInfo files. Addresses in the sec0 inventory are relative to 0x400e0000.
"""
import argparse
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INVENTORY_GLOBS = ('third_party/*/docs/*usip*dump*.md', 'third_party/*/docs/*dump*.md')
PATTERN = re.compile(r'^\| `([0-9a-f]+)`-`([0-9a-f]+)` \| (\d+) \| .*? \| `([^`]+)` \|')


def default_inventory():
    """Find the supplied function inventory instead of hardcoding a bundle path."""
    for pattern in INVENTORY_GLOBS:
        found = sorted(ROOT.glob(pattern))
        if found:
            return found[0]
    return None


def functions(path=None):
    path = path or default_inventory()
    if path is None:
        raise SystemExit('no function inventory found; pass --inventory PATH')
    for line in Path(path).read_text().splitlines():
        m = PATTERN.match(line)
        if m:
            start, end, size, name = m.groups()
            start, end, size = int(start, 16), int(end, 16), int(size)
            assert end - start == size
            yield start, end, name


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--section', choices=['sec0', 'ddr', 'all'], default='all')
    p.add_argument('--inventory', type=Path, default=None,
                   help='function inventory Markdown (default: auto-detected)')
    p.add_argument('--sec0-base', type=lambda s: int(s, 0), default=0x400e0000,
                   help='load alias added to the relative sec0 addresses')
    args = p.parse_args()
    for start, end, name in functions(args.inventory):
        section = 'sec0' if start < 0x100000 else 'ddr'
        if args.section not in (section, 'all'):
            continue
        addr = start + args.sec0_base if section == 'sec0' else start
        name = re.sub(r'[^a-zA-Z0-9_.$]', '_', name)
        print('f sym.%s %d @ 0x%08x' % (name, end - start, addr))


if __name__ == '__main__':
    main()
