#!/usr/bin/env python3
"""Reproduce the uSIP firmware inventory, annotated disassembly and flow audit.

Uses the actual native arch plugin via test_md32's stream interface. Symbol
ranges are evidence supplied with the images; their physical load aliases are
assumptions, not an independently recovered linker map.
"""
import argparse
import collections
import csv
import hashlib
import json
import re
import struct
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
# Default load aliases for the three supplied images. They are hypotheses, not a
# validated linker map; override them with --base NAME=0xADDR for other images.
REGIONS = {'sec0': 0x400e0000, 'ddr': 0x1ca34000, 'brp': 0x80c00000}
VECTOR_BYTES = 0x400
# Functions whose flow targets are not worth listing (e.g. the reset veneer).
SKIP_FLOW_FUNCTIONS = ('_ss_reset_entry',)


def parse_bases(items):
    if not items:
        return dict(REGIONS)
    bases = {}
    for item in items:
        name, _, value = item.partition('=')
        if not name or not value:
            raise SystemExit('--base wants NAME=0xADDR, got %r' % item)
        bases[name] = int(value, 0)
    return bases


def region_for(addr, bases=None):
    """Pick the region whose base is nearest below addr, else the lowest."""
    bases = REGIONS if bases is None else bases
    below = [a for a in bases.values() if a <= addr]
    wanted = max(below) if below else min(bases.values())
    return next(k for k, a in bases.items() if a == wanted)


def display(path):
    """Keep generated output free of absolute paths when they are inside ROOT."""
    path = Path(path).resolve()
    return str(path.relative_to(ROOT)) if path.is_relative_to(ROOT) else str(path)


def image_path(bundle, region):
    """Accept both the vendor-prefixed and the plain per-region image name."""
    for name in ('%s.bin' % region, 'usip_%s.bin' % region):
        path = Path(bundle) / 'bin' / name
        if path.exists():
            return path
    raise SystemExit('missing image for region %r under %s' % (region, Path(bundle) / 'bin'))


def inventory(bundle, bases=None, path=None):
    bases = REGIONS if bases is None else bases
    lowest = min(bases.values())
    result = []
    with Path(path or (Path(bundle) / 'data/functions.csv')).open() as fd:
        for r in csv.DictReader(fd):
            start, end = int(r['addr'], 16), int(r['end'], 16)
            region = region_for(start, bases)
            bias = bases[region] if start < lowest else 0
            result.append(dict(name=r['name'], source=r['source'], region=region,
                               start=start + bias, end=end + bias,
                               expected_instructions=int(r['instructions'])))
    return sorted(result, key=lambda f: (f['region'], f['start']))


def decode(items, decoder, cpu='usip'):
    text = ''.join('%s %d %x\n' % (code.ljust(4, b'\0').hex(), len(code), addr)
                   for addr, code, _ in items)
    proc = subprocess.run([str(decoder), '--stream', cpu], input=text, text=True,
                          capture_output=True, check=True)
    lines = proc.stdout.splitlines()
    if len(lines) != len(items):
        raise ValueError('Native decoder did not return one result per instruction')
    for (addr, code, function), line in zip(items, lines):
        fields = line.split('\t')
        valid, size, kind = map(int, fields[:3])
        if not valid or size != len(code):
            raise ValueError('Invalid/truncated instruction at %#x' % addr)
        yield dict(address=addr, bytes=code.hex(), size=size, type=kind,
                   jump=None if fields[3] == 'ffffffffffffffff' else int(fields[3], 16),
                   mnemonic=fields[6], esil=fields[7], function=function)


def scan_strings(data, base):
    result = []
    # Strict printable C-string candidates; raw printable runs inside code
    # are counted separately, not mislabeled as strings.
    for m in re.finditer(rb'[ -~]{6,}\x00', data):
        text = m.group()[:-1].decode('ascii')
        if re.search(r'[A-Za-z]{4}', text):
            result.append(dict(address=base + m.start(), encoding='ascii', value=text))
    for order, pattern in [('utf16le', rb'(?:[ -~]\x00){6,}\x00\x00'),
                           ('utf16be', rb'(?:\x00[ -~]){6,}\x00\x00')]:
        for m in re.finditer(pattern, data):
            text = m.group()[:-2].decode('utf-16-le' if order.endswith('le') else 'utf-16-be')
            if re.search(r'[A-Za-z]{4}', text):
                result.append(dict(address=base + m.start(), encoding=order, value=text))
    return result


def analyze(bundle, output, decoder, bases=None, inventory_path=None,
            vector_bytes=VECTOR_BYTES, cpu='usip', skip_flows=SKIP_FLOW_FUNCTIONS):
    bases = dict(REGIONS if bases is None else bases)
    boot = min(bases, key=bases.get)
    boot_base = bases[boot]
    output.mkdir(parents=True, exist_ok=True)
    fs = inventory(bundle, bases, inventory_path)
    by_region = {k: [f for f in fs if f['region'] == k] for k in bases}
    instructions, image_stats, all_strings = [], [], []
    starts = {f['start']: f for f in fs}
    for region, base in bases.items():
        path = image_path(bundle, region)
        data = path.read_bytes()
        items = []
        mismatches = []
        for f in by_region[region]:
            off, end = f['start'] - base, f['end'] - base
            if not 0 <= off < end <= len(data):
                raise ValueError('Symbol outside image: %r' % f)
            count = 0
            while off < end:
                size = 2 if data[off] & 0x80 else 4
                if off + size > end:
                    raise ValueError('Function boundary splits instruction: %s' % f['name'])
                items.append((base + off, data[off:off + size], f['name']))
                off += size
                count += 1
            if count != f['expected_instructions']:
                mismatches.append(f['name'])
        decoded = list(decode(items, decoder, cpu))
        instructions.extend(decoded)
        # Vector slots are executable branch stubs, not address data.
        code = decoded
        body = [i for i in decoded
                if not(region == boot and i['address'] < base + vector_bytes)]
        counts = collections.Counter(i['mnemonic'].split()[0] for i in code)
        unknown = collections.Counter((i['size'], i['bytes'][:4]) for i in code
                                      if i['mnemonic'].startswith('.'))
        strings = scan_strings(data, base)
        all_strings.extend(strings)
        (output / ('%s-strings.json' % region)).write_text(json.dumps(strings, indent=2) + '\n')
        with (output / ('%s-disassembly.txt' % region)).open('w') as fd:
            prev = None
            for i in decoded:
                if i['function'] != prev:
                    fd.write('\n; %s\n' % i['function'])
                    prev = i['function']
                comment = ''
                if region == boot and i['address'] < base + vector_bytes:
                    comment = ' ; executable vector %d' % ((i['address'] - base) // 4)
                    target = starts.get(i['jump'])
                    if target:
                        comment += ' -> ' + target['name']
                    elif i['jump'] == i['address']:
                        comment += ' (self-loop)'
                elif i['jump'] is not None:
                    target = starts.get(i['jump'])
                    if target:
                        comment = ' ; -> ' + target['name']
                fd.write('%08x  %-8s  %s%s\n' % (i['address'], i['bytes'], i['mnemonic'], comment))
        image_stats.append(dict(region=region, file=display(path), base=base,
                                size=len(data), sha256=hashlib.sha256(data).hexdigest(),
                                functions=len(by_region[region]), instruction_records=len(decoded), code_instructions=len(code),
                                non_vector_instructions=len(body), counts=dict(counts), string_candidates=len(strings),
                                long_string_candidates=sum(len(x['value']) >= 8 for x in strings),
                                metadata_count_mismatches=mismatches,
                                unresolved_top=[dict(size=k[0], hw1=k[1], count=v)
                                                for k, v in unknown.most_common(40)]))
    boundaries = {i['address'] for i in instructions}
    indexed = {i['address']: i for i in instructions}
    flows, return_extensions = [], collections.Counter()
    for i in instructions:
        if i['function'] in skip_flows:
            continue
        if i['bytes'].startswith('5ef9'):
            return_extensions[i['bytes'][4:]] += 1
        if i['jump'] is not None:
            f = next(f for f in fs if f['name'] == i['function'] and f['start'] <= i['address'] < f['end'])
            flows.append(dict(address=i['address'], function=i['function'], mnemonic=i['mnemonic'],
                              target=i['jump'], target_is_boundary=i['jump'] in boundaries,
                              target_symbol=starts.get(i['jump'], {}).get('name'),
                              target_inside_function=f['start'] <= i['jump'] < f['end']))
    data = image_path(bundle, boot).read_bytes()
    vectors = []
    old_pointer_targets = struct.unpack('>%dI' % (vector_bytes // 4), data[:vector_bytes])
    for n, word in enumerate(old_pointer_targets):
        address = boot_base + n * 4
        instruction = indexed[address]
        target = instruction['jump']
        containing = next((f for f in fs if target is not None and f['start'] <= target < f['end']), None)
        vectors.append(dict(index=n, address=address, encoding=word,
                            instruction=instruction['mnemonic'], target=target,
                            self_loop=target == address,
                            target_symbol=starts.get(target, {}).get('name'),
                            containing_symbol=containing['name'] if containing else None,
                            at_instruction_boundary=target in boundaries))
    pointer_hypothesis = dict(rejected=True,
                              mapped_targets=sum(boot_base <= t < boot_base + len(data)
                                                 for t in old_pointer_targets),
                              boundary_targets=sum(t in boundaries for t in old_pointer_targets),
                              exact_symbols=sum(t in starts for t in old_pointer_targets))
    aliases = collections.defaultdict(list)
    tree = Path(bundle).parent.parent
    for p in (sorted(tree.rglob('*.bin')) if tree.is_dir() else []):
        aliases[hashlib.sha256(p.read_bytes()).hexdigest()].append(display(p))
    candidate_refs = []
    string_addresses = {s['address'] for s in all_strings}
    for region, base in bases.items():
        data = image_path(bundle, region).read_bytes()
        for offset in range(0, len(data) - 3, 2):
            for endian in ('big', 'little'):
                target = int.from_bytes(data[offset:offset + 4], endian)
                if target in string_addresses:
                    candidate_refs.append(dict(address=base + offset, target=target, endian=endian,
                                               evidence='raw pointer candidate, not a decoded instruction reference'))
    report = dict(images=image_stats, functions=len(fs), flows=flows, vectors=vectors,
                  legacy_pointer_hypothesis=pointer_hypothesis,
                  string_pointer_candidates=candidate_refs,
                  return32_extensions=return_extensions.most_common(),
                  duplicate_images=[v for v in aliases.values() if len(v) > 1])
    (output / 'inventory.json').write_text(json.dumps(report, indent=2) + '\n')
    with (output / 'functions.csv').open('w') as fd:
        writer = csv.DictWriter(fd, fieldnames=list(fs[0]))
        writer.writeheader()
        writer.writerows(fs)
    # Load each image at its supplied alias, then add names (not guessed CFGs).
    with (output / 'load-usip.r2').open('w') as fd:
        fd.write('e asm.arch=md32\ne asm.cpu=%s\ne cfg.bigendian=true\n' % cpu)
        for region, base in bases.items():
            path = image_path(bundle, region).resolve()
            fd.write('on "%s" 0x%x r-x\n' % (display(path), base))
        for f in fs:
            name = re.sub('[^a-zA-Z0-9_.$]', '_', f['name'])
            fd.write('f sym.%s %d @ 0x%x\n' % (name, f['end'] - f['start'], f['start']))
        for v in vectors:
            fd.write('f vector.%d 4 @ 0x%x\n' % (v['index'], boot_base + v['index'] * 4))
        fd.write('s 0x%x\n' % vectors[0]['address'])
    print(json.dumps(dict(images=image_stats, functions=len(fs), decoded=len(instructions),
                          flow_candidates=len(flows), invalid_flow_boundaries=sum(not f['target_is_boundary'] for f in flows),
                          decoded_vectors=sum(v['target'] is not None for v in vectors),
                          vector_self_loops=sum(v['self_loop'] for v in vectors),
                          reset=vectors[0], return32_extension_variants=len(return_extensions)), indent=2))
    return report


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--bundle', type=Path, default=ROOT / 'third_party/v2/r2pkg')
    p.add_argument('--output', type=Path, default=ROOT / 'usipdata')
    p.add_argument('--decoder', type=Path, default=ROOT / 'test/test_md32')
    p.add_argument('--inventory', type=Path, default=None,
                   help='function CSV (default: BUNDLE/data/functions.csv)')
    p.add_argument('--base', action='append', metavar='NAME=0xADDR',
                   help='load alias per region, repeatable (default: %s)'
                        % ', '.join('%s=%#x' % kv for kv in REGIONS.items()))
    p.add_argument('--vector-bytes', type=lambda s: int(s, 0), default=VECTOR_BYTES,
                   help='leading vector-table bytes in the boot image')
    p.add_argument('--cpu', default='usip', help='CPU name passed to the decoder')
    p.add_argument('--skip-flow-function', action='append', metavar='NAME',
                   default=list(SKIP_FLOW_FUNCTIONS),
                   help='function whose flow targets are not listed, repeatable')
    args = p.parse_args()
    analyze(args.bundle.resolve(), args.output.resolve(), args.decoder.resolve(),
            bases=parse_bases(args.base),
            inventory_path=args.inventory.resolve() if args.inventory else None,
            vector_bytes=args.vector_bytes, cpu=args.cpu,
            skip_flows=tuple(args.skip_flow_function))
