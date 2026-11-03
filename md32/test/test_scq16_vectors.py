#!/usr/bin/env python3
"""Exercise cpu=scq16 with the public bytes-only vectors of test/scq16_vectors.json: for every row the disassembly of each unit at its
address (text and size) and, when the row carries an expected result, the ESIL of the r2 command line (registers / memory bytes) in the
big-endian regime of this harness (`r2` / `expected`, cfg.bigendian=true) and, when the row carries `r2_le` / `expected_le`, in the
little-endian regime of the core's data memory (cfg.bigendian=false: scalar memory values are stored little-endian).  Each row is
stand-alone: bytes, an initial state and the result the table predicts; no firmware is needed.
Usage: python3 test/test_scq16_vectors.py [--only ID,...]"""
import json
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
R2 = os.environ.get('R2', 'r2')
ext = subprocess.check_output([R2, '-H', 'R2_LIBEXT'], text=True).strip()
PLUGIN = ROOT / ('arch_md32.' + ext)
ASM_PLUGIN = ROOT / ('asm_md32.' + ext)
ONLY = sys.argv[sys.argv.index('--only') + 1].split(',') if '--only' in sys.argv else None
failures = 0


def r2(commands, bigendian=True, size=0x10000):
    setup = 'e scr.color=0;L %s;L %s;e asm.cpu=scq16;e asm.arch=md32;e cfg.bigendian=%s;' % (PLUGIN, ASM_PLUGIN, 'true' if bigendian else 'false')
    proc = subprocess.run([R2, '-NN', '-q', '-c', setup + commands + ';q', 'malloc://%d' % size], capture_output=True, text=True, check=True)
    return [l for l in proc.stdout.strip().splitlines() if not l.startswith(('WARN', 'INFO', 'ERROR'))]


def check(cond, msg):
    global failures
    print(('ok   ' if cond else 'FAIL ') + msg)
    if not cond:
        failures += 1


def norm(t):
    return re.sub(r'0x0*([0-9a-f]+)', lambda m: '0x' + (m.group(1) or '0'), t)   # the plugin prints 8-digit targets


V = json.load(open(ROOT / 'test' / 'scq16_vectors.json'))['vectors']
n_dis = n_be = n_le = 0
for v in V:
    if ONLY and v['id'] not in ONLY:
        continue
    for hx, L, exp, pc in v['disasm']:
        out = r2('wx %s @ %#x;pi 1 @ %#x;ao 1 @ %#x~size' % (hx, pc, pc, pc))
        text = out[0] if out else ''
        check(norm(text) == norm(exp) and any(l.strip() == 'size: %d' % L for l in out), '%s %-18s -> %s' % (v['id'], hx, text))
        n_dis += 1
    for tag, cmd_key, exp_key, be in (('BE', 'r2', 'expected', True), ('LE', 'r2_le', 'expected_le', False)):
        exp = v.get(exp_key)
        if exp is None:
            continue
        out = r2(v[cmd_key], be)
        got = {}
        for k, line in zip(exp.keys(), out[-len(exp):]):
            got[k] = line.strip() if k.startswith('mem[') else '%#x' % int(line, 16)
        check(got == exp, '%s ESIL %s (%s): %s' % (v['id'], tag, v['hypothesis_of_table'], got))
        if be:
            n_be += 1
        else:
            n_le += 1
print('\n%s (%d disassembly + %d ESIL checks: %d big-endian + %d little-endian)' % ('ALL OK' if not failures else '%d FAILURES' % failures, n_dis, n_be + n_le, n_be, n_le))
sys.exit(1 if failures else 0)
