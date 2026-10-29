#!/usr/bin/env python3
"""Exercise the actual plugin in r2 and the supplied uSIP firmware inventory."""
import collections
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from usip_symbols import functions

R2 = os.environ.get('R2', 'r2')
ext = subprocess.check_output([R2, '-H', 'R2_LIBEXT'], text=True).strip()
PLUGIN = ROOT / ('arch_md32.' + ext)
ASM_PLUGIN = ROOT / ('asm_md32.' + ext)


def r2(commands, size=128):
    setup = 'e scr.color=0;L %s;L %s;e asm.arch=md32;e cfg.bigendian=true;' % (PLUGIN, ASM_PLUGIN)
    proc = subprocess.run([R2, '-NN', '-q', '-c', setup + commands + ';q',
                           'malloc://%d' % size], capture_output=True, text=True, check=True)
    return proc.stdout.strip().splitlines()


def integration():
    # Load the actual RAsmPlugin and exercise the disassembly display path.
    assert r2('e asm.parser')[0] == 'md32'
    text = '\n'.join(r2('e asm.pseudo=true;wx 981198220400e321a03f;pD 10'))
    assert 'r1 = 0x1' in text and 'r1 = (r2 + r3)' in text and 'return' in text
    text = '\n'.join(r2('e asm.pseudo=true;wx 060fff2106c008214600203f;pD 12'))
    assert 'r2 = dmem8[r1 - 0x1]' in text
    assert 'r2 = dmem32[r1]; r1 += 0x8' in text
    assert 'parallel { r0 ^= r0; return; }' in text
    text = '\n'.join(r2('e asm.cpu=usip;e asm.pseudo=true;wx 400ee010400cd0105ef9901a;pD 12'))
    assert 'goto 0x00000010' in text and 'if (condition_0) goto 0x00000014' in text
    assert 'uSIP extension semantics unresolved' in text
    text = '\n'.join(r2('e asm.pseudo=true;wx 400fd5c0;e asm.cpu=usip;pD 4'))
    assert '.word 0x400fd5c0' in text
    ops = json.loads(r2('wx 981198220400e321a03f;aoj 4')[0])
    assert [o['size'] for o in ops] == [2, 2, 4, 2]
    assert [o['type'] for o in ops] == ['mov', 'mov', 'add', 'ret']
    assert ops[2]['opex']['operands'][2] == dict(type='reg', value='r3')
    regs = json.loads(r2('wx 981198220400e321;aei;ar r3=4;aes;aes;aes;arj')[0])
    assert regs['r1'] == 6 and regs['r2'] == 2 and regs['pc'] == 8
    # Signed byte load, then a word store in the Harvard data-memory view.
    regs = json.loads(r2('wx 06200012;wx 80 @ 32;aei;ar r2=32;aes;arj')[0])
    assert regs['r1'] == 0xffffff80
    # Signed and unsigned comparisons differ for 0xffffffff versus one.
    for opcode, expected_pc in [('1a000421', 8), ('1b000421', 4)]:
        regs = json.loads(r2('wx %s;aei;ar r2=0xffffffff;ar r1=1;aes;arj' % opcode)[0])
        assert regs['pc'] == expected_pc, (opcode, regs)
    regs = json.loads(r2('wx 1f80000f;aei;ar r15=32;aes;arj')[0])
    assert regs['pc'] == 32 and regs['r15'] == 4
    # Comparisons must also work when both operands cross the sign boundary.
    for opcode, expected_pc in [('1a000421', 4), ('1b000421', 8)]:
        regs = json.loads(r2('wx %s;aei;ar r2=0;ar r1=0xffffffff;aes;arj' % opcode)[0])
        assert regs['pc'] == expected_pc, (opcode, regs)
    # Delay-slot fallthrough must skip a two-byte instruction, not a fixed 4.
    bbs = json.loads(r2('wx 14000621800005000000a03fa03f;af;afbj', 14)[0])
    assert bbs[0]['size'] == 6 and bbs[0]['jump'] == 12 and bbs[0]['fail'] == 6
    ops = json.loads(r2('e asm.cpu=usip;wx 5f051e90000e78aaff05def9;aoj 4')[0])
    assert [o['size'] for o in ops] == [4, 4, 2, 2]
    assert ops[1]['jump'] == 0x8ae and ops[3]['type'] == 'ret'
    # uSIP condition numbers are decoded without assigning comparison names.
    ops = json.loads(r2('e asm.cpu=usip;wx 400cd010;aoj 1')[0])
    assert ops[0]['type'] == 'cjmp' and ops[0]['opcode'] == 'b0 0x00000010'
    assert ops[0]['jump'] == 0x10 and ops[0]['fail'] == 4
    ops = json.loads(r2('e asm.cpu=usip;wx 5f051e90000e78aa460ce030def9;aoj 4')[0])
    assert ops[2]['opcode'] == 'b3 0x00000038'
    assert ops[2]['jump'] == 0x38 and ops[2]['fail'] == 12
    ops = json.loads(r2('e asm.cpu=usip;wx df355ef900007f45abcd;aoj 3')[0])
    assert [o['size'] for o in ops] == [2, 4, 4]
    assert [o['opcode'] for o in ops] == ['save16 0x3', 'ret', 'restore 0x4']
    assert ops[1]['type'] == 'ret'
    # Tag F was accidentally accepted by the former >= C test. It is not
    # part of the supplied C/D/E branch rule and includes counterexamples.
    ops = json.loads(r2('e asm.cpu=usip;wx 400cfe72;aoj 1')[0])
    assert ops[0]['type'] == 'unk' and 'jump' not in ops[0]
    assert ops[0]['opex']['extension'] == 0xfe72
    ops = json.loads(r2('e asm.cpu=usip;wx 5ef9901a;aoj 1')[0])
    assert ops[0]['opex']['extension_semantics_unresolved']
    assert ops[0]['opex']['provisional'] and not ops[0].get('esil')
    ops = json.loads(r2('wx 0f123401;aoj 1')[0])
    assert ops[0]['val'] == 0x12340000
    print('Plugin loading, analysis, delay slots, operands and ESIL passed')


def corpus():
    bundle = ROOT / 'third_party/r2pkg'
    if not (bundle / 'bin/usip_sec0.bin').exists():
        print('r2pkg bundle absent; skipping optional corpus check')
        return
    blobs = {False: (bundle / 'bin/usip_sec0.bin').read_bytes(),
             True: (bundle / 'bin/usip_ddr.bin').read_bytes()}
    inp, expected = [], []
    fs = list(functions())
    assert len(fs) == 1128
    for start, end, name in fs:
        ddr = start >= 0x100000
        data = blobs[ddr]
        origin = 0x1ca34000 if ddr else 0
        pos, stop = start - origin, end - origin
        assert 0 <= pos < stop <= len(data), (name, start, end)
        while pos < stop:
            size = 2 if data[pos] & 0x80 else 4
            assert pos + size <= stop, name
            code = data[pos:pos + size].ljust(4, b'\0')
            inp.append('%s %d %x\n' % (code.hex(), size, origin + pos))
            expected.append((size, code[:size]))
            pos += size
    result = subprocess.run([str(ROOT / 'test/test_md32'), '--stream', 'usip'],
                            input=''.join(inp), text=True, capture_output=True, check=True)
    lines = result.stdout.splitlines()
    assert len(lines) == len(expected) == 100275
    counts = collections.Counter()
    for line, (size, code) in zip(lines, expected):
        fields = line.split('\t')
        assert fields[0] == '1' and int(fields[1]) == size, (code.hex(), line)
        counts[fields[6].split()[0]] += 1
    print('uSIP: all 1128 function boundaries and 100275 instruction lengths match')
    print('uSIP decode counts:', json.dumps(dict(sorted(counts.items()))))


if __name__ == '__main__':
    integration()
    corpus()
