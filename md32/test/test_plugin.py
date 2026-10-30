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
    # uSIP packets: slot-0 control flow, delay slot, interleaved S S O O layout.
    text = '\n'.join(r2('e asm.cpu=usip;e asm.pseudo=true;wx 7e0cc00c5c3907f0541c805c@0x40c;pD 12@0x40c', 0x8000))
    assert 'if (r15 != 0) goto 0x00000418' in text and 'goto 0x0000041e' in text and 'r15 = 0x1d07005c' in text
    text = '\n'.join(r2('e asm.cpu=usip;e asm.pseudo=true;wx 3e015000400ac000def9@0x41e;pD 10@0x41e', 0x8000))
    assert 'r0 = sext8(dmem8[r15 + 0xa])' in text and 'r0 = dmem32[r8 + 0x0]' in text and 'return' in text
    assert '.unit 0x400a (ld.b @ 0x0000041e)' in text and '.unit 0xc000 (ld.w @ 0x00000420)' in text
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
    # bnez: conditional branch with its tail adjacent; fail = next packet.
    ops = json.loads(r2('e asm.cpu=usip;wx 7e0cc00c@0x40c;aoj 1@0x40c', 0x8000)[0])
    assert ops[0]['size'] == 4 and ops[0]['type'] == 'cjmp' and ops[0]['opcode'] == 'bnez r15, 0x00000418'
    assert ops[0]['jump'] == 0x418 and ops[0]['fail'] == 0x410 and ops[0]['cond'] == 'ne'
    assert ops[0]['opex']['form'] == 'bnez' and ops[0]['opex']['units'] == [0x40c, 0x40e]
    # b.s with the packet open: the 48-bit mov32 that follows is its delay slot (one op).
    ops = json.loads(r2('e asm.cpu=usip;wx 5c3907f0541c805c@0x410;aoj 2@0x410', 0x8000)[0])
    assert [o['size'] for o in ops] == [2, 6] and [o['type'] for o in ops] == ['jmp', 'mov']
    assert ops[0]['jump'] == 0x41e and ops[0]['delay'] == 1 and ops[0]['opex']['packet']['delay']
    assert ops[1]['opcode'] == 'mov32 r15, #0x1d07005c' and ops[1]['opex']['delay_slot'] and ops[1]['val'] == 0x1d07005c
    # call with S = 0 tail at +2 (S S O O): call, the parallel op, then the two tails as .unit; delay = 3 ops.
    ops = json.loads(r2('e asm.cpu=usip;wx 400e40a07052c0fc@0xf18;aoj 4@0xf18', 0x8000)[0])
    assert [o['size'] for o in ops] == [2, 2, 2, 2] and ops[0]['type'] == 'call'
    assert ops[0]['jump'] == 0xf6a and ops[0]['fail'] == 0xf20 and ops[0]['delay'] == 3
    assert ops[2]['opcode'].startswith('.unit 0x7052 (call @ 0x00000f18)') and ops[2]['opex']['tail']
    assert ops[0]['opex']['units'] == [0xf18, 0xf1c]
    # 48-bit absolute call (x008 X hi lo X' lo'): hi/lo by rule R at +2/+3, one 4-byte .unit; 5 ops in the packet.
    ops = json.loads(r2('e asm.cpu=usip;wx 0608110b733769b012079407@0x1058;aoj 5@0x1058', 0x8000)[0])
    assert ops[0]['opcode'] == 'call.abs 0x1ccde9b0' and ops[0]['jump'] == 0x1ccde9b0 and ops[0]['size'] == 2
    assert ops[0]['opex']['units'] == [0x1058, 0x105c, 0x105e] and ops[0]['delay'] == 4 and ops[0]['fail'] == 0x1064
    assert [o['size'] for o in ops] == [2, 2, 4, 2, 2]
    assert ops[2]['opcode'] == '.unit 0x733769b0 (call.abs @ 0x00001058)'
    # hardware loop: the end address is a reference, not a branch.
    ops = json.loads(r2('e asm.cpu=usip;wx 060f02277010786028104390c100@0x2478;aoj 1@0x2478', 0x8000)[0])
    assert ops[0]['opcode'] == 'loop r3, last=0x00002488' and ops[0]['ptr'] == 0x2488 and 'jump' not in ops[0]
    # ret.d: the next op is its delay slot; ret closes a packet by itself.
    ops = json.loads(r2('e asm.cpu=usip;wx 5ef9a10ddef9@0x10a2;aoj 3@0x10a2', 0x8000)[0])
    assert ops[0]['opcode'] == 'ret.d' and ops[0]['type'] == 'ret' and ops[0]['delay'] == 1
    assert ops[2]['opcode'] == 'ret' and ops[2]['type'] == 'ret' and ops[2]['size'] == 2
    # 2-unit packet opened by 4X?d without a named pairing: context rule bz.s (P4).
    ops = json.loads(r2('e asm.cpu=usip;wx 44cd8207@0x4d46;aoj 1@0x4d46', 0x8000)[0])
    assert ops[0]['opcode'] == 'bz.s r2, 0x00004d78' and ops[0]['type'] == 'cjmp' and ops[0]['jump'] == 0x4d78
    # The maintainer's original call vector at the end of the buffer: a truncated packet still yields the call
    # (aoj would see r2's 0xff padding as a closing unit, so use the disassembly path, which gets the exact bytes).
    text = '\n'.join(r2('e asm.cpu=usip;wx 000e78aa@0x7ffc;pD 4@0x7ffc', 0x8000))
    assert 'call 0x000088a6' in text
    # save/restore/ret 16-bit forms and an unknown unit.
    ops = json.loads(r2('e asm.cpu=usip;wx 5f059ef9ff45ffff;aoj 4', 0x8000)[0])
    assert [o['opcode'] for o in ops] == ['save w=0x0', 'ret', 'restore w=0x4', '.fill 0xffff']
    assert [o['type'] for o in ops] == ['rpush', 'ret', 'pop', 'unk'] and [o['size'] for o in ops] == [2, 2, 2, 2]
    # Function analysis: the delay slot stays in the branch's basic block.
    bbs = json.loads(r2('e asm.cpu=usip;wx 7e0cc00c5c3907f0541c805c07f0141cc06c3e015000400ac000def9@0x40c;af@0x40c;afbj@0x40c', 0x8000)[0])
    bb = {b['addr']: b for b in bbs}
    assert bb[0x410]['size'] == 8 and bb[0x410]['jump'] == 0x41e and bb[0x40c]['jump'] == 0x418 and bb[0x40c]['fail'] == 0x410
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
