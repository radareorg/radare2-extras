#!/usr/bin/env python3
"""Exercise the built plugins inside radare2: disassembly, pseudo syntax, analysis, ESIL emulation."""
import json
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
R2 = os.environ.get('R2', 'r2')
ext = subprocess.check_output([R2, '-H', 'R2_LIBEXT'], text=True).strip()
PLUGIN = ROOT / ('arch_mn103.' + ext)
ASM_PLUGIN = ROOT / ('asm_mn103.' + ext)


def r2(commands, size=1024):
    setup = 'e scr.color=0;L %s;L %s;e asm.arch=mn103;' % (PLUGIN, ASM_PLUGIN)
    proc = subprocess.run([R2, '-NN', '-q', '-c', setup + commands + ';q', 'malloc://%d' % size],
                          capture_output=True, text=True, check=True)
    return proc.stdout.strip().splitlines()


def first_json(lines):
    for line in lines:
        if line.startswith('[') or line.startswith('{'):
            return json.loads(line)
    raise AssertionError(lines)


def disassembly():
    # the reset vector of an AM33 camera firmware
    text = r2('wx fafcfff0cbcbf8fefcfcff8c000000f8fe04fcde000010988f10f81e08dd710600000000f0f4;pD 0x32')
    joined = '\n'.join(text)
    for expected in ('and 0xf0ff, psw', 'nop', 'add -0x4, sp', 'calls 0x00000095', 'add 0x4, sp',
                     'mov 0x98100000, a2', 'mov 0x10, d3', 'mov d3, (0x8, a2)',
                     'call 0x0000068e, [], 0x0', 'jmp (a0)'):
        assert expected in joined, (expected, joined)
    assert r2('e asm.parser')[0] == 'mn103'
    pseudo = '\n'.join(r2('e asm.pseudo=true;wx 8f10f81e08f26c1fdfc008c004;pD 13'))
    for expected in ('d3 = 0x10', '[a2 + 0x8] = d3', 'd0 = mdr:d0 / d3', 'd3 = (uint16_t) d3',
                     'return (restore [d2,d3], frame 0x8)', 'if (<) goto 0x0000000f'):
        assert expected in pseudo, (expected, pseudo)
    # cpu selection: the base MN10300 table keeps the udf placeholders
    assert 'mulq d3, d0' in '\n'.join(r2('wx f60c;pD 2'))
    assert 'udf00 d3, d0' in '\n'.join(r2('e asm.cpu=mn10300;wx f60c;pD 2'))
    assert 'invalid' in '\n'.join(r2('wx f7ff0000;pD 1'))


def analysis():
    ops = first_json(r2('wx dd17040000c02c8f10f26cdfc008;aoj 4'))
    assert [o['size'] for o in ops] == [7, 2, 2, 3]
    assert [o['type'] for o in ops] == ['call', 'mov', 'div', 'ret']
    assert ops[0]['jump'] == 0x417 and ops[0]['fail'] == 7 and ops[0]['stackptr'] == 4 + 8 + 0x2c
    assert ops[3]['stackptr'] in (-20, (1 << 64) - 20)  # the json prints st64 as unsigned
    assert ops[2]['opex']['operands'] == [dict(type='reg', value='d3'), dict(type='reg', value='d0')]
    ops = first_json(r2('wx 5a1ef81e08387080;aoj 3'))
    assert ops[0]['type'] == 'load' and ops[0]['stack'] == 'get' and ops[0]['disp'] == 0x1e
    assert ops[1]['type'] == 'store' and ops[1]['ireg'] == 'a2' and ops[1]['disp'] == 8
    assert ops[2]['type'] == 'load' and ops[2]['ptr'] == 0x8070 and ops[2]['refptr'] == 2
    assert ops[2]['opex']['operands'][0] == dict(type='mem', address=0x8070, size=2)
    # a leaf function: calls target, branches and a return
    bbs = first_json(r2('wx a005c0068003f0fc8001f0fc;af;afbj', 64))
    assert sorted(b['addr'] for b in bbs) == [0, 4, 8]
    fn = first_json(r2('wx a005c0068003f0fc8001f0fc;af;afij', 64))[0]
    assert fn['size'] == 12


def emulation():
    # 16 * 3 / 16 through mulq, ext and div; then cmp 5,d0 sets N and C and blt is taken
    regs = first_json(r2('wx 8f108003f60cf2d0f26ca005c004;aei;aeim;6aes;arj'))
    assert regs['d0'] == 3 and regs['mdr'] == 0 and regs['psw'] & 0xf == 0x6, regs
    assert first_json(r2('wx 8f108003f60cf2d0f26ca005c004;aei;aeim;7aes;arj'))['pc'] == 0x10
    # signed division with a negative dividend: -7 / 2 = -3 remainder -1
    regs = first_json(r2('wx 80f98502f2d0f264;aei;aeim;4aes;arj'))
    assert regs['d0'] == 0xfffffffd and regs['mdr'] == 0xffffffff, regs
    # call pushes the return address and the register list, ret restores them
    regs = first_json(r2('wx cd2000c008;wx 8a07dfc008 @ 0x20;aei;aeim;ar sp=0x100;ar d2=0x11;ar d3=0x22;aes;arj', 512))
    assert regs['sp'] == 0x100 - 4 - 8 - 8 and regs['pc'] == 0x20 and regs['mdr'] == 5
    regs = first_json(r2('wx cd2000c008;wx 8a07dfc008 @ 0x20;aei;aeim;ar sp=0x100;ar d2=0x11;ar d3=0x22;3aes;arj', 512))
    assert regs['sp'] == 0x100 and regs['pc'] == 5 and regs['d2'] == 0x11 and regs['d3'] == 0x22
    # movm push keeps the old a3 at the lowest slot; stack-relative store/load; unsigned halfword extension; pop
    regs = first_json(r2('wx cf308f814e1e5a1e1fce30;aei;aeim;ar sp=0x200;ar a2=0xaa;6aes;arj'))
    assert regs['d2'] == 0xffffff81 and regs['d3'] == 0xff81 and regs['a2'] == 0xaa and regs['sp'] == 0x200
    words = r2('wx cf30;aei;aeim;ar sp=0x200;ar a2=0xaa;aes;pxw 8 @ 0x1f8')
    assert '0x00000200 0x000000aa' in '\n'.join(words)
    # absolute store, btst/bset on memory bytes, movhu from an absolute address
    out = r2('wx 8081017080fe027080000002fe0070800000f0387080;aei;aeim;2aes;aes;ar psw;aes;aes;ar d0;pxw 4 @ 0x8070', 65536)
    assert out[0] == '0x00000001' and out[1] == '0x0000fff1' and '0xfffffff1' in out[2]
    # setlb / lne loop: three iterations of inc d0 until d0 == 3
    regs = first_json(r2('wx 8000db40a003d9;aei;aeim;11aes;arj'))
    assert regs['d0'] == 3 and regs['pc'] == 7, regs


def main():
    disassembly()
    analysis()
    emulation()
    print('mn103 plugin tests passed')


if __name__ == '__main__':
    main()
