#!/usr/bin/env python3
"""Exercise cpu=scq16 (SCQ16, MD32 family, byte-granular packet variant) inside r2 with loose bytes only: disassembly of
stand-alone units, packets `{ A ‖ B }`, vector ops and bundles; analysis (types, targets relative to the packet start,
delay slots counted in instructions, fall-through after the slots, loop references); opex; ESIL (parallel packet
semantics, delayed call via SETJT/SETD, loads/stores and post-increments, sign/zero extension, division, bit fields,
the VU scalar ports, vop); the newer forms (cmov.ge / cmov.eq with a register / the provisional cmov.*?, mv 67 c8, bset/btst
rd, rd, #pos, lbu.post with 5-bit registers and the 23 page with a signed post-increment, and #0x3fff, the 6-byte and #imm16, ctz?/clb?,
vcfg4c? #0xc, ld46?, the established vector names v.move.mv / v.mem.ld / v.mem.st, lbu? off(sp), halt and sys41 without effect),
j.d1 decided by its target, `.d2` across two `aes` steps, negative stack offsets; the newest forms (ctz, the provisional sqr? / sra? /
vrd?, op41.fld with three registers, the provisional and? masks, lw.post of 2 bytes with a 4-bit destination, the signed post-increment
of the 6e page, the .post templates writing rd last) and the public model of the VU (v.mem.ld / v.mem.st / v.move.mv on vr0-vr31 with
the pointers vp0-vp7 and the counts va0-va7); the pseudo parser.  No firmware is needed."""
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
R2 = os.environ.get('R2', 'r2')
ext = subprocess.check_output([R2, '-H', 'R2_LIBEXT'], text=True).strip()
PLUGIN = ROOT / ('arch_md32.' + ext)
ASM_PLUGIN = ROOT / ('asm_md32.' + ext)
failures = 0


def r2(commands, size=0x8000):
    # asm.cpu before asm.arch: the register profile is taken when the arch session is created
    setup = 'e scr.color=0;L %s;L %s;e asm.cpu=scq16;e asm.arch=md32;e cfg.bigendian=true;' % (PLUGIN, ASM_PLUGIN)
    proc = subprocess.run([R2, '-NN', '-q', '-c', setup + commands + ';q', 'malloc://%d' % size], capture_output=True, text=True, check=True)
    return [l for l in proc.stdout.strip().splitlines() if not l.startswith(('WARN', 'INFO', 'ERROR'))]


def check(cond, msg):
    global failures
    print(('ok   ' if cond else 'FAIL ') + msg)
    if not cond:
        failures += 1


# 1. disassembly: (bytes, size, text) — targets are absolute (code at 0x1000)
DISASM = [
    ('2005', 2, 'ret'), ('2006', 2, 'ret.d1'), ('2007', 2, 'ret.d2'), ('1402', 2, 'addsp     sp, #0x8'), ('207e', 2, 'sw.lr     lr, -0x8(sp)'),
    ('157f', 2, 'lw.lr     lr, -0x4(sp)'), ('3084', 2, 'lw        r5, 0x4(r1)'), ('3a20', 2, 'sw.post   r1, [r3] -= 0x10'), ('2180', 2, 'lw.post   r1, [r1] += 4'),
    ('208a', 2, 'lbu       r3, [r2]'), ('2240', 2, 'lbu.post  r1, [r1] += 1'), ('1600', 2, 'lhu       r1, [r1]'), ('2c10', 2, 'sw.sp     r1, -0xfc(sp)'),
    ('2810', 2, 'lw.sp     r1, -0xfc(sp)'), ('0566', 2, 'xtd       r7, r5, #16'), ('0540', 2, 'xtd       r1, r1, #16'), ('0000', 2, 'and       r1, r1, #0x1'),
    ('0e12', 2, 'mul       r3, r2'), ('0f12', 2, 'max       r3, r2'), ('0c12', 2, 'or        r3, r2'), ('0d56', 2, 'and       r7, r6'), ('0b50', 2, 'sub       r1, r6'),
    ('0a12', 2, 'add       r3, r2'), ('0912', 2, 'sra       r3, r3, #1'), ('0811', 2, 'sll       r2, r2, #1'), ('0718', 2, 'mv        r9, #-15'),
    ('0445', 2, 'add       r6, r1, #1'), ('0288', 2, 'sll       r1, r2, #2'), ('2640', 2, 'beqz      r1, #0, 0x00001004'), ('3f02', 2, 'j8        0x00001002'),
    ('3e00', 2, 'j         . (trap)'), ('1810', 2, 'vget      r1, vu[1]'), ('1c10', 2, 'vbcast    v1, r1'), ('1f20', 2, 'vset.a    A2, r1'), ('1fa0', 2, 'vmem.set  p2, r1'),
    ('6a0010', 3, 'j16       0x00001010'), ('6b36ee', 3, 'jal11     0x00000eee'), ('6fecc5', 3, 'jr.d2     r5'), ('680010', 3, 'beqz8     r16, #0, 0x00001000'),
    ('690010', 3, 'beqz8.d1  r16, #0, 0x00001000'), ('6f0601', 3, 'sw.post   r1, [r16] += 0x4'), ('67b068', 3, 'and       r8, r3, #0x8000'), ('6b4c74', 3, 'vrd?      r20, vb3[3]'),
    ('6e4020', 3, 'sw        r0, 0x0(r1)'), ('6fe020', 3, 'sb        r0, [r1]'), ('6584c1', 3, 'add       r1, r6, r1 << 2'), ('6c0020', 3, 'lw        r0, 0x0(r1)'),
    ('650020', 3, 'add       r0, r1, r0 << 1'), ('67cc20', 3, 'mv        r0, r1'), ('67d820', 3, 'add       r0, r0, r1'), ('67e020', 3, 'and       r0, r0, r1'),
    ('6d0020', 3, 'lbu       r0, 0x0(r1)'),
    ('56400010', 4, 'jal.d1    0x00001010'), ('41e01904', 4, 'add       r4, r8, r6'), ('5c800a21', 4, 'beq       #81, r1, 0x00001000'), ('41f00140', 4, 'div       a0, r10, r0'),
    ('48080001', 4, 'mv        r1, #0x4000'), ('437acda0', 4, 'vpmem?    p0, #0x2c, m13  (b1 7a)'), ('41b51461', 4, 'fxts      r1, r3, #5, #10'),
    ('42141ce6', 4, 'cmov.ge   r6, r7, #0, r8'), ('40078000', 4, 'vbcast.i  v0, #-0x400  (sub 000)'), ('44000020', 4, 'lbu       r0, 0x0(r1)'),
    ('47c00020', 4, 'sw        r0, [r1] += 0'), ('42600000', 4, 'cmov.lt   r0, r0, r0, r0'), ('41aaa8c1', 4, 'fxtu      r1, r6, #10, #21'), ('4190410f', 4, 'fup       r15, r8, #16, #0'),
    ('55d01b03', 4, 'do.d2     r3, end=0x0000101b (F=27)'), ('5e800000', 4, 'sys       #0x0 (0x0000)'), ('41f38400', 4, 'clz       r0, r0'), ('41f70008', 4, 'addsp     sp, #0x8'),
    ('40200020', 4, 'mul       r0, r0, #1'), ('4a000020', 4, 'add       r0, r1, #0x0'), ('4b000020', 4, 'and       r0, r1, #0x0'), ('c0000001', 4, 'v.const.movi? op9=0x001 A0 B0 F0,F0,F0'),
    ('889026e4', 4, '{ mv        r1, r3 ‖ beqz      r5, #0, 0x0000100e }'), ('90c821e3', 4, '{ lw.post   r1, [r2] += 4 ‖ lw.post   r4, [r7] += 4 }'),
    ('903fe90543', 5, '{ sw.lr     lr, -0x4(sp) ‖ beqz8.d1  r3, #0, 0x0000102a }'), ('a40003d19125', 6, '{ mv        r3, #0x3d ‖ mv        r6, r3 }'),
    ('a17a0e7350813001', 8, '{ cmov.ne   r6, r7, #0, r8 ‖ ble.d1    #0, r1, 0x00001013 }'),
    ('f000000285288a02', 8, 'vbundle   v.mem.ld op9=0x00a A0 B0 F0,F0,F0 ‖ add r2, r6 ‖ add r3, r1'),
    # the whole page 42 (cmov.ge, cmov.eq with a register, the provisional cmov.leu?/ltu?/lt?/le?, the remaining sel? codes),
    # the 67 page (mv, bset/btst rd, rd, #pos), lbu.post? with +3, addsp 14 8x, halt, sys41 (no modelled effect), lbu? off(sp),
    # the 4-byte beq rA, rB of 5c 40-6f and j.d1 56 0x-3x decided by its target (0x1000 - 0x32 = 0xfce)
    ('4213b0c1', 4, 'cmov.ge   r1, r6, #5, r7'), ('42c2b5c8', 4, 'cmov.eq   r8, r14, r13, r5'), ('42308864', 4, 'cmov.leu? r4, r3, r2, r1'),
    ('42b0a464', 4, 'cmov.ltu? r4, r3, #9, r1'), ('4270a464', 4, 'cmov.lt?  r4, #2, r3, r1'), ('4240a464', 4, 'cmov.le?  r4, #9, r3, r1'),
    ('42008864', 4, 'sel?      r4, r3, r2, r1  (q0 c0)'), ('42e08864', 4, 'sel?      r4, r3, r2, r1  (q3 c2)'), ('42508864', 4, 'sel?      r4, r3, #2, r1  (q1 c1)'),
    ('42808864', 4, 'sel?      r4, r3, x2, r1  (q2 c0)'), ('42d0a464', 4, 'cmov.eq   r4, r3, #2, r1'),
    ('67c875', 3, 'mv        r21, r3'), ('67f409', 3, 'bset      r9, r9, #0'), ('67f865', 3, 'btst      r5, r5, #3'), ('67fb41', 3, 'op67      r1, r26  (x=0x3e)'),
    ('22c5', 2, 'lbu.post? r6, [r1] += 3'), ('148a', 2, 'addsp     sp, #0x228'), ('5eb00000', 4, 'halt'),
    ('41f3a000', 4, 'sys41     sub 0x28'), ('6f2041', 3, 'lbu?      r1, -0xfd(sp)'), ('5c68a8e6', 4, 'beq       r7, r6, 0x00000a2a'),
    ('563fffce', 4, 'j.d1      0x00000fce'), ('56200000', 2, '.b2       56 20'), ('88904213b0c1', 6, '{ mv        r1, r3 ‖ cmov.ge   r1, r6, #5, r7 }'),
    # lbu.post with 5-bit registers (6e q2 h0), the 23 page as lbu.post rd, [rb] += simm3 (-4..-1; the 22 page carries +1..+3),
    # and #0x3fff (67 a4-a7), the 6-byte and rd, rs, #imm16 (74 sub 1; sub 3 stays open), the provisional ctz?/clb? next to clz,
    # vcfg4c? v(17+2k), rs, #0xc (hypothetical ESIL p_k <- rs), ld46? with a post-increment, the established vector names
    # v.move.mv / v.mem.ld / v.mem.st (no ?) next to the provisional v.alu3.acc.add? / difsc?, a bundle and a vector head with them
    ('6e850d', 3, 'lbu.post  r13, [r8] += 0x1'), ('23fa', 2, 'lbu.post  r3, [r8] += -1'), ('2302', 2, 'lbu.post  r3, [r1] += -4'), ('2285', 2, 'lbu.post  r6, [r1] += 2'),
    ('67a468', 3, 'and       r8, r3, #0x3fff'), ('67ac68', 3, 'and?      r8, r3, #0xfc00?'), ('740004500000', 6, 'and       r0, r0, #0x1400'),
    ('740008500000', 6, 'or        r0, r0, #0x1400'), ('74000c500000', 6, 'alu74?    r0, r0, #0x1400  (sub 3)'), ('41f38800', 4, 'ctz       r0, r0'),
    ('41f38c00', 4, 'sqr?      r0, r0'), ('4c003231', 4, 'vcfg4c?   v17, r17, #0xc  (q0 s0)'), ('4600a020', 4, 'ld46?     r0, [r1] += 0x28'),
    ('c0000109', 4, 'v.move.mv op9=0x109 A0 B0 F0,F0,F0'), ('c0000002', 4, 'v.mem.ld  op9=0x002 A0 B0 F0,F0,F0'), ('c0000003', 4, 'v.mem.st  op9=0x003 A0 B0 F0,F0,F0'),
    ('c000000e', 4, 'v.alu3.acc.add? op9=0x00e A0 B0 F0,F0,F0'), ('c000002e', 4, 'v.alu3.acc.difsc? op9=0x02e A0 B0 F0,F0,F0'),
    ('e00001092005', 6, '{ v.mem.ld  op9=0x012 A0 B0 F0,F0,F1 ‖ ret }'), ('88906e850d', 5, '{ mv        r1, r3 ‖ lbu.post  r13, [r8] += 0x1 }'),
    # ctz (41 f3 0x22, established) next to the provisional sqr? (0x23), the provisional sra? rd, rd, #pos (67 fc-fd) and
    # vrd? rd, vb1[x] (1a xy), op41.fld rd, rs, rt, #pos (w[14:10] is a register), the provisional masks and? #0xf000? (67 98-9b, and the
    # 2-byte 00/01 with k = 6) / #0xc000? (67 b4-b7), lw.post of 2 bytes with a 4-bit destination (21 aa = r11), the signed 3-bit
    # post-increment of the 6e page (x = 4..7 -> -4..-1 units), vector ops with non-zero fields, a vector head and B slots with the newest forms
    ('67fc75', 3, 'sra?      r21, r21, #3'), ('67fd75', 3, 'sra?      r21, r21, #11'), ('1a76', 2, 'vrd?      r7, vb1[7]'), ('1a00', 2, 'vrd?      r1, vb1[0]'),
    ('418c0d27', 4, 'op41.fld  r7, r9, r3, #24'), ('679868', 3, 'and?      r8, r3, #0xf000?'), ('67b468', 3, 'and?      r8, r3, #0xc000?'), ('018a', 2, 'and?      r3, r2, #0xf000?'),
    ('21aa', 2, 'lw.post   r11, [r3] += 4'), ('21a1', 2, 'lw.post   r2, [r3] += 4'), ('6ed063', 3, 'lw.post   r3, [r3] += -0x10'), ('6ef463', 3, 'sh.post   r3, [r3] += -0x6'),
    ('6ee463', 3, 'sh.post   r3, [r3] += 0x2'), ('0912', 2, 'sra       r3, r3, #1'), ('c8204002', 4, 'v.mem.ld  op9=0x002 A2 B0 F4,F1,F0'), ('c8006003', 4, 'v.mem.st  op9=0x003 A2 B0 F0,F1,F16'),
    ('c0280109', 4, 'v.move.mv op9=0x109 A0 B0 F5,F0,F0'), ('e00807092005', 6, '{ v.mem.ld  op9=0x012 A0 B0 F2,F0,F7 ‖ ret }'), ('88901a76', 4, '{ mv        r1, r3 ‖ vrd?      r7, vb1[7] }'),
    ('889021aa', 4, '{ mv        r1, r3 ‖ lw.post   r11, [r3] += 4 }'), ('889041f38800', 6, '{ mv        r1, r3 ‖ ctz       r0, r0 }'),
]
for hx, L, exp in DISASM:
    out = r2('wx %s @ 0x1000;pi 1 @ 0x1000;ao 1 @ 0x1000~size' % hx)
    text = out[0] if out else ''
    check(text == exp and any(l.strip() == 'size: %d' % L for l in out), '%-18s -> %s' % (hx, text))

# 2. analysis
ops = json.loads(r2('wx 56400010 1402 207e 2005 @ 0x2000;aoj 4 @ 0x2000')[0])
check([o['size'] for o in ops] == [4, 2, 2, 2], 'sizes jal.d1/addsp/sw.lr/ret')
check(ops[0]['type'] == 'call' and ops[0]['jump'] == 0x2010 and ops[0].get('delay') == 1 and ops[0]['fail'] == 0x2006, 'jal.d1: call, jump, delay 1, fail after the slot')
check(ops[1]['type'] == 'add' and ops[1].get('stackptr') in (-8, 2**64 - 8), 'addsp sp,#8: stackptr -8')
check(ops[2]['type'] == 'store' and ops[2].get('stack') == 'set' and ops[2].get('ireg') == 'sp', 'sw.lr: store on the stack')
check(ops[3]['type'] == 'ret', 'ret')
ops = json.loads(r2('wx 5c800a21 2640 3f02 @ 0x3000;aoj 3 @ 0x3000')[0])
check(ops[0]['type'] == 'cjmp' and ops[0]['cond'] == 'eq' and ops[0]['jump'] == 0x3000 and ops[0]['fail'] == 0x3004, 'beq #imm, rn: cjmp eq, jump, fail')
check(ops[2]['type'] == 'jmp' and ops[2]['jump'] == 0x3008, 'j8: jump')
ops = json.loads(r2('wx 889026e4 @ 0x4000;aoj 1 @ 0x4000')[0])
check(ops[0]['type'] == 'cjmp' and ops[0]['jump'] == 0x400e and ops[0]['opex']['shape'] == 'packet' and ops[0]['opex']['parallel'] is True, 'packet {mv ‖ beqz}: cjmp with base = packet start, opex parallel')
check(ops[0]['opex']['units'][0]['transformed'] == '11 20' and ops[0]['opex']['units'][0]['form'] == 'mv', "opex: A' = 11 20 (mv r1,r3)")
ops = json.loads(r2('wx 55d01b03 @ 0x5000;aoj 1 @ 0x5000')[0])
check(ops[0].get('ptr') == 0x501b and ops[0].get('delay') == 2 and ops[0].get('reg') == 'r3', 'do.d2 r3: loop end reference, delay 2, count register')
ops = json.loads(r2('wx c0000001 @ 0x7000;aoj 1 @ 0x7000')[0])
check(ops[0]['opex']['units'][0]['vclass'] == 'const' and ops[0]['opex']['units'][0]['provisional'] is True and ops[0]['opex']['units'][0]['named'] is False, 'vector op: class const, provisional, unnamed')

# 2b. j.d1 by target (in a B slot the target is measured from the packet start), the 4-byte beq of 5c 40-6f, cmov types
ops = json.loads(r2('wx 563fffce @ 0x1036;aoj 1 @ 0x1036')[0])
check(ops[0]['size'] == 4 and ops[0]['type'] == 'jmp' and ops[0]['jump'] == 0x1004 and ops[0].get('delay') == 1, 'j.d1 56 3f: 4 bytes, jump by target, delay 1')
out = r2('wx 8890563fffce @ 0x1036;pi 1 @ 0x1036;ao 1 @ 0x1036~size')
check(out[0] == '{ mv        r1, r3 ‖ j.d1      0x00001004 }' and any(l.strip() == 'size: 6' for l in out), 'j.d1 in a B slot: target from the packet start')
ops = json.loads(r2('wx 5c68a8e6 2005 @ 0x1000;aoj 2 @ 0x1000')[0])
check(ops[0]['size'] == 4 and ops[0]['type'] == 'cjmp' and ops[0]['cond'] == 'eq' and ops[1]['type'] == 'ret', '5c 68 a8 e6: a 4-byte beq rA, rB')
ops = json.loads(r2('wx 4213b0c1 42308864 23fa 5eb00000 41f3a000 @ 0x5000;aoj 5 @ 0x5000')[0])
check(ops[0]['type'] == 'cmov' and ops[0]['opex']['units'][0]['form'] == 'cmov.ge' and ops[0]['opex']['units'][0]['named'] is True, 'cmov.ge: cmov, named form')
check(ops[1]['type'] == 'cmov' and ops[1]['opex']['units'][0]['provisional'] is True and ops[1]['opex']['units'][0]['named'] is False, 'cmov.leu?: provisional')
check(ops[2]['type'] == 'load' and ops[2].get('refptr') == 1 and ops[2].get('ireg') == 'r8' and ops[2]['opex']['units'][0]['named'] is True, 'lbu.post rd, [rb] += -1 (23 xx): byte load through r8, named')
check(ops[3]['type'] == 'trap' and ops[4]['type'] == 'swi', 'halt = trap, sys41 = swi')
# 2c. the established vector names are named operations, the provisional ones carry the ? flag; and #imm16 of 6 bytes; ctz?
ops = json.loads(r2('wx c0000002 c000000e f000000285288a02 740004500000 41f38800 @ 0x5100;aoj 5 @ 0x5100')[0])
u = ops[0]['opex']['units'][0]
check(u['mnemonic'] == 'v.mem.ld' and u['named'] is True and 'provisional' not in u and u.get('vname') == 'ld', 'v.mem.ld: an established vector name is a named operation')
u = ops[1]['opex']['units'][0]
check(u['mnemonic'] == 'v.alu3.acc.add?' and u['named'] is False and u['provisional'] is True, 'v.alu3.acc.add?: provisional vector name')
u = ops[2]['opex']['units'][0]
check(ops[2]['opex']['shape'] == 'bundle' and u['named'] is True and u.get('vname') == 'ld', 'bundle with v.mem.ld: named')
check(ops[3]['size'] == 6 and ops[3]['type'] == 'and', 'and rd, rs, #imm16 (74 sub 1): 6 bytes, and')
check(ops[4]['opex']['units'][0]['mnemonic'] == 'ctz' and ops[4]['opex']['units'][0]['named'] is True, 'ctz: an established operation')

# 2d. ctz is an established name (no ?), sqr? / sra? / vrd? are provisional, op41.fld carries three registers, lw.post of 2 bytes
# has a 4-bit destination
ops = json.loads(r2('wx 41f38800 41f38c00 67fc75 1a76 418c0d27 21aa @ 0x5200;aoj 6 @ 0x5200')[0])
u = [o['opex']['units'][0] for o in ops]
check(u[0]['mnemonic'] == 'ctz' and u[0]['named'] is True and 'provisional' not in u[0], 'ctz: an established operation name')
check(u[1]['mnemonic'] == 'sqr?' and u[1]['provisional'] is True and u[1]['named'] is False, 'sqr?: provisional')
check(ops[2]['type'] == 'sar' and u[2]['mnemonic'] == 'sra?' and u[2]['provisional'] is True, 'sra? rd, rd, #pos (67 fc): sar, provisional')
check(ops[3]['type'] == 'mov' and u[3]['mnemonic'] == 'vrd?' and u[3]['provisional'] is True, 'vrd? rd, vb1[x] (1a): mov, provisional')
check(u[4]['form'] == 'op41.fld' and u[4]['named'] is False and [o['name'] for o in u[4]['operands']][:3] == ['rd', 'rs', 'rt'], 'op41.fld rd, rs, rt, #pos: three registers, unnamed')
check(ops[5]['type'] == 'load' and u[5]['operands'][0]['value'] == 'r11' and ops[5].get('ireg') == 'r3', 'lw.post r11, [r3] += 4: 4-bit destination, base r3')

# 3. ESIL
regs = json.loads(r2('wx a40003d19125 @ 0x6000;aei;ar r3=7;ar r6=0;s 0x6000;aeip;aes;arj')[0])
check(regs['r3'] == 0x3d and regs['r6'] == 7, 'parallel packet {mv r3,#0x3d ‖ mv r6,r3}: r6 gets the old r3')
regs = json.loads(r2('wx 90c821e3 @ 0x6000;wx 11223344 @ 0x100;wx aabbccdd @ 0x200;aei;ar r2=0x100;ar r7=0x200;s 0x6000;aeip;aes;arj')[0])
check(regs['r1'] == 0x11223344 and regs['r4'] == 0xaabbccdd and regs['r2'] == 0x104 and regs['r7'] == 0x204, 'lw.post ‖ lw.post: loads and post-increments')
regs = json.loads(r2('wx 56400010 1402 @ 0x2000;aei;aeim;ar sp=0x1800;s 0x2000;aeip;aes;arj')[0])
check(regs['pc'] == 0x2010 and regs['sp'] == 0x1808 and regs['lr'] == 0x2006, 'jal.d1 + slot: the slot runs before the call (SETJT/SETD)')
regs = json.loads(r2('wx 3a20 @ 0x6000;aei;ar r1=0x12345678;ar r3=0x300;s 0x6000;aeip;aes;arj')[0])
check(regs['r3'] == 0x2f0, 'sw.post -0x10: base decremented')
regs = json.loads(r2('wx 0566 @ 0x6000;aei;ar r5=0x8123;s 0x6000;aeip;aes;arj')[0])
check(regs['r7'] == 0xffff8123, 'xtd #16: sign extension')
regs = json.loads(r2('wx 41f00140 @ 0x6000;aei;ar r10=100;ar r0=7;s 0x6000;aeip;aes;arj')[0])
check(regs['a0l'] == 14 and regs['a0h'] == 2, 'div: quotient in a0l, remainder in a0h')
regs = json.loads(r2('wx 41aaa8c1 @ 0x6000;aei;ar r6=0xffc00000;s 0x6000;aeip;aes;arj')[0])
check(regs['r1'] == 0x3fe, 'fxtu r1, r6, #10, #21: bit field')
regs = json.loads(r2('wx 5b808a21 @ 0x6000;aei;ar r1=0xffffffff;s 0x6000;aeip;aes;arj')[0])
check(regs['pc'] == 0x6008, 'bltu #81, r1(-1), +8: unsigned compare taken')
regs = json.loads(r2('wx 5a800a21 @ 0x6000;aei;ar r1=0xffffffff;s 0x6000;aeip;aes;arj')[0])
check(regs['pc'] == 0x6004, 'blt #0, r1(-1): signed compare not taken')
regs = json.loads(r2('wx 1810 6b4c74 6b7407 @ 0x3000;aei;ar vu1=0x77;ar vb3_3=0x99;ar r7=0x55;s 0x3000;aeip;aes;aes;aes;arj')[0])
check(regs['r1'] == 0x77 and regs['r20'] == 0x99 and regs['vb5_0'] == 0x55, 'VU scalar ports as registers (vget, vrd?, vwr?)')
out = r2('wx c0000001 2005 @ 0x3000;ao 1 @ 0x3000~esil;aei;s 0x3000;aeip;aes;ar pc')
check(any('vop' in l for l in out) and out[-1].strip() == '0x00003004', 'vector op: ESIL vop, aes steps over it')

# 3b. the new semantics, negative stack offsets (ESIL addresses cut to 32 bits), halt/sys41 without effect, .d2 across two aes steps
regs = json.loads(r2('wx 4213b0c1 @ 0x3000;aei;ar r6=5;ar r7=4;ar r1=9;s 0x3000;aeip;aes;arj')[0])
check(regs['r1'] == 4, 'cmov.ge r1, r6, #5, r7 with r6 = 5: taken')
regs = json.loads(r2('wx 4213b0c1 @ 0x3000;aei;ar r6=0xfffffffc;ar r7=4;ar r1=9;s 0x3000;aeip;aes;arj')[0])
check(regs['r1'] == 9, 'cmov.ge with r6 = -4 (signed): not taken')
regs = json.loads(r2('wx 42c2b5c8 @ 0x3000;aei;ar r14=0x4000;ar r13=0x4000;ar r5=0x77;ar r8=1;s 0x3000;aeip;aes;arj')[0])
check(regs['r8'] == 0x77, 'cmov.eq r8, r14, r13, r5 (register form): taken')
regs = json.loads(r2('wx 42308864 @ 0x3000;aei;ar r3=0x100;ar r2=0x100;ar r1=0xaa;ar r4=0;s 0x3000;aeip;aes;arj')[0])
check(regs['r4'] == 0xaa, 'cmov.leu? r4, r3, r2, r1 with r3 == r2: taken')
regs = json.loads(r2('wx 42b0a464 @ 0x3000;aei;ar r3=9;ar r1=0xbb;ar r4=0;s 0x3000;aeip;aes;arj')[0])
check(regs['r4'] == 0, 'cmov.ltu? r4, r3, #9, r1 with r3 = 9: not taken (strict)')
regs = json.loads(r2('wx 4270a464 @ 0x3000;aei;ar r3=0xffffffff;ar r1=0xcc;ar r4=0;s 0x3000;aeip;aes;arj')[0])
check(regs['r4'] == 0, 'cmov.lt? r4, #2, r3, r1 with r3 = -1: not taken (signed)')
regs = json.loads(r2('wx 4240a464 @ 0x3000;aei;ar r3=9;ar r1=0xdd;ar r4=0;s 0x3000;aeip;aes;arj')[0])
check(regs['r4'] == 0xdd, 'cmov.le? r4, #9, r3, r1 with r3 = 9: taken')
regs = json.loads(r2('wx 67c875 67f409 67f865 @ 0x3000;aei;ar r3=0x12345678;ar r9=0x100;ar r5=8;s 0x3000;aeip;aes;aes;aes;arj')[0])
check(regs['r21'] == 0x12345678 and regs['r9'] == 0x101 and regs['r5'] == 1, 'mv r21, r3 (67 c8); bset r9, r9, #0; btst r5, r5, #3')
regs = json.loads(r2('wx 23fa 22c5 @ 0x3000;wx 807f @ 0x400;aei;ar r8=0x400;ar r1=0x401;s 0x3000;aeip;aes;aes;arj')[0])
check(regs['r3'] == 0x80 and regs['r8'] == 0x3ff and regs['r6'] == 0x7f and regs['r1'] == 0x404, 'lbu.post r3, [r8] += -1 (zero-extended byte, post-decrement); lbu.post? r6, [r1] += 3')
regs = json.loads(r2('wx 207e 157e 6f2041 2c10 2810 @ 0x3000;wx 80 @ 0x503;aei;ar sp=0x600;ar lr=0x1234;s 0x3000;aeip;aes;ar lr=0;aes;aes;ar r1=0x55;aes;ar r1=0;aes;arj')[0])
check(regs['lr'] == 0x1234 and regs['r1'] == 0x55, 'sw.lr / lw.lr -0x8(sp), lbu? -0xfd(sp), sw.sp / lw.sp -0xfc(sp): negative offsets reach the 32-bit frame')
regs = json.loads(r2('wx 5eb00000 41f3a000 2005 @ 0x3000;aei;ar lr=0x4000;s 0x3000;aeip;aes;aes;aes;arj')[0])
check(regs['pc'] == 0x4000, 'halt and sys41: no effect, aes steps over them')
regs = json.loads(r2('wx 2007 1402 0445 2005 @ 0x2000;aei;aeim;ar sp=0x1800;ar r1=10;ar lr=0x3000;s 0x2000;aeip;aes;arj')[0])
check(regs['pc'] == 0x2004 and regs['sp'] == 0x1808 and regs['r6'] == 0, 'ret.d2, first aes step: the first slot runs, no jump yet')
regs = json.loads(r2('wx 2007 1402 0445 2005 @ 0x2000;aei;aeim;ar sp=0x1800;ar r1=10;ar lr=0x3000;s 0x2000;aeip;aes;aes;arj')[0])
check(regs['pc'] == 0x3000 and regs['r6'] == 11, 'ret.d2, second aes step: the second slot runs and the return is taken')
regs = json.loads(r2('wx 6fecc5 a40003d19125 0445 2005 @ 0x2000;aei;aeim;ar r1=10;ar r3=7;ar r5=0x4000;s 0x2000;aeip;aes;aes;arj')[0])
check(regs['pc'] == 0x4000 and regs['r3'] == 0x3d and regs['r6'] == 11, 'jr.d2 r5 with a packet in the first slot: both slots, then the jump')
# 3c. lbu.post with 5-bit registers, and #0x3fff, the 6-byte and #imm16, vcfg4c? #0xc (hypothetical: p_k <- rs), ld46? (hypothetical byte load)
regs = json.loads(r2('wx 6e8501 @ 0x3000;wx 8081 @ 0x400;aei;ar r8=0x400;ar r1=0;s 0x3000;aeip;aes;arj')[0])
check(regs['r1'] == 0x80 and regs['r8'] == 0x401, 'lbu.post r1, [r8] += 0x1 (3 bytes): zero-extended byte, post-increment')
regs = json.loads(r2('wx 67a468 740004ffc063 @ 0x3000;aei;ar r3=0x12345678;ar r8=0;s 0x3000;aeip;aes;aes;arj')[0])
check(regs['r8'] == 0x1678 and regs['r3'] == 0x1670, 'and r8, r3, #0x3fff (67 a4); and r3, r3, #0x3ff0 (74 sub 1, 6 bytes)')
regs = json.loads(r2('wx 4c003231 4c003233 @ 0x3000;aei;ar r17=0x1234;ar vp0=0;ar vp1=0;s 0x3000;aeip;aes;aes;arj')[0])
check(regs['vp0'] == 0x1234 and regs['vp1'] == 0x1234, 'vcfg4c? v17 / v19, r17, #0xc: the hypothetical p_k <- rs (vp0, vp1)')
regs = json.loads(r2('wx 4600a020 @ 0x3000;wx 7f @ 0x400;aei;ar r1=0x400;ar r0=0;s 0x3000;aeip;aes;arj')[0])
check(regs['r0'] == 0x7f and regs['r1'] == 0x428, 'ld46? r0, [r1] += 0x28: hypothetical zero-extended byte with a post-increment')
out = r2('wx c0000109 2005 @ 0x3000;ao 1 @ 0x3000~esil;aei;s 0x3000;aeip;aes;ar pc')
check(any('vop' in l for l in out) and out[-1].strip() == '0x00003004', 'v.move.mv: the ESIL is vop (modelled by the plugin), aes steps over it')

# 3d. ctz / sqr? / sra? / vrd? semantics, the .post templates write rd last (rd == rb: the loaded value wins), the signed
# post-increment of the 6e page, and the public model of the VU (vr0-vr31 of 128 bytes as four 256-bit quarters, vp0-vp7, va0-va7)
regs = json.loads(r2('wx 41f38820 @ 0x3000;aei;ar r1=0x8;ar r0=0xff;s 0x3000;aeip;aes;arj')[0])
check(regs['r0'] == 3, 'ctz r0, r1: ctz(8) = 3')
regs = json.loads(r2('wx 41f38c20 67fc75 @ 0x3000;aei;ar r1=7;ar r0=0;ar r21=0xfffffff0;s 0x3000;aeip;aes;aes;arj')[0])
check(regs['r0'] == 49 and regs['r21'] == 0xfffffffe, 'sqr? r0, r1 (7 * 7); sra? r21, r21, #3 (arithmetic shift of a negative value)')
regs = json.loads(r2('wx 1a76 @ 0x3000;aei;ar vb1_7=0x99;ar r7=0;s 0x3000;aeip;aes;arj')[0])
check(regs['r7'] == 0x99, 'vrd? r7, vb1[7]: r7 <- vb1_7 (hypothetical)')
regs = json.loads(r2('wx 2300 @ 0x3000;wx 7f @ 0x404;aei;ar r1=0x404;s 0x3000;aeip;aes;arj')[0])
check(regs['r1'] == 0x7f, 'lbu.post r1, [r1] += -4 with rd == rb: the loaded value wins (rd is written last)')
regs = json.loads(r2('wx 6ed063 @ 0x3000;wx deadbeef @ 0x200;aei;ar r3=0x200;s 0x3000;aeip;aes;arj')[0])
check(regs['r3'] == 0xdeadbeef, 'lw.post r3, [r3] += -0x10 (signed increment x = 4 -> -16; rd == rb): the loaded value wins')
regs = json.loads(r2('wx 6ed068 6ef463 @ 0x3000;wx deadbeef @ 0x200;aei;ar r3=0x200;ar r8=0;s 0x3000;aeip;aes;ar r3=0x300;aes;arj')[0])
check(regs['r8'] == 0xdeadbeef and regs['r3'] == 0x2fa, 'lw.post r8, [r3] += -0x10 (post-decrement of 16); sh.post r3, [r3] += -0x6')
regs = json.loads(r2('wx 21aa @ 0x3000;wx 11223344 @ 0x100;aei;ar r3=0x100;ar r11=0;s 0x3000;aeip;aes;arj')[0])
check(regs['r11'] == 0x11223344 and regs['r3'] == 0x104, 'lw.post r11, [r3] += 4 (21 aa): the destination is r11')
regs = json.loads(r2('wx 1f20 1fa0 @ 0x3000;aei;ar r1=3;s 0x3000;aeip;aes;ar r1=0x400;aes;arj')[0])
check(regs['va2'] == 3 and regs['vp2'] == 0x400, 'vset.a A2, r1 / vmem.set p2, r1: va2 and vp2 are registers')
out = r2('wx c8204002 @ 0x3000;wx 1122334455667788 @ 0x400;aei;ar va2=3;ar vp2=0x400;s 0x3000;aeip;aes;ar vr1_0;ar vp2')
check(int(out[-2], 16) == 0x665544332211 and int(out[-1], 16) == 0x406, 'v.mem.ld vr1 <- DM[vp2], 3 halves (va2 = 3): the lanes land in vr1_0 (little-endian), vp2 post-incremented by 6')
out = r2('wx c8004002 c8004003 @ 0x3000;wx 1122334455667788 @ 0x400;wx 0000000000000000 @ 0x500;aei;ar va2=3;ar vp2=0x400;s 0x3000;aeip;aes;ar vp2=0x500;aes;p8 8 @ 0x500;ar vp2')
check(out[-2].strip() == '1122334455660000' and int(out[-1], 16) == 0x506, 'v.mem.ld vr0 <- DM[0x400]; v.mem.st DM[0x500] <- vr0: 6 bytes copied through the VU, vp2 = 0x506')
out = r2('wx c8004002 c0280109 c0000b09 c8004003 @ 0x3000;wx 1122334455667788 @ 0x400;wx 0000000000000000 @ 0x500;aei;ar va2=3;ar vp2=0x400;s 0x3000;aeip;aes;aes;ar vr0_0=0;aes;ar vp2=0x500;aes;p8 8 @ 0x500')
check(out[-1].strip() == '1122334455660000', 'v.move.mv vr5 <- vr0, vr0 cleared, v.move.mv vr0 <- vr5, st: the register copy comes back to memory')
out = r2('wx c8010002 @ 0x3000;wx 1122334455667788 @ 0x400;aei;ar va2=3;ar vp2=0x400;ar vp4=0x400;s 0x3000;aeip;aes;ar vp2;ar vp4;ar vr1_0')
check(int(out[-3], 16) == 0x400 and int(out[-2], 16) == 0x400 and int(out[-1], 16) == 0, 'v.mem.ld with F2 = 4 (second access family, pointer not established): no effect')
out = r2('wx c8204002 @ 0x3000;wx 1122334455667788 @ 0x400;aei;ar va2=0;ar vp2=0x400;s 0x3000;aeip;aes;ar vp2;ar vr1_0')
check(int(out[-2], 16) == 0x480 and int(out[-1], 16) == 0x8877665544332211, 'v.mem.ld with va2 = 0: the whole 128-byte register, vp2 += 128')
out = r2('wx f000000285288a02 @ 0x3000;wx aabbccdd @ 0x400;aei;ar va0=2;ar vp0=0x400;ar r1=1;ar r2=2;ar r3=3;ar r6=6;s 0x3000;aeip;aes;ar vr0_0;ar vp0;ar r2;ar r3')
check([int(l, 16) for l in out[-4:]] == [0xddccbbaa, 0x404, 8, 4], 'bundle { v.mem.ld op9=0x00a ‖ add r2, r6 ‖ add r3, r1 }: the vector load and the two scalar slots')
out = r2('wx c0000001 c000000e @ 0x3000;aei;ar va0=2;ar vp0=0x400;s 0x3000;aeip;aes;aes;ar vp0;ar pc')
check([int(l, 16) for l in out[-2:]] == [0x400, 0x3008], 'v.const.movi? / v.alu3.acc.add?: no model (vop without effect), aes steps over them')

# 4. pseudo
text = '\n'.join(r2('e asm.pseudo=true;wx 889026e4 3084 1402 0566 2005 @ 0x1000;pD 12 @ 0x1000'))
check('parallel { r1 = r3; if (r5 == 0) goto 0x0000100e; }' in text, 'pseudo: packet')
check('r5 = dmem32[r1 + 0x4]' in text and 'sp += 0x8' in text and 'r7 = sext16(r5)' in text and 'return' in text, 'pseudo: memory, stack, extension, return')
text = '\n'.join(r2('e asm.pseudo=true;wx 90c821e3 41aaa8c1 @ 0x1000;pD 8 @ 0x1000'))
check('r1 = dmem32[r2]; r2 += 4' in text and 'r1 = ((r6 >> 21) & ((1U << 10) - 1))' in text, 'pseudo: post-increment, bit field')

print('\n%s' % ('ALL OK' if not failures else '%d FAILURES' % failures))
sys.exit(1 if failures else 0)
