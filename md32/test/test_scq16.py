#!/usr/bin/env python3
"""Exercise cpu=scq16 (SCQ16, MD32 family, byte-granular packet variant) inside r2 with loose bytes only: disassembly of
stand-alone units, packets `{ A ‖ B }`, vector ops and bundles; analysis (types, targets relative to the packet start,
delay slots counted in instructions, fall-through after the slots, loop references); opex; ESIL (parallel packet
semantics, delayed call via SETJT/SETD, loads/stores and post-increments, sign/zero extension, division, bit fields,
the VU scalar ports, vop); the pseudo parser.  No firmware is needed."""
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
    ('48080001', 4, 'mv        r1, #0x4000'), ('437acda0', 4, 'vpmem?    p0, #0x2c, m13  (b1 7a)'), ('41b51461', 4, 'fxts?     r1, r3, #5, #10'),
    ('42141ce6', 4, 'sel?      r6, r7, x7, r8  (q0 c1)'), ('40078000', 4, 'vbcast.i  v0, #-0x400  (sub 000)'), ('44000020', 4, 'lbu       r0, 0x0(r1)'),
    ('47c00020', 4, 'sw        r0, [r1] += 0'), ('42600000', 4, 'cmov.lt   r0, r0, r0, r0'), ('41aaa8c1', 4, 'fxtu      r1, r6, #10, #21'), ('4190410f', 4, 'fup       r15, r8, #16, #0'),
    ('55d01b03', 4, 'do.d2     r3, end=0x0000101b (F=27)'), ('5e800000', 4, 'sys       #0x0 (0x0000)'), ('41f38400', 4, 'clz       r0, r0'), ('41f70008', 4, 'addsp     sp, #0x8'),
    ('40200020', 4, 'mul       r0, r0, #1'), ('4a000020', 4, 'add       r0, r1, #0x0'), ('4b000020', 4, 'and       r0, r1, #0x0'), ('c0000001', 4, 'v.const.movi? op9=0x001 A0 B0 F0,F0,F0'),
    ('889026e4', 4, '{ mv        r1, r3 ‖ beqz      r5, #0, 0x0000100e }'), ('90c821e3', 4, '{ lw.post   r1, [r2] += 4 ‖ lw.post   r4, [r7] += 4 }'),
    ('903fe90543', 5, '{ sw.lr     lr, -0x4(sp) ‖ beqz8.d1  r3, #0, 0x0000102a }'), ('a40003d19125', 6, '{ mv        r3, #0x3d ‖ mv        r6, r3 }'),
    ('a17a0e7350813001', 8, '{ cmov.ne   r6, r7, #0, r8 ‖ ble.d1    #0, r1, 0x00001013 }'),
    ('f000000285288a02', 8, 'vbundle   v.mem.ld? op9=0x00a A0 B0 F0,F0,F0 ‖ add r2, r6 ‖ add r3, r1'),
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

# 4. pseudo
text = '\n'.join(r2('e asm.pseudo=true;wx 889026e4 3084 1402 0566 2005 @ 0x1000;pD 12 @ 0x1000'))
check('parallel { r1 = r3; if (r5 == 0) goto 0x0000100e; }' in text, 'pseudo: packet')
check('r5 = dmem32[r1 + 0x4]' in text and 'sp += 0x8' in text and 'r7 = sext16(r5)' in text and 'return' in text, 'pseudo: memory, stack, extension, return')
text = '\n'.join(r2('e asm.pseudo=true;wx 90c821e3 41aaa8c1 @ 0x1000;pD 8 @ 0x1000'))
check('r1 = dmem32[r2]; r2 += 4' in text and 'r1 = ((r6 >> 21) & ((1U << 10) - 1))' in text, 'pseudo: post-increment, bit field')

print('\n%s' % ('ALL OK' if not failures else '%d FAILURES' % failures))
sys.exit(1 if failures else 0)
