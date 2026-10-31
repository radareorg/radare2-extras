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
    # uSIP packets: slot-0 control flow, delay slot, interleaved S S O O layout; the
    # compared register of a 32-bit branch carries its bank bit (r15!).
    text = '\n'.join(r2('e asm.cpu=usip;e asm.pseudo=true;wx 7e0cc00c5c3907f0541c805c@0x40c;pD 12@0x40c', 0x8000))
    assert 'if (r15! != 0) goto 0x00000418' in text and 'goto 0x0000041e' in text and 'r15! = 0x1d07005c' in text
    text = '\n'.join(r2('e asm.cpu=usip;e asm.pseudo=true;wx 3e015000400ac000def9@0x41e;pD 10@0x41e', 0x8000))
    assert 'dmem32[r15! + 0x0] = r0' in text and 'r0 = 0x0' in text and 'return' in text
    text = '\n'.join(r2('e asm.cpu=usip;e asm.pseudo=true;wx 44614a315000d000@0x68c;pD 8@0x68c', 0x8000))
    assert 'dmem32[r2 + 0x0] = r6' in text and '.unit 0x5000 (st.w @ 0x0000068c)' in text and '.unit 0xd000 (st.w @ 0x0000068e)' in text
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
    assert ops[0]['size'] == 4 and ops[0]['type'] == 'cjmp' and ops[0]['opcode'] == 'bnez r15!, 0x00000418'
    assert ops[0]['jump'] == 0x418 and ops[0]['fail'] == 0x410 and ops[0]['cond'] == 'ne'
    assert ops[0]['opex']['form'] == 'bnez' and ops[0]['opex']['units'] == [0x40c, 0x40e]
    # b.s with the packet open: the 48-bit mov32 that follows is its delay slot (one op).
    ops = json.loads(r2('e asm.cpu=usip;wx 5c3907f0541c805c@0x410;aoj 2@0x410', 0x8000)[0])
    assert [o['size'] for o in ops] == [2, 6] and [o['type'] for o in ops] == ['jmp', 'mov']
    assert ops[0]['jump'] == 0x41e and ops[0]['delay'] == 1 and ops[0]['opex']['packet']['delay']
    assert ops[1]['opcode'] == 'mov32 r15!, #0x1d07005c' and ops[1]['opex']['delay_slot'] and ops[1]['val'] == 0x1d07005c
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
    # Table update: port I/O, the 32-bit ret of the sys shape, nop32, register jump.
    ops = json.loads(r2('e asm.cpu=usip;wx 0000c674001ac0024014c00040ffc000@0x1000;aoj 4@0x1000', 0x8000)[0])
    assert [o['opcode'] for o in ops] == ['add r0, r0, #0x33a', 'movi r1, #0x1', 'iow r1, [r0]', 'ret']
    assert [o['type'] for o in ops] == ['add', 'mov', 'io', 'ret'] and ops[2]['ireg'] == 'r0' and ops[3]['opex']['form'] == 'ret32'
    ops = json.loads(r2('e asm.cpu=usip;wx 0030c7004007fac04614c000@0x1100;aoj 3@0x1100', 0x8000)[0])
    assert [o['opcode'] for o in ops] == ['add r3, r0, #0x380', 'nop32', 'iow r1, [r3]'] and ops[1]['type'] == 'nop'
    ops = json.loads(r2('e asm.cpu=usip;wx 4414c400@0x524;aoj 1@0x524', 0x8000)[0])
    assert ops[0]['opcode'] == 'ior r1, [r2]' and ops[0]['type'] == 'io' and ops[0]['opex']['form'] == 'ior'
    ops = json.loads(r2('e asm.cpu=usip;wx 402fc000@0x5d6;aoj 1@0x5d6', 0x8000)[0])
    assert ops[0]['opcode'] == 'jr r2' and ops[0]['type'] == 'rjmp' and ops[0]['reg'] == 'r2'
    # Stack adjust (16-bit closer, scaled signed immediate) and the 64-bit pair load (rB:rB+1, 2 * off11).
    ops = json.loads(r2('e asm.cpu=usip;wx bdd8@0x100;aoj 1@0x100', 0x8000)[0])
    assert ops[0]['opcode'] == 'addsp #-0x14' and ops[0]['type'] == 'add' and ops[0]['size'] == 2
    ops = json.loads(r2('e asm.cpu=usip;wx 5005c0f8@0x1200;aoj 1@0x1200', 0x8000)[0])
    assert ops[0]['opcode'] == 'ld.d r0:r1, [r8+0x1f0]' and ops[0]['type'] == 'load' and ops[0]['refptr'] == 8 and ops[0]['disp'] == 0x1f0
    # First-slot context forms (rule R7 / lea?) and the movhi value (20 bits << 12, high-bank destination).
    ops = json.loads(r2('e asm.cpu=usip;wx 45045ad65002c002@0x9b0;aoj 1@0x9b0', 0x8000)[0])
    assert ops[0]['opcode'] == 'stslot r0!, #0x4' and ops[0]['type'] == 'store' and ops[0]['opex']['form'] == 'stslot_S0'
    ops = json.loads(r2('e asm.cpu=usip;wx 5d004b074fe3f867@0xebc;aoj 2@0xebc', 0x8000)[0])
    assert [o['opcode'] for o in ops] == ['ld.w r0!, [r14-0x20]', 'cmov r7, r5, r0!'] and ops[0]['opex']['form'] == 'mem_ld_w_t4_F1S0'
    ops = json.loads(r2('e asm.cpu=usip;wx 1028b425@0x16f6;aoj 1@0x16f6', 0x8000)[0])
    assert ops[0]['opcode'] == 'lea? r8, [sp+0x14]' and ops[0]['type'] == 'lea' and ops[0]['opex']['form'] == 'lea_sp_S0'
    ops = json.loads(r2('e asm.cpu=usip;wx 3f980381fe015f05@0x4da8;aoj 1@0x4da8', 0x8000)[0])
    assert ops[0]['opcode'] == 'movhi r9!, #0x7ff00000' and ops[0]['val'] == 0x7ff00000 and ops[0]['opex']['units'] == [0x4da8, 0x4dac]
    # 48-bit control packets [head][op16][tail] with the tail at +2 and a target guard: the loop end at the next
    # packet validates; beqz.d validates when the forward target is a packet start (scan of the bytes at hand) and
    # is data when it is not; the call with the F' = 0 tail needs the function table, so it is read unverified (call?).
    ops = json.loads(r2('e asm.cpu=usip;wx 4a0f5e0db0060fb34563166cc400@0x1300;aoj 1@0x1300', 0x8000)[0])
    assert ops[0]['opcode'] == 'loop r5, last=0x00001306' and ops[0]['ptr'] == 0x1306 and ops[0]['opex']['form'] == 'loop_F0'
    assert ops[0]['opex']['units'] == [0x1300, 0x1304] and ops[0]['opex']['target_guard'] == 'validated'
    pk = 'wx 240c2132501800046520d0026730c0007ffe4f336ff1d0044871d000@0x752;'
    ops = json.loads(r2('e asm.cpu=usip;' + pk + 'aoj 1@0x752', 0x8000)[0])
    assert ops[0]['opcode'] == 'beqz.d r2!, 0x0000076a' and ops[0]['type'] == 'cjmp' and ops[0]['jump'] == 0x76a and ops[0]['delay'] == 4
    assert ops[0]['opex']['units'] == [0x752, 0x756] and ops[0]['opex']['target_guard'] == 'validated'
    ops = json.loads(r2('e asm.cpu=usip;' + pk + 'wx 4f33@0x768;aoj 1@0x752', 0x8000)[0])
    assert ops[0]['opcode'].startswith('.dsp') and 'jump' not in ops[0]
    ops = json.loads(r2('e asm.cpu=usip;wx 7ffe557ebcd1@0x1af0;aoj 2@0x1af0', 0x8000)[0])
    assert ops[0]['opcode'] == 'call? 0x000017c0' and ops[0]['type'] == 'call' and ops[0]['jump'] == 0x17c0 and ops[0]['delay'] == 2
    assert ops[0]['opex']['form'] == 'call_F0' and ops[0]['opex']['target_guard'] == 'unverified' and ops[0]['opex']['confidence'] == 'medium'
    assert ops[1]['opcode'] == 'st.w r7, [r10+20]' and ops[1]['opex']['delay_slot']
    text = '\n'.join(r2('e asm.cpu=usip;e asm.pseudo=true;wx 0000c674001ac0024014c00040ffc000@0x1000;pD 16@0x1000;wx 5005c0f8@0x1200;pD 4@0x1200;wx bdd8@0x100;pD 2@0x100', 0x8000))
    assert 'io[r0] = r1' in text and 'r0:r1 = dmem64[r8 + 0x1f0]' in text and 'sp -= 0x14' in text
    # Table update (594 forms): the immediate hardware loop with its target validated (the next packet is visible),
    # with the S = 0 tail at +2 (the bytes up to the loop end validate it) and unverified (loop#?: the end lies beyond
    # the bytes at hand).
    ops = json.loads(r2('e asm.cpu=usip;wx 006f600cc207021640b0c30e@0x1bfa;aoj 2@0x1bfa', 0x8000)[0])
    assert ops[0]['opcode'] == 'loop# #4, last=0x00001c06' and ops[0]['ptr'] == 0x1c06 and ops[0]['val'] == 4 and 'jump' not in ops[0]
    assert ops[0]['opex']['form'] == 'loop_imm_F0S0' and ops[0]['opex']['target_guard'] == 'validated' and ops[0]['size'] == 4
    assert ops[1]['opcode'] == 'movi r1, #0x0'
    pk = '404f4a26602ec2801028b425048778095ec1880740904000c005586b88214c7de00e04087bf9480b9813dc11f246140b'
    ops = json.loads(r2('e asm.cpu=usip;wx %s@0x16ee;aoj 2@0x16ee' % pk, 0x8000)[0])
    assert ops[0]['opcode'] == 'loop# #3, last=0x0000171c' and ops[0]['opex']['units'] == [0x16ee, 0x16f2] and ops[0]['opex']['form'] == 'loop_imm_F1S0'
    assert ops[1]['opcode'] == 'add r2, r5, #0x140'
    text = '\n'.join(r2('e asm.cpu=usip;wx 006f600cc207@0x7ffa;pD 6@0x7ffa', 0x8000))
    assert 'loop#? #4, last=0x00008006' in text
    # 48-bit compare-and-branch prefix forms (b<cond>.l): validated (target +32 within the lookahead), unverified
    # (target beyond it: confidence medium) and not taken (the target is not a packet start: normal layout).
    pk = '402f6100c01004477b0348078a070a0b88652a4d8c1940606000c000483dfff34507fb034609f35a'
    ops = json.loads(r2('e asm.cpu=usip;wx %s@0x1562;aoj 2@0x1562' % pk, 0x8000)[0])
    assert ops[0]['opcode'] == 'blt.l r2, #0x1, 0x00001582' and ops[0]['type'] == 'cjmp' and ops[0]['cond'] == 'lt' and ops[0]['sign']
    assert ops[0]['size'] == 6 and ops[0]['jump'] == 0x1582 and ops[0]['fail'] == 0x1568 and ops[0]['delay'] == 0
    assert ops[0]['opex']['form'] == 'bcc48_opf_mh2_blt' and ops[0]['opex']['target_guard'] == 'validated'
    assert ops[0]['opex']['units'] == [0x1562, 0x1564, 0x1566] and ops[1]['opcode'] == 'lsl r3, r2, #0x4'
    ops = json.loads(r2('e asm.cpu=usip;wx 404e6100c151@0x1f84;aoj 1@0x1f84', 0x8000)[0])
    assert ops[0]['opcode'] == 'beq.l? r4, #0x1, 0x00002226' and ops[0]['jump'] == 0x2226 and ops[0]['cond'] == 'eq'
    assert ops[0]['opex']['target_guard'] == 'unverified' and ops[0]['opex']['confidence'] == 'medium'
    ops = json.loads(r2('e asm.cpu=usip;wx 404e6100c00440004000c000@0x1f84;aoj 1@0x1f84', 0x8000)[0])
    assert ops[0]['opcode'] == 'st.w r4, [r0+12]' and 'jump' not in ops[0]
    # The 64-bit twin (head with F = 0 followed by 1e0d): four units, one op, the packet closed by its last unit.
    ops = json.loads(r2('e asm.cpu=usip;wx 002d1e0d6200c49e1c501c2040d840dc@0x1cca;aoj 1@0x1cca', 0x8000)[0])
    assert ops[0]['opcode'] == 'blt.l? r2, #0x2, 0x00002606' and ops[0]['size'] == 8 and ops[0]['fail'] == 0x1cd2
    assert ops[0]['opex']['units'] == [0x1cca, 0x1ccc, 0x1cce, 0x1cd0] and ops[0]['opex']['form'] == 'bcc48_opd_mh2_blt_64'
    # 64-bit pair load/store with the sign bit of the offset (off = 4 * v9 - 2048 * s).
    ops = json.loads(r2('e asm.cpu=usip;wx 5225c3b1@0x3054;aoj 1@0x3054', 0x8000)[0])
    assert ops[0]['opcode'] == 'ld.d r2:r3, [r9-0xa0]' and ops[0]['type'] == 'load' and ops[0]['refptr'] == 8
    assert ops[0]['disp'] == (-0xa0) & 0xffffffffffffffff and dict(name='off', type='imm', value=-160) in ops[0]['opex']['operands']
    ops = json.loads(r2('e asm.cpu=usip;wx 4a85cbef@0x141e;aoj 1@0x141e', 0x8000)[0])
    assert ops[0]['opcode'] == 'st.d r8:r9, [r5-0x24]' and ops[0]['type'] == 'store' and ops[0]['refptr'] == 8
    # Half-word and word offsets of the closed negative bands (odd f12; f12 = 3 mod 4 >= 0xf00).
    ops = json.loads(r2('e asm.cpu=usip;wx 5000dfcf@0x24dc;aoj 1@0x24dc', 0x8000)[0])
    assert ops[0]['opcode'] == 'ld.h r0, [r8-0x32]' and ops[0]['sign'] and dict(name='off', type='disp', value=-50) in ops[0]['opex']['operands']
    ops = json.loads(r2('e asm.cpu=usip;wx 1c201c104ffb4fff040749a72402bb66@0xe8c;aoj 2@0xe8c', 0x8000)[0])
    assert [o['opcode'] for o in ops] == ['ld.w r2, [r14-0x8]', 'ld.w r1, [r14-0x4]'] and ops[0]['opex']['units'] == [0xe8c, 0xe90]
    # Set-on-compare family: seq / sle of op 6 (tail adjacent), sgt of op 7 with the tail at +2.
    ops = json.loads(r2('e asm.cpu=usip;wx 4216d402@0x100e;aoj 1@0x100e', 0x8000)[0])
    assert ops[0]['opcode'] == 'seq r1, r1, #0x1' and ops[0]['type'] == 'cmp' and ops[0]['opex']['form'] == 'seq_op6_F1S1'
    ops = json.loads(r2('e asm.cpu=usip;wx 4057600ecf20@0x144ce;aoj 1@0x144ce', 0x20000)[0])
    assert ops[0]['opcode'] == 'sgt r5, r0, #0x190' and ops[0]['type'] == 'cmp' and ops[0]['opex']['units'] == [0x144ce, 0x144d2]
    ops = json.loads(r2('e asm.cpu=usip;wx 12361246403000205820c00c@0x1d28;aoj 2@0x1d28', 0x8000)[0])
    assert ops[1]['opcode'] == 'sle r4, r9, #0x10' and ops[1]['type'] == 'cmp' and ops[1]['opex']['units'] == [0x1d2a, 0x1d30]
    # movhi: the small cell (f12 >> 1 << 12).
    ops = json.loads(r2('e asm.cpu=usip;wx 703075220008001c4a57c040@0x1dba;aoj 3@0x1dba', 0x8000)[0])
    assert ops[2]['opcode'] == 'movhi r0, #0x00020000' and ops[2]['val'] == 0x20000 and ops[2]['opex']['form'] == 'movhi_small'
    # 16-bit st.h of the first slot (formerly movi/addi).
    ops = json.loads(r2('e asm.cpu=usip;wx 408f44605000c004@0x76e;aoj 1@0x76e', 0x8000)[0])
    assert ops[0]['opcode'] == 'st.h r8, [r0]' and ops[0]['type'] == 'store' and ops[0]['size'] == 2 and ops[0]['opex']['form'] == 'st_h16_f_slot0'
    # st.h with the F' = 0 tail (R-st1h): the tail is deferred (+2 or farther) ...
    ops = json.loads(r2('e asm.cpu=usip;wx 4c314c3fa004@0x1392;aoj 2@0x1392', 0x8000)[0])
    assert ops[0]['opcode'] == 'st.h r3, [r6+0x4]' and ops[0]['opex']['units'] == [0x1392, 0x1396] and ops[0]['opex']['form'] == 'st_h_Fp0_F1S1'
    assert ops[1]['opcode'] == 'movi r6, #0x7'
    # ... and in the first slot a b.s head whose target is a packet start keeps its 16-bit reading (the pair is undone).
    pk = '5c515c5f2014ca17'
    ops = json.loads(r2('e asm.cpu=usip;wx %s@0x2000;aoj 1@0x2000' % (pk + 'be79' * 5 + '4020c000be79'), 0x8000)[0])
    assert ops[0]['opcode'] == 'st.h r5, [r14+0x14]' and ops[0]['opex']['units'] == [0x2000, 0x2004]
    ops = json.loads(r2('e asm.cpu=usip;wx %s@0x2000;aoj 3@0x2000' % (pk + 'be79' * 6 + '4020c000'), 0x8000)[0])
    assert [o['opcode'] for o in ops] == ['b.s 0x00002014', 'movi r14, #0xb', '.op4i r1, r0, tail'] and ops[0]['delay'] == 2 and ops[2]['opex']['delay_slot']
    # H H T T: two named stores interleaved with their tails at +2 in a 4-unit packet.
    ops = json.loads(r2('e asm.cpu=usip;wx 44614a315000d000@0x68c;aoj 2@0x68c', 0x8000)[0])
    assert [o['opcode'] for o in ops] == ['st.w r6, [r2+0x0]', 'st.w r3, [r5+0x0]']
    assert ops[0]['opex']['units'] == [0x68c, 0x690] and ops[1]['opex']['units'] == [0x68e, 0x692]
    # The op8 slot split, the 48-bit add trio and the system op whose F = S = 0 tail keeps the packet open.
    ops = json.loads(r2('e asm.cpu=usip;wx 60086300f93e@0x1196;aoj 2@0x1196', 0x8000)[0])
    assert [o['opcode'] for o in ops] == ['ldslot r0, #0x21', 'ldslot r0!, #0x22'] and [o['size'] for o in ops] == [2, 2]
    ops = json.loads(r2('e asm.cpu=usip;wx 0e103fc0c000@0x4d70;aoj 1@0x4d70', 0x8000)[0])
    assert ops[0]['opcode'] == 'add r1, r1, #0x3ff00000' and ops[0]['size'] == 6
    ops = json.loads(r2('e asm.cpu=usip;wx 041f5000e2aa@0x1042;aoj 2@0x1042', 0x8000)[0])
    assert [o['opcode'] for o in ops] == ['cop r2', 'ld.w r10, [r1+16]'] and ops[0]['size'] == 4 and ops[0]['opex']['form'] == 'cop_FS0'
    # xor alone, movi into the high bank, bset with the high-bank destination, the funnel shift osl.
    ops = json.loads(r2('e asm.cpu=usip;wx 838a@0x16bc;aoj 1@0x16bc', 0x8000)[0])
    assert ops[0]['opcode'] == 'xor r1, r8!' and ops[0]['type'] == 'xor'
    ops = json.loads(r2('e asm.cpu=usip;wx 2407e439@0xf14;aoj 1@0xf14', 0x8000)[0])
    assert ops[0]['opcode'] == 'movi r2!, #0x0' and ops[0]['opex']['form'] == 'movi5_hi'
    ops = json.loads(r2('e asm.cpu=usip;wx 00002007ff18@0x1c20;aoj 2@0x1c20', 0x8000)[0])
    assert ops[1]['opcode'] == 'bset r8!, r0!, #0x0' and ops[1]['type'] == 'or'
    ops = json.loads(r2('e asm.cpu=usip;wx 04570c419be2@0x409c;aoj 1@0x409c', 0x8000)[0])
    assert ops[0]['opcode'] == 'osl r5, r2, #1' and ops[0]['type'] == 'shl' and ops[0]['opex']['units'] == [0x409c, 0x40a0]
    text = '\n'.join(r2('e asm.cpu=usip;e asm.pseudo=true;wx 006f600cc207021640b0c30e@0x1bfa;pD 4@0x1bfa;wx 5225c3b1@0x3054;pD 4@0x3054;wx 12361246403000205820c00c@0x1d28;pD 12@0x1d28', 0x8000))
    assert 'repeat 4 times until last=0x00001c06' in text and 'r2:r3 = dmem64[r9 - 0xa0]' in text and 'r4 = ((int32_t)r9 <= (int32_t)0x10)' in text
    # MS15E30 group-5 forms: 0xDA00 / 0xDC00 named after the little-endian layout of the data memory.
    ops = json.loads(r2('wx da49dc49d849de49ca89cb21;aoj 6')[0])
    assert [o['opcode'] for o in ops] == ['cmulr16 r2, r2, r2', 'cmuli16 r2, r2, r2', 'cmulcr16 r2, r2, r2', 'cmulci16 r2, r2, r2', 'rem16 r2, r2', 'ctz16 r1, r2']
    assert [o['type'] for o in ops] == ['mul', 'mul', 'mul', 'mul', 'mod', 'unk']
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
