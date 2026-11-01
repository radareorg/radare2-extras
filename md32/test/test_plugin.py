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
    # b.s with the packet open: the 48-bit mov32 that follows is its delay slot (one op); the target is validated on the
    # packet that starts there (the next two packets are part of the vector).
    ops = json.loads(r2('e asm.cpu=usip;wx 5c3907f0541c805c07f0141cc06c@0x410;aoj 2@0x410', 0x8000)[0])
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
    # hardware loop: the end address is a reference, not a branch (its guard validates on the packet that starts there).
    ops = json.loads(r2('e asm.cpu=usip;wx 060f02277010786028104390c100c123e227@0x2478;aoj 1@0x2478', 0x8000)[0])
    assert ops[0]['opcode'] == 'loop r3, last=0x00002488' and ops[0]['ptr'] == 0x2488 and 'jump' not in ops[0]
    assert ops[0]['opex']['target_guard'] == 'validated'
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
    assert [o['opcode'] for o in ops] == ['save w=0', 'ret', 'restore w=4', '.fill 0xffff']
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
    # The op8 slot split (the two slot-family halves of an .op8? pair), the 48-bit add trio and the system op whose
    # F = S = 0 tail keeps the packet open.
    ops = json.loads(r2('e asm.cpu=usip;wx 004842700787d03e@0x194c;aoj 3@0x194c', 0x8000)[0])
    assert [o['opcode'] for o in ops] == ['ldslot r4, #0x1', 'ldslot r7, #0x2', 'fxtu r8!, r3, #0x1, #0xf'] and [o['size'] for o in ops] == [2, 2, 4]
    assert ops[0]['opex']['form'] == 'ldslot_split' and ops[0]['type'] == 'load'
    ops = json.loads(r2('e asm.cpu=usip;wx 0e103fc0c000@0x4d70;aoj 1@0x4d70', 0x8000)[0])
    assert ops[0]['opcode'] == 'add r1, r1, #0x3ff00000' and ops[0]['size'] == 6
    ops = json.loads(r2('e asm.cpu=usip;wx 041f5000e2aa@0x1042;aoj 2@0x1042', 0x8000)[0])
    assert [o['opcode'] for o in ops] == ['cop r2', 'ld.w r10, [r1+16]'] and ops[0]['size'] == 4 and ops[0]['opex']['form'] == 'cop_FS0'
    # xor alone, movi into the high bank, bset with the high-bank destination, the funnel shift osl.
    ops = json.loads(r2('e asm.cpu=usip;wx 838a@0x16bc;aoj 1@0x16bc', 0x8000)[0])
    assert ops[0]['opcode'] == 'xor r1, r8!' and ops[0]['type'] == 'xor'
    # (the updated table pairs this unit with its named 16-bit tail as mtcsr? of an accumulator CSR: R-mtacc)
    ops = json.loads(r2('e asm.cpu=usip;wx 2407e439@0xf14;aoj 1@0xf14', 0x8000)[0])
    assert ops[0]['opcode'] == 'mtcsr? #0x39, r2!' and ops[0]['opex']['form'] == 'mtcsr_q' and ops[0]['size'] == 4
    ops = json.loads(r2('e asm.cpu=usip;wx 00002007ff18@0x1c20;aoj 2@0x1c20', 0x8000)[0])
    assert ops[1]['opcode'] == 'bset r8!, r0!, #0x0' and ops[1]['type'] == 'or'
    ops = json.loads(r2('e asm.cpu=usip;wx 04570c419be2@0x409c;aoj 1@0x409c', 0x8000)[0])
    assert ops[0]['opcode'] == 'osl r5, r2, #1' and ops[0]['type'] == 'shl' and ops[0]['opex']['units'] == [0x409c, 0x40a0]
    text = '\n'.join(r2('e asm.cpu=usip;e asm.pseudo=true;wx 006f600cc207021640b0c30e@0x1bfa;pD 4@0x1bfa;wx 5225c3b1@0x3054;pD 4@0x3054;wx 12361246403000205820c00c@0x1d28;pD 12@0x1d28', 0x8000))
    assert 'repeat 4 times until last=0x00001c06' in text and 'r2:r3 = dmem64[r9 - 0xa0]' in text and 'r4 = ((int32_t)r9 <= (int32_t)0x10)' in text
    # Table update (634 forms): the 14-bit word displacement of the ld.w/st.w pairs (W14, here in the H H T T layout).
    ops = json.loads(r2('e asm.cpu=usip;wx 5011501151c6d1ca@0x3000;aoj 2@0x3000', 0x8000)[0])
    assert [o['opcode'] for o in ops] == ['st.w r1, [r8+0x11c4]', 'st.w r1, [r8+0x11c8]'] and ops[0]['disp'] == 0x11c4
    assert ops[0]['opex']['units'] == [0x3000, 0x3004] and dict(name='off', type='disp', value=0x11c4) in ops[0]['opex']['operands']
    # nop.ctl: the structural no-op 5e0d (renamed after the layout; never a tail, never a head with a tail).
    ops = json.loads(r2('e asm.cpu=usip;wx 5e0d3836020c8217@0x189c;aoj 3@0x189c', 0x8000)[0])
    assert [o['opcode'] for o in ops] == ['nop.ctl', 'add r3, r12!, #0x106', 'movi r1, #0x2']
    assert ops[0]['type'] == 'nop' and ops[0]['size'] == 2 and ops[0]['opex']['form'] == 'nop_ctl' and ops[0]['opex']['kind'] == 'nop'
    ops = json.loads(r2('e asm.cpu=usip;wx 5e0da487@0x19a0;aoj 2@0x19a0', 0x8000)[0])
    assert [o['opcode'] for o in ops] == ['nop.ctl', 'movi r2!, #0x10']
    # The bit-field family: fxtu / fxts (extract), fup (insert, read-modify-write) and the fup? cell; pos = rotr5(p).
    ops = json.loads(r2('e asm.cpu=usip;wx 0007d03e@0x2c42;aoj 1@0x2c42', 0x8000)[0])
    assert ops[0]['opcode'] == 'fxtu r0, r0, #0x1, #0xf' and ops[0]['type'] == 'cast' and ops[0]['opex']['form'] == 'bf_fxtu' and ops[0]['size'] == 4
    ops = json.loads(r2('e asm.cpu=usip;wx 020643d94127d5e2@0x1d1a;aoj 2@0x1d1a', 0x8000)[0])
    assert [o['opcode'] for o in ops] == ['add r0, r1, #-0x14', 'fxts r2!, r0, #0xf, #0x1'] and ops[1]['type'] == 'cast' and ops[1]['opex']['form'] == 'bf_fxts'
    ops = json.loads(r2('e asm.cpu=usip;wx 001700079910@0x124a;aoj 2@0x124a', 0x8000)[0])
    assert [o['opcode'] for o in ops] == ['fup r1, r0, #0x8, #0x8', 'movi r0, #0x0'] and ops[0]['type'] == 'or' and ops[0]['opex']['units'] == [0x124a, 0x124e]
    assert [op['value'] for op in ops[0]['opex']['operands'] if op['name'] in ('w', 'pos')] == [8, 8]
    ops = json.loads(r2('e asm.cpu=usip;wx 0207db88@0x228;aoj 1@0x228', 0x8000)[0])
    assert ops[0]['opcode'] == 'fup? r0, r1, #0x1c, #0x4' and ops[0]['opex']['form'] == 'bf_fup_q' and ops[0]['opex']['confidence'] == 'medium'
    # mtacc? (the accumulator pair load, formerly clr.a?), movi? #-32768 and sgt with F = S = 1.
    ops = json.loads(r2('e asm.cpu=usip;wx 1d401d50401400106547fd20@0xe10;aoj 5@0xe10', 0x8000)[0])
    assert ops[4]['opcode'] == 'mtacc? A0, r2!:r4!' and ops[4]['opex']['form'] == 'op7d_2_mtacc_q' and ops[4]['opex']['units'] == [0xe18, 0xe1a]
    assert ops[0]['opcode'] == 'ld.w r4!, [r14+0x14]' and ops[1]['opcode'] == 'addi r5!, r14, #0x8'
    ops = json.loads(r2('e asm.cpu=usip;wx 10a77b004087c001@0xf20;aoj 2@0xf20', 0x8000)[0])
    assert [o['opcode'] for o in ops] == ['lsl r0, r8, #0xa', 'movi? r8, #-32768'] and ops[1]['type'] == 'mov' and ops[1]['opex']['form'] == 'movi_min16_q'
    ops = json.loads(r2('e asm.cpu=usip;wx 1c300097410838654604ffff@0x46ba;aoj 5@0x46ba', 0x8000)[0])
    assert ops[4]['opcode'] == 'sgt r0, r3, #-1' and ops[4]['type'] == 'cmp' and ops[4]['opex']['form'] == 'setcc_op4_t31_sgt_m1_F1S1'
    assert [o['opcode'] for o in ops[:2]] == ['ld.w r3, [r14+0x108]', 'cmov r5, r0, r9']
    # The register forms bset / bext rd, rs1, rB (7e X = 0 / 6, renamed from .7e after the layout).
    ops = json.loads(r2('e asm.cpu=usip;wx 0487228abe02@0x3916;aoj 2@0x3916', 0x8000)[0])
    assert [o['opcode'] for o in ops] == ['bset r2, r2, r8', 'mul r1, r1, r8'] and ops[0]['type'] == 'or' and ops[0]['opex']['form'] == 'op7e_0_bset_r'
    ops = json.loads(r2('e asm.cpu=usip;wx 0087fe60@0x5048;aoj 1@0x5048', 0x8000)[0])
    assert ops[0]['opcode'] == 'bext r0, r0, r8' and ops[0]['type'] == 'shr' and ops[0]['opex']['form'] == 'op7e_6_bext_r' and ops[0]['size'] == 4
    # b<cond>.d with the [0][1][tt] tail at +2 (S0F1): unverified when the forward target lies beyond the bytes at
    # hand (bne / beqz are on the allow-list), validated by the session for a backward target (the register cells are
    # not accepted unverified: without the target the units are 16-bit ops).
    ops = json.loads(r2('e asm.cpu=usip;wx 7e096f204264cfdf@0xeb8;aoj 2@0xeb8', 0x8000)[0])
    assert ops[0]['opcode'] == 'bne.d? r15!, #0x1, 0x00000f1c' and ops[0]['type'] == 'cjmp' and ops[0]['jump'] == 0xf1c and ops[0]['cond'] == 'ne'
    assert ops[0]['opex']['form'] == 'bne_imm8_s0f1' and ops[0]['opex']['target_guard'] == 'unverified' and ops[0]['opex']['units'] == [0xeb8, 0xebc]
    assert ops[1]['opcode'] == 'ld.w r2!, [r7!-0x24]' and ops[1]['opex']['delay_slot'] and ops[0]['delay'] == 3
    ops = json.loads(r2('e asm.cpu=usip;wx 400c4d11505ed024@0x1fae;aoj 2@0x1fae', 0x8000)[0])
    assert ops[0]['opcode'] == 'beqz.d? r0, 0x0000200c' and ops[0]['opex']['form'] == 'beqz_s0f1' and ops[1]['opcode'] == 'st.w r1!, [r6+0x24]'
    pk = 'wx a03f@0x1704;wx 5e5d00667f832002bdd4@0x1782;'
    ops = json.loads(r2('e asm.cpu=usip;' + pk + 'aoj 1@0x1704;aoj 3@0x1782', 0x8000)[1])
    assert ops[0]['opcode'] == 'blt.d r15, r5, 0x00001704' and ops[0]['jump'] == 0x1704 and ops[0]['opex']['target_guard'] == 'validated'
    assert ops[0]['opex']['form'] == 'blt_rr_s0f1' and ops[0]['opex']['units'] == [0x1782, 0x1786] and ops[1]['opcode'] == 'and r6, r0, #0x1'
    ops = json.loads(r2('e asm.cpu=usip;' + pk + 'aoj 3@0x1782', 0x8000)[0])
    assert [o['opcode'] for o in ops] == ['.hword 0x5e5d', 'and r6, r0, #0x1', 'addi r15, #-0x10']
    pk = 'wx a03f@0xe3c;wx 4f1c49226ff5c004@0xe48;'
    ops = json.loads(r2('e asm.cpu=usip;' + pk + 'aoj 1@0xe3c;aoj 2@0xe48', 0x8000)[1])
    assert ops[0]['opcode'] == 'bleu.d r7, r1, 0x00000e3c' and ops[0]['cond'] == 'ls' and ops[0]['opex']['form'] == 'bleu_rr_s0f1' and ops[1]['opcode'] == 'add.2 r2!, r4, #0x2'
    # The loads with the fixed base r15 (renamed from .1eX0), the F' = 0 half-word load and the open-width .ldF0?.
    ops = json.loads(r2('e asm.cpu=usip;wx 1e80515011a1b721@0x683a;aoj 3@0x683a', 0x8000)[0])
    assert [o['opcode'] for o in ops] == ['ld.h? r8, [r15+0x150]', 'mov r10!, r8', 'mov r2!, r11!'] and ops[0]['type'] == 'load' and ops[0]['ireg'] == 'r15'
    assert ops[0]['opex']['form'] == 'x1e0_ld_h_q' and ops[0]['size'] == 4 and ops[0]['refptr'] == 2
    ops = json.loads(r2('e asm.cpu=usip;wx 1e10424044078807@0x1e90;aoj 2@0x1e90', 0x8000)[0])
    assert [o['opcode'] for o in ops] == ['ld.w? r1, [r15+0x407]', 'addi r4, r1, #-0x3fd'] and ops[0]['opex']['form'] == 'x1e0_ld_w_q' and ops[0]['opex']['units'] == [0x1e90, 0x1e94]
    ops = json.loads(r2('e asm.cpu=usip;wx 4200790e9008@0x1bbc;aoj 2@0x1bbc', 0x8000)[0])
    assert [o['opcode'] for o in ops] == ['ld.h? r0, [r1+0x8]', 'st.w r0, [r12+24]'] and ops[0]['opex']['form'] == 'ld_h_q_Fp0' and ops[0]['opex']['units'] == [0x1bbc, 0x1bc0]
    ops = json.loads(r2('e asm.cpu=usip;wx 0f009240@0x2176;aoj 1@0x2176', 0x8000)[0])
    assert ops[0]['opcode'] == '.ldF0? r0!, [r7+0x240]' and ops[0]['type'] == 'unk' and ops[0]['opex']['form'] == 'ldF0_q_t1_adj'
    # The 48-bit constants admitted by the value table (any op 0 head), and the .3eX0? trio that is not a constant.
    ops = json.loads(r2('e asm.cpu=usip;wx 1e301ffdffff@0x2cd6;aoj 1@0x2cd6', 0x8000)[0])
    assert ops[0]['opcode'] == 'mov32 r3, #0x7fff7fff' and ops[0]['size'] == 6 and ops[0]['val'] == 0x7fff7fff and ops[0]['opex']['form'] == 'c48tab_mov32'
    ops = json.loads(r2('e asm.cpu=usip;wx 1e400a495fbfbfff@0x4dc8;aoj 2@0x4dc8', 0x8000)[0])
    assert [o['opcode'] for o in ops] == ['mov32 r4, #0x7fefffff', 'add r5, r4'] and ops[0]['opex']['units'] == [0x4dc8, 0x4dcc, 0x4dce]
    ops = json.loads(r2('e asm.cpu=usip;wx 0a5660203e606e14d000@0x7b74;aoj 2@0x7b74', 0x8000)[0])
    assert [o['opcode'] for o in ops] == ['and r5, r5, #0x10', '.3eX0? r6, 0x6e14 0xd000'] and ops[1]['size'] == 6 and ops[1]['opex']['form'] == 'x3eX0_q'
    # The 16-bit renames: lsl with S = 0, lsl? at k >= 1 with F = 1, sext16 / zext16 with F = 1, addi #32 next to cop.
    ops = json.loads(r2('e asm.cpu=usip;wx 144a20358338@0x128a;aoj 2@0x128a', 0x8000)[0])
    assert [o['opcode'] for o in ops] == ['movi r4, #0x519c', 'lsl r3, r0, #0x2'] and ops[1]['type'] == 'shl' and ops[1]['opex']['form'] == 'lsl16_S0'
    ops = json.loads(r2('e asm.cpu=usip;wx 060840057337000229b08570@0x1108;aoj 2@0x1108', 0x8000)[0])
    assert ops[0]['opcode'] == 'call.abs 0x1ccde9b0' and ops[1]['opcode'] == 'lsl? r0, r0, #0x1' and ops[1]['opex']['form'] == 'lsl16_F1_S0_k1_q'
    ops = json.loads(r2('e asm.cpu=usip;wx 0c8778e7e43d@0x65e;aoj 2@0x65e', 0x8000)[0])
    assert [o['opcode'] for o in ops] == ['slt r7, r6, r8', 'sext16 r3, r2'] and ops[1]['type'] == 'cast' and ops[1]['opex']['form'] == 'sext16_F1_c'
    ops = json.loads(r2('e asm.cpu=usip;wx 09077b27066a693d8a98@0x7d9e;aoj 3@0x7d9e', 0x8000)[0])
    assert ops[2]['opcode'] == 'zext16? r3, r4' and ops[2]['opex']['form'] == 'zext16_F1_S0_q' and ops[1]['opcode'] == 'movi r6, #0x1d4c'
    ops = json.loads(r2('e asm.cpu=usip;wx 001f5000c103@0x3338;aoj 2@0x3338', 0x8000)[0])
    assert [o['opcode'] for o in ops] == ['cop r0', 'addi r0, #32'] and ops[1]['type'] == 'add' and ops[1]['opex']['form'] == 'addi32_cop'
    # H1: a loose hi syllable is .hi only after a head of the 48-bit family (here the ld.w); movhi with the tt = 10
    # tail (the IEEE test); the .op4t0 shape is not a load.
    ops = json.loads(r2('e asm.cpu=usip;wx 1bb048c435d735ffb90c@0x2352;aoj 3@0x2352', 0x8000)[0])
    assert [o['opcode'] for o in ops] == ['ld.w r11!, [r13+0x8c4]', 'and r12, r10!, r13!', '.hi 0x35ff'] and ops[2]['opex']['form'] == 'hi1010_loose'
    ops = json.loads(r2('e asm.cpu=usip;wx 0218a016@0x627c;aoj 1@0x627c', 0x8000)[0])
    assert ops[0]['opcode'] == 'movhi r1, #0x4080b000' and ops[0]['val'] == 0x4080b000 and ops[0]['opex']['form'] == 'movhi_tt10_short'
    ops = json.loads(r2('e asm.cpu=usip;wx 0e33240750043872c819@0x7ee;aoj 3@0x7ee', 0x8000)[0])
    assert ops[2]['opcode'] == '.op4t0 r0, [r8+0x19]' and ops[2]['type'] == 'unk' and ops[0]['opcode'] == 'addi r7, #0x6'
    # Table update (687 forms): the F = S = 0 compare-and-branch cells with a known target as a validation filter: validated by
    # the session (the target is a packet start seen before), rejected (the target is inside a packet decoded before: the pair
    # falls through to two 16-bit ops instead of .word) and unknown backward (a conditional branch is not read unverified
    # backward); the R-br0 cells (head with F = 0 and the [0][1][tt] tail at +1 or +2) of bne.d / bleu.d / bge.d / beq.u8.d /
    # bgeu.d / bne.u8.d / ble.d, the bgt.d cell back in the table, and an unverified forward one.
    pk = 'wx 04094de7540ac044def9@0x2992;'
    ops = json.loads(r2('e asm.cpu=usip;wx 8000@0x2978;' + pk + 'aoj 1@0x2978;aoj 3@0x2992', 0x8000)[1])
    assert ops[0]['opcode'] == 'bne.d r2, #0x6, 0x00002978' and ops[0]['type'] == 'cjmp' and ops[0]['jump'] == 0x2978 and ops[0]['cond'] == 'ne'
    assert ops[0]['opex']['form'] == 'bne_imm8_f0s0' and ops[0]['opex']['target_guard'] == 'validated' and ops[0]['delay'] == 1 and ops[1]['opcode'] == 'movi r0, #0x5022'
    ops = json.loads(r2('e asm.cpu=usip;wx 00008000@0x2976;' + pk + 'aoj 1@0x2976;aoj 3@0x2992', 0x8000)[1])
    assert [o['opcode'] for o in ops] == ['add r2, r0', 'st.h r14, [r6]+', 'movi r0, #0x5022'] and ops[0]['size'] == 2
    ops = json.loads(r2('e asm.cpu=usip;' + pk + 'aoj 3@0x2992', 0x8000)[0])
    assert [o['opcode'] for o in ops] == ['add r2, r0', 'st.h r14, [r6]+', 'movi r0, #0x5022']
    ops = json.loads(r2('e asm.cpu=usip;wx 0c5c0801601c500c007a427701feb8014471d0007ffe42316d63d000@0x8a2;aoj 3@0x8a2', 0x8000)[0])
    assert ops[0]['opcode'] == 'bleu.d r6, r5, 0x000008be' and ops[0]['cond'] == 'ls' and ops[0]['opex']['form'] == 'bleu_rr_f0s0'
    assert ops[0]['opex']['target_guard'] == 'validated' and ops[0]['opex']['units'] == [0x8a2, 0x8a6] and ops[0]['delay'] == 7 and ops[1]['opcode'] == 'st.w r0, [r4+0xc]'
    ops = json.loads(r2('e asm.cpu=usip;wx 8000@0x652;wx 000a618dd4a6@0x6c6;aoj 1@0x652;aoj 2@0x6c6', 0x8000)[1])
    assert ops[0]['opcode'] == 'bge.d r0, #0x0, 0x00000652' and ops[0]['cond'] == 'ge' and ops[0]['opex']['form'] == 'bge_imm8_f0s0' and ops[1]['opcode'] == 'inc r10, r10'
    ops = json.loads(r2('e asm.cpu=usip;wx 1a181d215020504004d760573802ba1045045ad65002c0021a6c6ff97f07cfff@0x9a0;aoj 2@0x9a0', 0x8000)[0])
    assert ops[0]['opcode'] == 'beq.u8.d r13, #0x8, 0x000009c0' and ops[0]['cond'] == 'eq' and ops[0]['opex']['form'] == 'beq.u8_imm8_f0s0' and ops[0]['opex']['units'] == [0x9a0, 0x9a4]
    assert ops[1]['opcode'] == 'st.w r2!, [r14+0x40]' and ops[1]['opex']['delay_slot']
    ops = json.loads(r2('e asm.cpu=usip;wx 8000@0xaa0;wx 000a455dc207@0xb44;aoj 1@0xaa0;aoj 2@0xb44', 0x8000)[1])
    assert ops[0]['opcode'] == 'bgeu.d r0, #0x2, 0x00000aa0' and ops[0]['cond'] == 'hs' and ops[0]['opex']['form'] == 'bgeu_imm8_f0s0'
    ops = json.loads(r2('e asm.cpu=usip;wx 8000@0x1b32;wx 02f838144dd920c04200c004@0x1b5a;aoj 1@0x1b32;aoj 2@0x1b5a', 0x8000)[1])
    assert ops[0]['opcode'] == 'bne.u8.d r1, #0x7e, 0x00001b32' and ops[0]['opex']['form'] == 'bne.u8_imm8_f0s0' and ops[0]['opex']['units'] == [0x1b5a, 0x1b5e] and ops[1]['opcode'] == 'st.h r0, [r12+r1]'
    ops = json.loads(r2('e asm.cpu=usip;wx 00096434c08100095888c22f4009cbe0142063c4c2378406053814015e3423c4c02f1430000643d02402c0814009ca9e400ee3de4009d258@0x47cc;aoj 3@0x47cc', 0x8000)[0])
    assert ops[0]['opcode'] == 'ble.d r0, #0x2, 0x00004800' and ops[0]['opex']['form'] == 'ble_imm8_f0s0' and ops[0]['opex']['target_guard'] == 'validated'
    assert ops[2]['opcode'] == 'beq.d? r0, #0x4, 0x0000485a' and ops[2]['opex']['form'] == 'beq_imm8_d' and ops[2]['opex']['target_guard'] == 'unverified'
    ops = json.loads(r2('e asm.cpu=usip;wx 000a7624c0914009d23a4009c46a180053c0d417520d7f00c025800b5d69580123c0be794009d81e@0x3e06;aoj 2@0x3e06', 0x8000)[0])
    assert ops[0]['opcode'] == 'bgt.d r0, #0x3, 0x00003e2a' and ops[0]['cond'] == 'gt' and ops[0]['opex']['form'] == 'bgt_imm8_d' and ops[0]['opex']['target_guard'] == 'validated'
    ops = json.loads(r2('e asm.cpu=usip;wx 3e094268010762f72030b811@0xcca;aoj 3@0xcca', 0x8000)[0])
    assert ops[0]['opcode'] == 'bne.d? r15!, #0x1, 0x00000d32' and ops[0]['opex']['form'] == 'bne_imm8_f0s0' and ops[0]['opex']['target_guard'] == 'unverified'
    assert [o['opcode'] for o in ops[1:]] == ['mfcsr r0!, #0x30', 'add r1!, r1!, r15']
    # ret.s.d (1ef1 in the first slot, the rest of the packet its delay slot), movi rA, #-1 with F = 0, the 16-bit op 2 shifts
    # lsl / asr rA, #B (firm cells) and lsl? / asr? (the others), the open b.s validated by R-tgt: rejected when the target is
    # inside a packet decoded before, kept unverified when it is unknown.
    ops = json.loads(r2('e asm.cpu=usip;wx 1ef1a406@0x5168;aoj 2@0x5168', 0x8000)[0])
    assert [o['opcode'] for o in ops] == ['ret.s.d', 'mfacc r2, A0.lo'] and ops[0]['type'] == 'ret' and ops[0]['delay'] == 1 and ops[0]['opex']['form'] == 'ret_s_d'
    ops = json.loads(r2('e asm.cpu=usip;wx 01ff8207@0x1b56;aoj 2@0x1b56', 0x8000)[0])
    assert [o['opcode'] for o in ops] == ['movi r0, #-1', 'movi r1, #0x0'] and ops[0]['opex']['form'] == 'movi_m1_F0_S0' and ops[0]['type'] == 'mov'
    ops = json.loads(r2('e asm.cpu=usip;wx 8022@0x1028;aoj 1@0x1028', 0x8000)[0])
    assert ops[0]['opcode'] == 'lsl r0, #0x2' and ops[0]['type'] == 'shl' and ops[0]['opex']['form'] == 'lsl16_imm'
    ops = json.loads(r2('e asm.cpu=usip;wx 45f28479e5fe8c0b@0x7e50;aoj 1@0x7e50', 0x8000)[0])
    assert ops[0]['opcode'] == 'asr r2, #0xf' and ops[0]['type'] == 'sar' and ops[0]['opex']['form'] == 'asr16_imm'
    ops = json.loads(r2('e asm.cpu=usip;wx 4006c402@0x818;aoj 2@0x818', 0x8000)[0])
    assert ops[1]['opcode'] == 'lsl? r2, #0x0' and ops[1]['opex']['form'] == 'lsl16_imm_q' and ops[1]['opex']['confidence'] == 'medium'
    ops = json.loads(r2('e asm.cpu=usip;wx 8522@0x1000;aoj 1@0x1000', 0x8000)[0])
    assert ops[0]['opcode'] == 'asr? r2, #0x2' and ops[0]['opex']['form'] == 'asr16_imm_q'
    pk = 'wx 7c316612000204874000a03e@0x3856;'
    ops = json.loads(r2('e asm.cpu=usip;wx 7c217aa15008f000@0x37de;' + pk + 'aoj 1@0x37de;aoj 2@0x3856', 0x8000)[1])
    assert [o['opcode'] for o in ops] == ['mov r3, r14!', 'add.2 r1, r3!, #0x0']
    ops = json.loads(r2('e asm.cpu=usip;' + pk + 'aoj 1@0x3856', 0x8000)[0])
    assert ops[0]['opcode'] == 'b.s? 0x000037e2' and ops[0]['type'] == 'jmp' and ops[0]['opex']['form'] == 'b_s_open' and ops[0]['opex']['target_guard'] == 'unverified'
    # bz.s with bit 3 = 0 (context rule bz_s_P5): unconditional in a 2-unit packet, validated in longer ones (a self-target, a
    # forward target inside the lookahead) and left .hword when the target cannot be checked; the first-slot ldslot / stslot
    # with m = 1 (k >= 32) when the rest of the packet is named without a ?.
    ops = json.loads(r2('e asm.cpu=usip;wx 54458007@0x4f6e;aoj 2@0x4f6e', 0x8000)[0])
    assert ops[0]['opcode'] == 'bz.s r10, 0x00004f7e' and ops[0]['type'] == 'cjmp' and ops[0]['delay'] == 1 and ops[0]['opex']['form'] == 'bz_s_P5' and ops[1]['opcode'] == 'movi r0, #0x0'
    ops = json.loads(r2('e asm.cpu=usip;wx 4005400a3302422690c1@0x10c0;aoj 2@0x10c0', 0x8000)[0])
    assert ops[0]['opcode'] == 'bz.s r0, 0x000010c0' and ops[0]['opex']['target_guard'] == 'validated' and ops[0]['delay'] == 3 and ops[1]['opcode'] == 'ld.w r0, [r0+12]'
    pk = 'wx 4c750247f817'
    ops = json.loads(r2('e asm.cpu=usip;' + pk + '122a2f915141102479d7f9442649920be7417ffeef2f6f216fb1@0x1766;aoj 2@0x1766', 0x8000)[0])
    assert ops[0]['opcode'] == 'bz.s r6, 0x00001782' and ops[0]['opex']['target_guard'] == 'validated' and ops[1]['opcode'] == 'add r7!, r1, r4'
    ops = json.loads(r2('e asm.cpu=usip;' + pk + '@0x1766;aoj 2@0x1766', 0x8000)[0])
    assert ops[0]['opcode'] == '.hword 0x4c75' and ops[1]['opcode'] == 'add r7!, r1, r4'
    ops = json.loads(r2('e asm.cpu=usip;wx 72889821@0x4f04;aoj 2@0x4f04', 0x8000)[0])
    assert [o['opcode'] for o in ops] == ['ldslot r8, #0x33', 'mov r2, r12'] and ops[0]['type'] == 'load' and ops[0]['opex']['form'] == 'ldslot_S0_m1'
    ops = json.loads(r2('e asm.cpu=usip;wx 6c045848c020@0x361a;aoj 1@0x361a', 0x8000)[0])
    assert ops[0]['opcode'] == 'stslot r0, #0x2c' and ops[0]['type'] == 'store' and ops[0]['opex']['form'] == 'stslot_S0_m1'
    # Hardware loops: loop.b1? (B = 1) validated and unverified (its ss >= 2 twin), loop rX?ss=N; movi? #-32767; the asr16 clamp
    # with the same register on both sides.
    ops = json.loads(r2('e asm.cpu=usip;wx 0a1f08f7701c7b60300740073d03bac0024050024027fd0546f7fb63@0x4210;aoj 2@0x4210', 0x8000)[0])
    assert ops[0]['opcode'] == 'loop.b1? r5, last=0x0000422c' and ops[0]['ptr'] == 0x422c and ops[0]['opex']['form'] == 'loop_b1_q' and ops[0]['opex']['target_guard'] == 'validated'
    assert ops[0]['opex']['units'] == [0x4210, 0x4214] and ops[1]['opcode'] == 'lsr r0, r4, #0xf'
    ops = json.loads(r2('e asm.cpu=usip;wx 221f705cc029@0x25c2;aoj 1@0x25c2', 0x8000)[0])
    assert ops[0]['opcode'] == 'loop.b1?? r1?ss=2, last=0x0000261e' and ops[0]['opex']['form'] == 'loop_b1_q_ssq' and ops[0]['opex']['target_guard'] == 'unverified'
    ops = json.loads(r2('e asm.cpu=usip;wx 340f3816701c4008002a40078060e233a62a86994630c0244636f0024606cc02@0x22c6;aoj 1@0x22c6', 0x8000)[0])
    assert ops[0]['opcode'] == 'loop r2?ss=3, last=0x000022e2' and ops[0]['opex']['form'] == 'loop_ssq' and ops[0]['opex']['target_guard'] == 'validated'
    ops = json.loads(r2('e asm.cpu=usip;wx 040c202700a0c003@0x6214;aoj 2@0x6214', 0x8000)[0])
    assert ops[1]['opcode'] == 'movi? r2, #-32767' and ops[1]['opex']['form'] == 'movi_m32767_q' and ops[1]['opex']['units'] == [0x6216, 0x621a] and ops[0]['opcode'] == 'sub r0, r2, r0'
    ops = json.loads(r2('e asm.cpu=usip;wx 0007d4d4060cc0c0c161@0xc0a;aoj 2@0xc0a', 0x8000)[0])
    assert [o['opcode'] for o in ops] == ['asr16 r0, r0, #10', 'L_shr r0, r3, r0'] and ops[0]['opex']['form'] == 'asr16_clamp_u' and ops[0]['type'] == 'sar'
    # The bit-field family by H H T T pair (R-bfpair) and by cell (the BF_SEL renames of .bf?: fup, fup?, fxtu, fxtu?, fxts?).
    ops = json.loads(r2('e asm.cpu=usip;wx 063708471258d258@0x1fea;aoj 2@0x1fea', 0x8000)[0])
    assert [o['opcode'] for o in ops] == ['fxtu r3, r3, #0x12, #0xc', 'fxtu r4, r4, #0x12, #0xc'] and ops[0]['opex']['form'] == 'bfpair_fxtu' and ops[0]['opex']['units'] == [0x1fea, 0x1fee]
    ops = json.loads(r2('e asm.cpu=usip;wx 10071027187bd286@0x4f9c;aoj 2@0x4f9c', 0x8000)[0])
    assert [o['opcode'] for o in ops] == ['fup r0, r8, #0x3, #0x1d', 'fxtu r2, r8, #0x14, #0x3'] and ops[0]['opex']['form'] == 'bfpair_fup' and ops[1]['opex']['form'] == 'bfpair_fxtu'
    ops = json.loads(r2('e asm.cpu=usip;wx 0067d8305e0cc018@0x6ca6;aoj 1@0x6ca6', 0x8000)[0])
    assert ops[0]['opcode'] == 'fup r6, r0, #0x1, #0x8' and ops[0]['opex']['form'] == 'bfsel_fup' and ops[0]['type'] == 'or'
    ops = json.loads(r2('e asm.cpu=usip;wx 3be79961@0x735e;aoj 1@0x735e', 0x8000)[0])
    assert ops[0]['opcode'] == 'fup? r14!, r13!, #0xb, #0x10' and ops[0]['opex']['form'] == 'bfsel_fup_q' and ops[0]['opex']['confidence'] == 'low'
    ops = json.loads(r2('e asm.cpu=usip;wx 3fde78f94427d028@0x4b6e;aoj 2@0x4b6e', 0x8000)[0])
    assert ops[1]['opcode'] == 'fxtu r2, r2, #0x1, #0x4' and ops[1]['opex']['form'] == 'bfsel_fxtu' and ops[1]['type'] == 'cast'
    ops = json.loads(r2('e asm.cpu=usip;wx 0017d088@0x3344;aoj 1@0x3344', 0x8000)[0])
    assert ops[0]['opcode'] == 'fxtu? r1, r0, #0x4, #0x4' and ops[0]['opex']['form'] == 'bfsel_fxtu_q'
    ops = json.loads(r2('e asm.cpu=usip;wx 0017d510@0x666a;aoj 1@0x666a', 0x8000)[0])
    assert ops[0]['opcode'] == 'fxts? r1, r0, #0x8, #0x8' and ops[0]['opex']['form'] == 'bfsel_fxts_q'
    # The ld/st type 111 is ld.bu / st.b with the byte displacement (sext12 of the swapped bits, printed with its sign): the
    # plain F = S forms, the 2-unit head + tail packet with a named 16-bit tail (group b111) and the H H T T layout; ld.b /
    # st.h with F != S of op 1 exactly at +2 (at +1 the pair is undone).
    ops = json.loads(r2('e asm.cpu=usip;wx 5001f800ff05def9@0x122c;aoj 1@0x122c', 0x8000)[0])
    assert ops[0]['opcode'] == 'st.b r0, [r8+0x1]' and ops[0]['opex']['form'] == 'mem_st_b_t7_F1S1' and ops[0]['refptr'] == 1 and ops[0]['size'] == 4
    ops = json.loads(r2('e asm.cpu=usip;wx 09814802002a7d288040@0x234c;aoj 1@0x234c', 0x8000)[0])
    assert ops[0]['opcode'] == 'st.b r8!, [r4+0x529]' and ops[0]['opex']['form'] == 'mem_st_b_t7_F0S0' and ops[0]['opex']['units'] == [0x234c, 0x2352]
    ops = json.loads(r2('e asm.cpu=usip;wx 4001cf11@0x104e;aoj 1@0x104e', 0x8000)[0])
    assert ops[0]['opcode'] == 'ld.b r0, [r0-0xef]' and ops[0]['opex']['form'] == 'mem_ld_b_t4_F1S1' and dict(name='off', type='disp', value=-0xef) in ops[0]['opex']['operands']
    ops = json.loads(r2('e asm.cpu=usip;wx 5010f628@0x5a24;aoj 1@0x5a24', 0x8000)[0])
    assert ops[0]['opcode'] == 'ld.bu r1, [r8+0x628]' and ops[0]['opex']['form'] == 'b111_ld_bu_t7_F1S1' and ops[0]['type'] == 'load' and not ops[0].get('sign')
    ops = json.loads(r2('e asm.cpu=usip;wx 5c01f066@0x24d6;aoj 1@0x24d6', 0x8000)[0])
    assert ops[0]['opcode'] == 'st.b r0, [r14+0x66]' and ops[0]['opex']['form'] == 'b111_st_b_t7_F1S1'
    ops = json.loads(r2('e asm.cpu=usip;wx 4201422148daf0b2@0x153a;aoj 2@0x153a', 0x8000)[0])
    assert [o['opcode'] for o in ops] == ['ld.b r0, [r1+0xdb]', 'st.b r2, [r1+0xb2]'] and ops[0]['opex']['form'] == 'mem_ld_b_t4_F1S0' and ops[1]['opex']['form'] == 'b111_st_b_t7_F1S1'
    ops = json.loads(r2('e asm.cpu=usip;wx 52315211780ef010@0x1dd2;aoj 2@0x1dd2', 0x8000)[0])
    assert [o['opcode'] for o in ops] == ['st.b r3, [r9+0xf]', 'st.b r1, [r9+0x10]'] and ops[0]['opex']['form'] == 'b111_st_b_t7_F1S0'
    ops = json.loads(r2('e asm.cpu=usip;wx 522052a17802c800@0x75e8;aoj 2@0x75e8', 0x8000)[0])
    assert [o['opcode'] for o in ops] == ['ld.bu r2, [r9+0x3]', 'ld.b r10, [r9+0x1]'] and ops[0]['opex']['form'] == 'b111_ld_bu_t7_F1S0'
    ops = json.loads(r2('e asm.cpu=usip;wx 50110010400200008000@0x121a;aoj 2@0x121a', 0x8000)[0])
    assert ops[0]['opcode'] == 'ld.b r1, [r8+0x2]' and ops[0]['opex']['form'] == 'mem_ld_b_t4_F1S0' and ops[0]['opex']['units'] == [0x121a, 0x121e] and ops[1]['opcode'] == 'mov32 r1, #0x0'
    ops = json.loads(r2('e asm.cpu=usip;wx 501140028000@0x1300;aoj 1@0x1300', 0x8000)[0])
    assert ops[0]['opcode'] == 'mov r1, r8' and ops[0]['size'] == 2
    ops = json.loads(r2('e asm.cpu=usip;wx 4c114c816fffe014@0x1380;aoj 2@0x1380', 0x8000)[0])
    assert [o['opcode'] for o in ops] == ['st.h r1, [r6-0x2]', 'st.h r8, [r6+0x14]'] and ops[0]['opex']['form'] == 'mem_st_h_t6_F1S0' and ops[0]['opex']['units'] == [0x1380, 0x1384]
    # ld.h? / ld.hu? with the F' = 0 tail as the second head of H H T T (R-hhttF0) and by the deferred tail of a head with base
    # sp (R-F0d, the middle unit re-read as a first-slot 16-bit op); the sp adjustment pair add r14, r14, #imm (spfix);
    # ld.w? / st.w? of the f12 = 1 / 3 mod 4 classes (NEGQ); the immediate-store triple of 17+ bits (.stimm16?).
    ops = json.loads(r2('e asm.cpu=usip;wx 1400142050041006@0x2262;aoj 2@0x2262', 0x8000)[0])
    assert [o['opcode'] for o in ops] == ['ld.h r0, [r10+0x4]', 'ld.h? r2, [r10+0x6]'] and ops[1]['opex']['form'] == 'hhttF0_ld_h_q' and ops[1]['opex']['units'] == [0x2264, 0x2268]
    ops = json.loads(r2('e asm.cpu=usip;wx 1420144060282004@0x2974;aoj 2@0x2974', 0x8000)[0])
    assert [o['opcode'] for o in ops] == ['ld.hu r2, [r10+0x28]', 'ld.hu? r4, [r10+0x4]'] and ops[1]['opex']['form'] == 'hhttF0_ld_hu_q'
    ops = json.loads(r2('e asm.cpu=usip;wx 5c0042542098ca07@0x2edc;aoj 2@0x2edc', 0x8000)[0])
    assert ops[0]['opcode'] == 'ld.hu? r0, [r14+0x98]' and ops[0]['opex']['form'] == 'rf0d_ld_hu_q' and ops[0]['opex']['units'] == [0x2edc, 0x2ee0] and ops[0]['stack'] == 'get'
    ops = json.loads(r2('e asm.cpu=usip;wx 5c50707211e2000b8443@0x4c00;aoj 2@0x4c00', 0x8000)[0])
    assert [o['opcode'] for o in ops] == ['ld.h? r5, [r14+0x1e2]', 'add.2 r7, r8!, #-0x1fb'] and ops[0]['opex']['form'] == 'rf0d_ld_h_q'
    ops = json.loads(r2('e asm.cpu=usip;wx 008f1cf0500000005ce0c008@0x678;aoj 5@0x678', 0x8000)[0])
    assert ops[4]['opcode'] == 'add r14, r14, #0x4' and ops[4]['opex']['form'] == 'spfix_add_sp' and ops[4]['type'] == 'add' and ops[4]['stack'] == 'inc' and ops[4]['stackptr'] in (-4, (1 << 64) - 4)
    ops = json.loads(r2('e asm.cpu=usip;wx 202032354305a134@0x1398;aoj 1@0x1398', 0x8000)[0])
    assert ops[0]['opcode'] == 'ld.w? r2, [r0!+0x305]' and ops[0]['opex']['form'] == 'negq_ld_w_c1' and ops[0]['opex']['units'] == [0x1398, 0x139c]
    ops = json.loads(r2('e asm.cpu=usip;wx 663265573b1200506707407f79f0bfff@0x714;aoj 3@0x714', 0x8000)[0])
    assert ops[2]['opcode'] == 'ld.w? r5, [r0+0x7f]' and ops[2]['opex']['form'] == 'negq_ld_w_c3'
    ops = json.loads(r2('e asm.cpu=usip;wx 001150351210502812716688c868@0x2f42;aoj 1@0x2f42', 0x8000)[0])
    assert ops[0]['opcode'] == 'st.w? r1, [r0+0x35]' and ops[0]['opex']['form'] == 'negq_st_w_c1' and ops[0]['type'] == 'store'
    ops = json.loads(r2('e asm.cpu=usip;wx 4608729108324000600de688@0x7c3e;aoj 2@0x7c3e', 0x8000)[0])
    assert ops[1]['opcode'] == '.stimm16? [r0], #0x36688' and ops[1]['size'] == 6 and ops[1]['type'] == 'unk' and ops[1]['opex']['form'] == 'stimm16_q_F1'
    ops = json.loads(r2('e asm.cpu=usip;wx 0110080f600aaccc@0x4c52;aoj 2@0x4c52', 0x8000)[0])
    assert ops[0]['opcode'] == '.stimm16? [r1!], #0x2accc' and ops[0]['opex']['form'] == 'stimm16_q_F0_x1' and ops[0]['opex']['units'] == [0x4c52, 0x4c56, 0x4c58] and ops[1]['opcode'] == 'movi r4, #0x1'
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
