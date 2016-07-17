/*
  Copyright 2003-2006 Ronald S. Burkey <info@sandroid.org>,
            2008 Onno Hommes
            2016 Inokentiy Babushkin

  This file is based on the implmentation found in yaAGC, but modified for new
  purposes.

  This file is part of yaAGC / radare2-extras.
  yaAGC is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.
  yaAGC is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.
  You should have received a copy of the GNU General Public License
  along with yaAGC; if not, write to the Free Software
  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

  Filename:  agc_disassembler.h
  Purpose:   Source file for AGC Disassembler.
  Contact:   Onno Hommes
  Reference: http://www.ibiblio.org/apollo
  Mods:      08/31/08 OH. Began.
             07/12/16 IB. Began refactoring to include in radare2-extras.
*/

#include <stdbool.h>
#include <stdio.h>
#include "asm_agc.h"

/* 
 * We need to find out what the logic behind the modifications done by
 * ShowAddressContents() is. Since that function performs some lookup
 * on the internal state of the AGC *simulator*, it is very well possible
 * we can simplify things a fair bit. This would also mean that we might be
 * able to reduce the decoding work to interpreting the EXTEND instruction
 * as a prefix, since that's it's only function as far as we know so far.
 *
 * However, if the assembling/disassembling doesn't yield the desired
 * results, we will be in deep trouble already.
 *
 * So far, the best thing to do is to document the functionality of the
 * different static variables employes:
 * * sCurrentZ: the current address to be disassembled.
 *   It appears that they are handled differently depending on their value.
 *   For instance, the bank gets computed using them (duh).
 * * sBank: the memory bank the address maps to.
 *   Memory bank addressing was used because of storage shortage for
 *   adresses, which led to this workaround. Banks have different sizes
 *   (1K or 256 bytes), thus they get used differently in the code.
 * * sValue: the memory value at the location denoted by the address.
 * * sErasable: whether the data we access is in erasable memory.
 * * sFixed: whether we are reading from ROM.
 *
 * But why are we using two variables to denote mutually exclusive flags?
 *
 * We can get the current address from the RAsm structure pointer passed
 * to disassemble(). Thus, we can compute erasable and fixed.
 *
 * NOP's seem to be encoded in a position-depend way, but that's all we
 * need to handle specially.
 */

#define SWITCH_MASK 070000
#define LOWER_WIDE 07777
#define LOWER 01777
#define HIGHER 06000


void disasm_instruction(unsigned int address, int value, char *buf, int len) {
    static bool extra_opcode_bit = false;
    // distinguish between RW and RO memory
    bool erasable = false;
    if (address < 02000)
        erasable = true;

    // instruction encoding is pretty convoluted, since it doesn't work well with
    // byte boundaries. Thus, every decoding operation below is about to get proper
    // documentation to allow for better understanding (to write the ESIL and ANAL
    // bits still needed).
    // also see http://www.ibiblio.org/apollo/assembly_language_manual.html

    if (!extra_opcode_bit) {
        // simple instructions below - encoded as follows: x iii ooo ooo ooo
        // where x is the odd-parity bit, which is used only by the hardware itself
        // to determine error conditions. However, yaYUL doesn't emulate it, so things
        // are shifted one bit to the left. TODO: maybe we should change this?

        // first, special cases that have their own mnemonics
        if (value == 040000) // i = 100, o = 0
            // complement the A register (address 0)
            snprintf(buf, len, "com");
        else if (value == 020001) // i = 010, o = 0, 1
            // add the A, L register pair to itself (addresses 0 and 1)
            snprintf(buf, len, "ddoubl");
        else if (value == 060000) // i = 110, o = 0
            // add the A register to itself (address 0o)
            snprintf(buf, len, "double");
        else if (value == 052006)
            // change adressing, see manual
            snprintf(buf, len, "dtcb");
        else if (value == 052005)
            // change adressing, see manual
            snprintf(buf, len, "dtcf");
        else if (value == 6) {
            // set extracode flag for next instruction, and the instruction after that,
            // if it is an index.
            snprintf(buf, len, "extend");
            extra_opcode_bit = true;
        } else if (value == 4)
            // disable interrupts
            snprintf(buf, len, "inhint");
        else if (!erasable && value == address + 1 && value != 10000)
            // NOOP's are special:
            // they are encoded as 10000 + current adress in fixed memory...
            // (which is a jump to the next instruction)
            snprintf(buf, len, "noop");
        else if (erasable && value == 030000)
            // ...and as a constant value in erasable memory, because the jump method
            // isn't applicable. Note that this way of encoding it means loading the
            // accumulator (A) with itself.
            snprintf(buf, len, "noop");
        else if (value == 054000)
            // skip the next instruction if A is overflown
            snprintf(buf, len, "ovsk");
        else if (value == 3)
            // enable interrupts after an inhint
            snprintf(buf, len, "relint");
        else if (value == 050017)
            // resume program from an ISR
            snprintf(buf, len, "resume");
        else if (value == 2)
            // return from subroutine, which is to say, move the Q register
            // into the Z register.
            snprintf(buf, len, "return");
        else if (value == 054005) // essentially a `TS Z`
            // jump to the address stored in the A register
            snprintf(buf, len, "tcaa");
        else if (value == 1) // essentially a `TC L`
            // convoluted control flow primitive from hell, see manual:
            // load an instruction in the `A` register, and a return instruction into
            // the `L` register, call `XLQ` and you will execute the contents of `A`
            // and return.
            snprintf(buf, len, "xlq");
        else if (value == 0) // essentially `TC A`
            // similar to the above, but with extracode:
            // load an `EXTEND` instruction into the `A` register, an extracode
            // instruction into the `L` register, a return instruction into the `Q`
            // register and call `XXALQ`. This results in the execution of the given
            // extracode instruction.
            snprintf(buf, len, "xxalq");
        else if (value == 022007) // essentially `LXCH 7`
            // zero the `L` register, by exchanging it's content with the 7th register,
            // which is hardwired to zero.
            snprintf(buf, len, "zl");
        else switch (value & SWITCH_MASK) {
            // from now on, we have instructions with operands, so switch based on
            // the first three bits.
            case 000000: // i = 000, o = address of subroutine
                // call a subroutine (this can't be nested, because it stores the
                // current contents of the `Z` register in the `Q` register).
                snprintf(buf, len, "tc\t%04o", value & LOWER_WIDE);
                break;
            case 010000: // i = 001
                if (!(value & 06000)) // one of the many space-saving tricks employed
                    // weird compare and jump (10 bit address in erasable memory)
                    snprintf(buf, len, "ccs\t%04o",value & LOWER);
                else
                    // jump to a memory location (12 bit address in fixed memory)
                    snprintf(buf, len, "tcf\t%04o", value & LOWER_WIDE);
                break;
            case 020000: // i = 010
                switch (value & 06000) { // lower bits...
                    case 00000:
                        // add the `A`, `L` register pair to a memory location
                        snprintf(buf, len, "das\t%04o", (value - 1) & LOWER);
                        break;
                    case 02000:
                        // exchange the L register and a memory location
                        snprintf(buf, len, "lxch\t%04o", value & LOWER);
                        break;
                    case 04000:
                        // increment a memory location
                        snprintf(buf, len, "incr\t%04o", value & LOWER);
                        break;
                    case 06000:
                        // add the `A` register to a memory location
                        snprintf(buf, len, "ads\t%04o", value & LOWER);
                        break;
                }
                break;
            case 030000: // i = 011
                // move a memory location's contents into the `A` register
                snprintf(buf, len, "ca\t%04o", value & LOWER_WIDE);
                break;
            case 040000: // i = 100
                // move a memory location's complement into the `A` register
                snprintf(buf, len, "cs\t%04o", value & LOWER_WIDE);
                break;
            case 050000: // i = 101
                switch (value & HIGHER) { // lower bits again...
                    case 00000:
                        // adds the contents of a memory location to the next
                        // instruction before it is executed, without altering memory
                        snprintf(buf, len, "index\t%04o", value & LOWER);
                        break;
                    case 02000:
                        // exchange double precision int with `A`, `L` register pair
                        snprintf(buf, len, "dxch\t%04o", (value - 1) & LOWER);
                        break;
                    case 04000:
                        // copy the contents of the `A` register to memory, with extra
                        // magic when overflow occured.
                        snprintf(buf, len, "ts\t%04o", value & LOWER);
                        break;
                    case 06000:
                        // exchange an erasable memory location with the `A` register
                        snprintf(buf, len, "xch\t%04o", value & LOWER);
                        break;
                }
                break;
            case 060000: // i = 110
                // add a memory location to the `A` register
                snprintf(buf, len, "ad\t%04o", value & LOWER_WIDE);
                break;
            case 070000: // i = 111
                // logical and between the `A` register and a memory location
                snprintf(buf, len, "mask\t%04o", value & LOWER_WIDE);
                break;
        }
    } else {
        // the previous instruction was an `EXTEND`. This means we will interpret
        // not three, but four leading bits of our intruction as an opcode. This
        // was added to the second-generation AGC, after it became clear that three
        // bits for an opcode are not enough.
        extra_opcode_bit = false;
        if (value == 040001) // basically a `DCS A`
            // bitwise complement of the register pair `A`, `L`
            snprintf(buf, len, "dcom");
        else if (value == 050017) // 
            // resume program from an ISR
            snprintf(buf, len, "resume"); // FIXME: wtf is this here? see manual...
        else if (value == 070000) // essentially `MP A`
            // square the contents of register `A`
            snprintf(buf, len, "square");
        else if (value == 022007) // essentially `QXCH 7`
            // zero the `Q` register, by exchanging it's content with the 7th register,
            // which is hardwired to zero.
            snprintf(buf, len, "zq");
        else switch (value & SWITCH_MASK) {
            case 000000: // i = 000
                switch (value & 07000) { // lower bits
                    case 00000:
                        // read a 9 bit IO channel into register `A`
                        snprintf(buf, len, "read\t%03o", value & 0777);
                        break;
                    case 01000:
                        // write register `A`into a 9 bit IO channel
                        snprintf(buf, len, "write\t%03o", value & 0777);
                        break;
                    case 02000:
                        // read and bitwise and
                        snprintf(buf, len, "rand\t%03o", value & 0777);
                        break;
                    case 03000:
                        // read and bitwise and with writeback
                        snprintf(buf, len, "wand\t%03o", value & 0777);
                        break;
                    case 04000:
                        // read and bitwise or
                        snprintf(buf, len, "ror\t%03o", value & 0777);
                        break;
                    case 05000:
                        // read and bitwise or with writeback
                        snprintf(buf, len, "wor\t%03o", value & 0777);
                        break;
                    case 06000:
                        // read and xor
                        snprintf(buf, len, "rxor\t%03o", value & 0777);
                        break;
                    case 07000:
                        // noone knows o__O
                        snprintf(buf, len, "edrupt\t%03o", value & 0777);
                        break;
                }
                break;
            case 010000: // i = 001
                if (!(value & HIGHER))
                    // divide register pair `A`, `L` by a memory location,
                    // putting the quotient/remainder in `A`, `L`, respectively
                    snprintf(buf, len, "dv\t%04o", value & LOWER);
                else
                    // branch to a fixed memory location if `A` equals 0
                    snprintf(buf, len, "bzf\t%04o", value & LOWER_WIDE);
                break;
            case 020000: // i = 010
                switch (value & HIGHER) {
                    case 00000:
                        // 1's complement difference between two 2's complement values
                        // of which the first is the register `A`
                        snprintf(buf, len, "msu\t%04o", value & LOWER);
                        break;
                    case 02000:
                        // exchange `Q` register with memory location
                        snprintf(buf, len, "qxch\t%04o", value & LOWER);
                        break;
                    case 04000:
                        // increrement positive and decrement negative values at a
                        // memory location, using 1's complement
                        snprintf(buf, len, "aug\t%04o", value & LOWER);
                        break;
                    case 06000:
                        // other way 'round
                        snprintf(buf, len, "dim\t%04o", value & LOWER);
                        break;
                }
                break;
            case 030000: // i = 011
                // move a pair of registers into `A` and `L`
                snprintf(buf, len, "dca\t%04o", (value - 1) & LOWER_WIDE);
                break;
            case 040000: // i = 100
                // move the complement of a pair of registers into `A` and `L`
                snprintf(buf, len, "dcs\t%04o", (value - 1) & LOWER_WIDE);
                break;
            case 050000: // i = 101
                // see above
                snprintf(buf, len, "index\t%04o", value & LOWER_WIDE);
                // reset bit
                extra_op_code_bit = true;
                break;
            case 060000: // i = 110
                if (!(value & HIGHER))
                    // subtract a memory location from the `A` register
                    snprintf(buf, len, "su\t%04o", value & LOWER);
                else
                    // branch to a fixed memory location if `A` is equal or less than 0
                    snprintf(buf, len, "bzmf\t%04o", value & LOWER_WIDE);
                break;
            case 070000: // i = 111
                // multiply two single precision values to form a double precision
                // value, of which one is the accumulator.
                snprintf(buf, len, "mp\t%04o", value & LOWER_WIDE);
                break;
        }
    }
}
