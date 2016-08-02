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
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	See the
  GNU General Public License for more details.
  You should have received a copy of the GNU General Public License
  along with yaAGC; if not, write to the Free Software
  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA	02111-1307	USA

  Filename:  asm_agc.c
  Purpose:	 Source file for AGC Disassembler integrated in radare2.
  Contact:	 Inokentiy Babushkin
  Reference: http://www.ibiblio.org/apollo
  Mods:		 08/31/08 OH. Began.
			 07/12/16 IB. Began refactoring to include in radare2-extras.
			 07/17/16 IB. Annotated disassembler source and added symbolic
						  constants.
*/

#include <stdbool.h>
#include "asm.h"

const char *agc_mnemonics[59] = {
	// 3-bit opcode, no operand
	"com", "ddoubl", "double", "dtcb", "dtcf", "extend", "inhint", "noop",
	"ovsk", "relint", "resume", "return", "tcaa", "xlq", "xxalq", "zl",
	// 3-bit opcode, w/ operand
	"tc %04o", "ccs %04o", "tcf %04o", "das %04o", "lxch %04o",
	"incr %04o", "ads %04o", "ca %04o", "cs %04o", "index %04o",
	"dxch %04o", "ts %04o", "xch %04o", "ad %04o", "mask %04o",
	// 4-bit opcode, no operand
	"dcom", "resume", "square", "zq",
	// 4-bit opcode, w/ small operand
	"read %03o", "write %03o", "rand %03o", "wand %03o", "ror %03o",
	"wor %03o", "rxor %03o", "edrupt %03o",
	// 4-bit opcode, w/ normal operand
	"dv %04o", "bzf %04o", "msu %04o", "qxch %04o", "aug %04o",
	"dim %04o", "dca %04o", "dcs %04o", "index %04o", "su %04o",
	"bzmf %04o", "mp %04o"
};

// decode a 3-bit opcode
static void decode_no_extra_opcode_bit(
		agc_insn_t *insn, ut16 value, ut16 nop_value) {
	// first, special cases that have their own mnemonics
	if (value == 040000) { // i = 100, o = 0
		// complement the A register (address 0)
		insn->type = AGC_INSN_COM;
	} else if (value == 020001) { // i = 010, o = 0, 1
		// add the A, L register pair to itself (addresses 0 and 1)
		insn->type = AGC_INSN_DDOUBL;
	} else if (value == 060000) { // i = 110, o = 0
		// add the A register to itself (address 0o)
		insn->type = AGC_INSN_DOUBLE;
	} else if (value == 052006) {
		// change adressing, see manual
		insn->type = AGC_INSN_DTCB;
	} else if (value == 052005) {
		// change adressing, see manual
		insn->type = AGC_INSN_DTCF;
	} else if (value == 6) {
		// set extracode flag for next instruction, and the instruction
		// after that, if it is an index.
		insn->type = AGC_INSN_EXTEND;
	} else if (value == 4) {
		// disable interrupts
		insn->type = AGC_INSN_INHINT;
	} else if (value == nop_value && value != 010000) {
		// do nothing
		insn->type = AGC_INSN_NOOP;
	} else if (value == 054000) {
		// skip the next instruction if A is overflown
		insn->type = AGC_INSN_OVSK;
	} else if (value == 3) {
		// enable interrupts after an inhint
		insn->type = AGC_INSN_RELINT;
	} else if (value == 050017) {
		// resume program from an ISR
		insn->type = AGC_INSN_RESUME;
	} else if (value == 2) {
		// return from subroutine, which is to say, move the Q register
		// into the Z register.
		insn->type = AGC_INSN_RETURN;
	} else if (value == 054005) { // essentially a `TS Z`
		// jump to the address stored in the A register
		insn->type = AGC_INSN_TCAA;
	} else if (value == 1) { // essentially a `TC L`
		// convoluted control flow primitive from hell, see manual: load an
		// instruction in the `A` register, and a return instruction into
		// the `L` register, call `XLQ` and you will execute the contents
		// of `A` and return.
		insn->type = AGC_INSN_XLQ;
	} else if (value == 0) { // essentially `TC A`
		// similar to the above, but with extracode: load an `EXTEND`
		// instruction into the `A` register, an extracode instruction into
		// the `L` register, a return instruction into the `Q` register and
		// call `XXALQ`. This results in the execution of the given
		// extracode instruction.
		insn->type = AGC_INSN_XXALQ;
	} else if (value == 022007) { // essentially `LXCH 7`
		// zero the `L` register, by exchanging it's content with the 7th
		// register, which is hardwired to zero.
		insn->type = AGC_INSN_ZL;
	} else {
		switch (value & SWITCH_MASK) {
		// from now on, we have instructions with operands, so switch based
		// on the first three bits.
		case 000000: // i = 000, o = address of subroutine
			// call a subroutine (this can't be nested, because it stores
			// the current contents of the `Z` register in the `Q`
			// register).
			insn->type = AGC_INSN_TC;
			insn->operand = value & LOWER_WIDE;
			break;
		case 010000: // i = 001
			// one of the many space-saving tricks employed
			if (value & HIGHER) {
				// jump to a memory location
				// (12 bit address in fixed memory)
				insn->type = AGC_INSN_TCF;
				insn->operand = value & LOWER_WIDE;
			} else {
				// weird compare and jump (10 bit address in erasable
				// memory)
				insn->type = AGC_INSN_CCS;
				insn->operand = value & LOWER;
			}
			break;
		case 020000: // i = 010
			switch (value & HIGHER) { // lower bits...
			case 00000:
				// add the `A`, `L` register pair to a memory location
				insn->type = AGC_INSN_DAS;
				insn->operand = (value - 1) & LOWER;
				break;
			case 02000:
				// exchange the `L` register and a memory location
				insn->type = AGC_INSN_LXCH;
				insn->operand = value & LOWER;
				break;
			case 04000:
				// increment a memory location
				insn->type = AGC_INSN_INCR;
				insn->operand = value & LOWER;
				break;
			case 06000:
				// add the `A` register to a memory location
				insn->type = AGC_INSN_ADS;
				insn->operand = value & LOWER;
				break;
			}
			break;
		case 030000: // i = 011
			// move a memory location's contents into the `A` register
			insn->type = AGC_INSN_CA;
			insn->operand = value & LOWER_WIDE;
			break;
		case 040000: // i = 100
			// move a memory location's complement into the `A` register
			insn->type = AGC_INSN_CS;
			insn->operand = value & LOWER_WIDE;
			break;
		case 050000: // i = 101
			switch (value & HIGHER) { // lower bits again...
			case 00000:
				// adds the contents of a memory location to the next
				// instruction before it is executed, without altering
				// memory
				insn->type = AGC_INSN_INDEX;
				insn->operand = value & LOWER;
				break;
			case 02000:
				// exchange double precision int with `A`, `L` register
				// pair
				insn->type = AGC_INSN_DXCH;
				insn->operand = (value - 1) & LOWER;
				break;
			case 04000:
				// copy the contents of the `A` register to memory,
				// with extra magic when overflow occured.
				insn->type = AGC_INSN_TS;
				insn->operand = value & LOWER;
				break;
			case 06000:
				// exchange an erasable memory location with the `A`
				// register
				insn->type = AGC_INSN_XCH;
				insn->operand = value & LOWER;
				break;
			}
			break;
		case 060000: // i = 110
			// add a memory location to the `A` register
			insn->type = AGC_INSN_AD;
			insn->operand = value & LOWER_WIDE;
			break;
		case 070000: // i = 111
			// logical and between the `A` register and a memory location
			insn->type = AGC_INSN_MASK;
			insn->operand = value & LOWER_WIDE;
			break;
		}
	}
}

static void decode_extra_opcode_bit(agc_insn_t *insn, ut16 value) {
	if (value == 040001) { // basically a `DCS A`
		// bitwise complement of the register pair `A`, `L`
		insn->type = AGC_INSN_DCOM;
	} else if (value == 050017) {
		// FIXME: wtf is this here? see manual...
		// resume program from an ISR
		insn->type = AGC_INSN_RESUME;
	} else if (value == 070000) { // essentially `MP A`
		// square the contents of register `A`
		insn->type = AGC_INSN_SQUARE;
	} else if (value == 022007) { // essentially `QXCH 7`
		// zero the `Q` register, by exchanging it's content with the 7th
		// register, which is hardwired to zero.
		insn->type = AGC_INSN_ZQ;
	} else {
		switch (value & SWITCH_MASK) {
		case 000000: // i = 000
			insn->operand = value & 0777;
			switch (value & 07000) { // lower bits
			case 00000:
				// read a 9 bit IO channel into register `A`
				insn->type = AGC_INSN_READ;
				break;
			case 01000:
				// write register `A` into a 9 bit IO channel
				insn->type = AGC_INSN_WRITE;
				break;
			case 02000:
				// read and bitwise and
				insn->type = AGC_INSN_RAND;
				break;
			case 03000:
				// read and bitwise and with writeback
				insn->type = AGC_INSN_WAND;
				break;
			case 04000:
				// read and bitwise or
				insn->type = AGC_INSN_ROR;
				break;
			case 05000:
				// read and bitwise or with writeback
				insn->type = AGC_INSN_WOR;
				break;
			case 06000:
				// read and xor
				insn->type = AGC_INSN_RXOR;
				break;
			case 07000:
				// noone knows o__O
				insn->type = AGC_INSN_EDRUPT;
				break;
			}
			break;
		case 010000: // i = 001
			if (value & HIGHER) {
				// branch to a fixed memory location if `A` equals 0
				insn->type = AGC_INSN_BZF;
				insn->operand = value & LOWER_WIDE;
			} else{ 
				// divide register pair `A`, `L` by a memory location,
				// putting the quotient/remainder in `A`, `L`, respectively
				insn->type = AGC_INSN_DV;
				insn->operand = value & LOWER;
			}
			break;
		case 020000: // i = 010
			insn->operand = value & LOWER;
			switch (value & HIGHER) {
			case 00000:
				// 1's complement difference between two 2's complement
				// values of which the first is the register `A`
				insn->type = AGC_INSN_MSU;
				break;
			case 02000:
				// exchange `Q` register with memory location
				insn->type = AGC_INSN_QXCH;
				break;
			case 04000:
				// increment positive and decrement negative values at
				// a memory location, using 1's complement
				insn->type = AGC_INSN_AUG;
				break;
			case 06000:
				// other way 'round
				insn->type = AGC_INSN_DIM;
				break;
			}
			break;
		case 030000: // i = 011
			// move a pair of registers into `A` and `L`
			insn->type = AGC_INSN_DCA;
			insn->operand = (value - 1) & LOWER_WIDE;
			break;
		case 040000: // i = 100
			// move the complement of a pair of registers into `A` and `L`
			insn->type = AGC_INSN_DCS;
			insn->operand = (value - 1) & LOWER_WIDE;
			break;
		case 050000: // i = 101
			// see above
			insn->type = AGC_INSN_INDEX;
			insn->operand = (value - 1) & LOWER_WIDE;
			// reset bit
			break;
		case 060000: // i = 110
			if (value & HIGHER) {
				// branch to a fixed memory location if `A` is equal or
				// less than 0
				insn->type = AGC_INSN_BZMF;
				insn->operand = value & LOWER_WIDE;
			} else {
				// subtract a memory location from the `A` register
				insn->type = AGC_INSN_SU;
				insn->operand = value & LOWER;
			}
			break;
		case 070000: // i = 111
			// multiply two single precision values to form a double
			// precision value, of which one is the accumulator.
			insn->type = AGC_INSN_MP;
			insn->operand = value & LOWER_WIDE;
			break;
		}
	}
}

void disasm_agc_insn(agc_insn_t *insn, unsigned int address, ut16 value, bool shift) {
	// See http://www.ibiblio.org/apollo/assembly_language_manual.html
	// for instruction set documentation and other valuable info.

	// extracode flag saved between invocations
	static bool extra_opcode_bit = false;

	// distinguish between RW and RO memory
	bool erasable = false;
	if (address < 02000) {
		erasable = true;
	}

	// shift data one bit to the right if we work with memory as it was stored
	// on the original AGC hardware.
	if (shift) {
		value <<= 1;
	}

	if (extra_opcode_bit) {
		// the previous instruction was an `EXTEND`. This means we will
		// interpret not three, but four leading bits of our intruction as an
		// opcode. This was added to the second-generation AGC, after it became
		// clear that three bits for an opcode are not enough.
		extra_opcode_bit = false;
		decode_extra_opcode_bit (insn, value);
		if (insn->type == AGC_INSN_EXTEND) {
			extra_opcode_bit = true;
		}
	} else {
		// simple instructions below - encoded as follows: x iii ooo ooo ooo
		// where x is the odd-parity bit, which is used only by the hardware
		// itself to determine error conditions. However, yaYUL doesn't emulate
		// it, so things are shifted one bit to the left. This behaviour is
		// configurable, just in case.

		// NOOP's are special:
		// they are encoded as 10000 + current adress in fixed memory...
		// (which is a jump to the next instruction)
		// ...and as a constant value in erasable memory, because the jump
		// method isn't applicable. Note that this way of encoding it means
		// loading the accumulator (A) with itself.
		ut16 nop_value = 010000;
		if (erasable) {
			nop_value = 030000;
		} else if (value == address + 1) {
			nop_value = value;
		}
		decode_no_extra_opcode_bit (insn, value, nop_value);
		if (insn->type == AGC_INSN_EXTEND) {
			extra_opcode_bit = true;
		}
	}
}
