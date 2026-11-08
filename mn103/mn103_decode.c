/* radare2 - GPL-3.0-or-later - Copyright 2026 - n0p */
/* MN10300 / AM33 decoder: the length rule, the first-match lookup and the operand extraction follow
 * GNU binutils opcodes/m10300-dis.c (print_insn_mn10300 / disassemble) step by step so that the output
 * agrees with objdump; only the number formatting differs. */

#include "mn103_decode.h"

static const char *const mn103_dregs[4] = { "d0", "d1", "d2", "d3" };
static const char *const mn103_aregs[4] = { "a0", "a1", "a2", "a3" };
static const char *const mn103_rregs[16] = {
	"r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7",
	"a0", "a1", "a2", "a3", "d0", "d1", "d2", "d3"
};
static const char *const mn103_xrregs[16] = {
	"sp", "xr1", "xr2", "xr3", "xr4", "xr5", "xr6", "xr7",
	"xr8", "xr9", "xr10", "xr11", "xr12", "xr13", "xr14", "xr15"
};
static const char *const mn103_fsregs[32] = {
	"fs0", "fs1", "fs2", "fs3", "fs4", "fs5", "fs6", "fs7", "fs8", "fs9", "fs10", "fs11", "fs12", "fs13", "fs14", "fs15",
	"fs16", "fs17", "fs18", "fs19", "fs20", "fs21", "fs22", "fs23", "fs24", "fs25", "fs26", "fs27", "fs28", "fs29", "fs30", "fs31"
};
static const char *const mn103_fdregs[32] = {
	"fd0", "fd1", "fd2", "fd3", "fd4", "fd5", "fd6", "fd7", "fd8", "fd9", "fd10", "fd11", "fd12", "fd13", "fd14", "fd15",
	"fd16", "fd17", "fd18", "fd19", "fd20", "fd21", "fd22", "fd23", "fd24", "fd25", "fd26", "fd27", "fd28", "fd29", "fd30", "fd31"
};

int mn103_insn_size(ut8 insn) {
	if ((insn & 0xf3) == 0x00 || (insn & 0xf0) == 0x10 || (insn & 0xfc) == 0x3c || (insn & 0xf3) == 0x41
		|| (insn & 0xf3) == 0x40 || (insn & 0xfc) == 0x50 || (insn & 0xfc) == 0x54 || (insn & 0xf0) == 0x60
		|| (insn & 0xf0) == 0x70
		|| ((insn & 0xf0) == 0x80 && (insn & 0x0c) >> 2 != (insn & 0x03))
		|| ((insn & 0xf0) == 0x90 && (insn & 0x0c) >> 2 != (insn & 0x03))
		|| ((insn & 0xf0) == 0xa0 && (insn & 0x0c) >> 2 != (insn & 0x03))
		|| ((insn & 0xf0) == 0xb0 && (insn & 0x0c) >> 2 != (insn & 0x03))
		|| insn == 0xcb || (insn & 0xfc) == 0xd0 || (insn & 0xfc) == 0xd4 || (insn & 0xfc) == 0xd8
		|| (insn & 0xf0) == 0xe0 || insn == 0xff) {
		return 1;
	}
	if ((insn & 0xf0) == 0x80 || (insn & 0xf0) == 0x90 || (insn & 0xf0) == 0xa0 || (insn & 0xf0) == 0xb0
		|| (insn & 0xfc) == 0x20 || (insn & 0xfc) == 0x28 || (insn & 0xf3) == 0x43 || (insn & 0xf3) == 0x42
		|| (insn & 0xfc) == 0x58 || (insn & 0xfc) == 0x5c
		|| ((insn & 0xf0) == 0xc0 && insn != 0xcb && insn != 0xcc && insn != 0xcd)
		|| (insn >= 0xf0 && insn <= 0xf6)) {
		return 2;
	}
	if (insn == 0xf8 || insn == 0xcc || insn == 0xf9 || (insn & 0xf3) == 0x01 || (insn & 0xf3) == 0x02
		|| (insn & 0xf3) == 0x03 || (insn & 0xfc) == 0x24 || (insn & 0xfc) == 0x2c || (insn & 0xfc) == 0x30
		|| (insn & 0xfc) == 0x34 || (insn & 0xfc) == 0x38 || insn == 0xde || insn == 0xdf) {
		return 3;
	}
	if (insn == 0xfa || insn == 0xf7 || insn == 0xfb) {
		return 4;
	}
	if (insn == 0xcd || insn == 0xdc) {
		return 5;
	}
	if (insn == 0xfd || insn == 0xfc) {
		return 6;
	}
	return 7;
}

static int mn103_format_size(int format) {
	switch (format) {
	case MN103_FMT_S0: return 1;
	case MN103_FMT_S1: case MN103_FMT_D0: return 2;
	case MN103_FMT_S2: case MN103_FMT_D1: case MN103_FMT_D6: return 3;
	case MN103_FMT_D2: case MN103_FMT_D7: case MN103_FMT_D10: return 4;
	case MN103_FMT_S4: case MN103_FMT_D3: return 5;
	case MN103_FMT_D4: case MN103_FMT_D8: return 6;
	default: return 7; /* S6, D5, D9 */
	}
}

static bool mn103_mach_ok(int mach, int machine) {
	switch (machine) {
	case MN103_MACH_BASE: return true;
	case MN103_MACH_AM30: return mach >= MN103_MACH_AM30;
	case MN103_MACH_AM33: return mach >= MN103_MACH_AM33;
	case MN103_MACH_AM33_2: return mach >= MN103_MACH_AM33_2;
	}
	return false;
}

static ut32 be32(const ut8 *p) {
	return ((ut32)p[0] << 24) | ((ut32)p[1] << 16) | ((ut32)p[2] << 8) | p[3];
}

static ut32 le16(const ut8 *p) {
	return p[0] | ((ut32)p[1] << 8);
}

static ut32 le32(const ut8 *p) {
	return p[0] | ((ut32)p[1] << 8) | ((ut32)p[2] << 16) | ((ut32)p[3] << 24);
}

static st32 sign_bits(ut32 value, unsigned bits) {
	const ut32 sign = 1U << (bits - 1);
	return (st32)((value ^ sign) - sign);
}

/* Fill the operands of a matched row from the raw bytes, the binutils way (insn/extension split). */
static void mn103_fill_operands(Mn103Insn *in, const ut8 *d, ut64 memaddr) {
	const Mn103Opcode *op = in->desc;
	const int fmt = op->format;
	const int size = in->size;
	ut32 insn = in->insn;
	ut32 extension = 0;
	int extra_shift;

	if (fmt == MN103_FMT_D1 || fmt == MN103_FMT_S1) {
		extra_shift = 8;
	} else if (fmt == MN103_FMT_D2 || fmt == MN103_FMT_D4 || fmt == MN103_FMT_S2 || fmt == MN103_FMT_S4
		|| fmt == MN103_FMT_S6 || fmt == MN103_FMT_D5) {
		extra_shift = 16;
	} else if (fmt == MN103_FMT_D7 || fmt == MN103_FMT_D8 || fmt == MN103_FMT_D9) {
		extra_shift = 8;
	} else {
		extra_shift = 0;
	}

	if (size == 1 || size == 2) {
		/* nothing */
	} else if (size == 3 && (fmt == MN103_FMT_D1 || op->opcode == 0xdf0000 || op->opcode == 0xde0000)) {
		/* nothing */
	} else if (size == 3 && fmt == MN103_FMT_D6) {
		/* nothing */
	} else if (size == 3) {
		insn &= 0xff0000;
		insn |= le16 (d + 1);
	} else if (size == 4 && (op->opcode == 0xfaf80000 || op->opcode == 0xfaf00000 || op->opcode == 0xfaf40000)) {
		/* nothing */
	} else if (size == 4 && (fmt == MN103_FMT_D7 || fmt == MN103_FMT_D10)) {
		/* nothing */
	} else if (size == 4) {
		insn &= 0xffff0000;
		insn |= le16 (d + 2);
	} else if (size == 5 && op->opcode == 0xdc000000) {
		const ut32 temp = le32 (d + 1);
		insn &= 0xff000000;
		insn |= (temp & 0xffffff00) >> 8;
		extension = temp & 0xff;
	} else if (size == 5 && fmt == MN103_FMT_D3) {
		insn &= 0xffff0000;
		insn |= le16 (d + 2);
		extension = d[4];
	} else if (size == 5) {
		const ut32 temp = le16 (d + 1);
		insn &= 0xff0000ff;
		insn |= temp << 8;
		extension = d[4];
	} else if (size == 6 && fmt == MN103_FMT_D8) {
		insn &= 0xffffff00;
		insn |= d[5];
		extension = le16 (d + 3);
	} else if (size == 6) {
		const ut32 temp = le32 (d + 2);
		insn &= 0xffff0000;
		insn |= (temp >> 16) & 0xffff;
		extension = temp & 0xffff;
	} else if (size == 7 && fmt == MN103_FMT_D9) {
		insn &= 0xffffff00;
		extension = le32 (d + 3);
		insn |= (extension & 0xff000000) >> 24;
		extension &= 0xffffff;
	} else if (size == 7 && op->opcode == 0xdd000000) {
		const ut32 temp = le32 (d + 1);
		insn &= 0xff000000;
		insn |= (temp >> 8) & 0xffffff;
		extension = (temp & 0xff) << 16;
		extension |= ((ut32)d[5] << 8) | d[6];
	} else if (size == 7) {
		const ut32 temp = le32 (d + 2);
		insn &= 0xffff0000;
		insn |= (temp >> 16) & 0xffff;
		extension = (temp & 0xffff) << 8;
		extension |= d[6];
	}
	in->insn = insn;

	int i;
	in->nops = op->nops;
	for (i = 0; i < op->nops; i++) {
		const Mn103OperandDesc *od = &mn103_operands[op->ops[i]];
		Mn103Operand *o = &in->ops[i];
		const unsigned bits = od->bits;
		const int shift = od->shift;
		const ut32 fl = od->flags;
		ut32 value;
		o->index = op->ops[i];
		o->flags = fl;
		o->reg = NULL;
		if (fl & (MN103_OPERAND_DREG | MN103_OPERAND_AREG | MN103_OPERAND_RREG | MN103_OPERAND_XRREG)) {
			value = (insn >> (shift + extra_shift)) & ((1U << bits) - 1);
		} else if (fl & MN103_OPERAND_SPLIT) {
			ut32 temp;
			value = insn & ((1U << bits) - 1);
			value <<= (32 - bits);
			temp = extension >> shift;
			temp &= ((1U << (32 - bits)) - 1);
			value |= temp;
		} else if (fl & MN103_OPERAND_BIT24) {
			ut32 temp;
			value = insn & ((1U << bits) - 1);
			value <<= (24 - bits);
			temp = extension >> shift;
			temp &= ((1U << (24 - bits)) - 1);
			value |= temp;
			if (fl & MN103_OPERAND_SIGNED) {
				value = (ut32)(st32)(((value & 0xffffff) ^ 0x800000) - 0x800000);
			}
		} else if (fl & (MN103_OPERAND_FSREG | MN103_OPERAND_FDREG)) {
			ut32 mask_low, mask_high;
			int shl_low, shr_high, shl_high;
			if (bits == 5) {
				if (shift >= 0) {
					shl_low = shift;
					shl_high = 8 + (8 & shl_low) + (shl_low & 4) / 4;
				} else {
					shl_low = -shift;
					shl_high = shl_low / 4;
				}
				mask_low = 0x0f;
				mask_high = 0x10;
				shr_high = 4;
			} else {
				shl_low = -shift;
				shl_high = 0;
				mask_low = 0x03;
				mask_high = 0x04;
				shr_high = 2;
			}
			value = ((((insn >> shl_high) << shr_high) & mask_high) | ((insn >> shl_low) & mask_low));
		} else if (fl & MN103_OPERAND_EXTENDED) {
			value = (extension >> shift) & ((1U << bits) - 1);
		} else if (bits) {
			value = (insn >> shift) & ((1U << bits) - 1);
		} else {
			value = 0;
		}
		if ((fl & MN103_OPERAND_SIGNED) && !(fl & MN103_OPERAND_BIT24) && bits) {
			value = (ut32)sign_bits (value, bits);
		}
		o->value = (st32)value;
		if (fl & MN103_OPERAND_DREG) {
			o->reg = mn103_dregs[value & 3];
		} else if (fl & MN103_OPERAND_AREG) {
			o->reg = mn103_aregs[value & 3];
		} else if (fl & MN103_OPERAND_SP) {
			o->reg = "sp";
		} else if (fl & MN103_OPERAND_PSW) {
			o->reg = "psw";
		} else if (fl & MN103_OPERAND_MDR) {
			o->reg = "mdr";
		} else if (fl & MN103_OPERAND_RREG) {
			o->reg = mn103_rregs[value & 15];
		} else if (fl & MN103_OPERAND_XRREG) {
			o->reg = mn103_xrregs[value & 15];
		} else if (fl & MN103_OPERAND_FSREG) {
			o->reg = mn103_fsregs[value & 31];
		} else if (fl & MN103_OPERAND_FDREG) {
			o->reg = mn103_fdregs[value & 31];
		} else if (fl & MN103_OPERAND_FPCR) {
			o->reg = "fpcr";
		} else if (fl & MN103_OPERAND_USP) {
			o->reg = "usp";
		} else if (fl & MN103_OPERAND_SSP) {
			o->reg = "ssp";
		} else if (fl & MN103_OPERAND_MSP) {
			o->reg = "msp";
		} else if (fl & MN103_OPERAND_PC) {
			o->reg = "pc";
		} else if (fl & MN103_OPERAND_EPSW) {
			o->reg = "epsw";
		} else if (fl & MN103_OPERAND_PCREL) {
			o->value = (st32)((ut32)memaddr + value);
		}
	}
}

bool mn103_decode(Mn103Insn *in, const ut8 *buf, int len, ut64 addr, int mach) {
	memset (in, 0, sizeof (*in));
	in->index = -1;
	if (len < 1) {
		return false;
	}
	int size = mn103_insn_size (buf[0]);
	ut32 insn;
	if (size == 1) {
		insn = buf[0];
	} else if (size == 2) {
		if (len < 2) {
			in->size = size;
			return false;
		}
		insn = ((ut32)buf[0] << 8) | buf[1];
	} else if (size == 3) {
		if (len < 3) {
			in->size = size;
			return false;
		}
		insn = ((ut32)buf[0] << 16) | ((ut32)buf[1] << 8) | buf[2];
	} else {
		if (len < 4) {
			in->size = size;
			return false;
		}
		insn = be32 (buf);
		if (size == 7 && (insn & 0xfff80000) == 0xfe800000) {
			size = 5;
		}
	}
	in->size = size;
	in->insn = insn;
	if (len < size) {
		return false;
	}
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (mn103_opcodes); i++) {
		const Mn103Opcode *op = &mn103_opcodes[i];
		if ((op->mask & insn) != op->opcode || mn103_format_size (op->format) != size) {
			continue;
		}
		if (!mn103_mach_ok (mach, op->machine)) {
			continue;
		}
		in->desc = op;
		in->index = (int)i;
		mn103_fill_operands (in, buf, addr);
		return true;
	}
	return false;
}

static void mn103_format_imm(RStrBuf *sb, const Mn103Operand *o) {
	const ut32 fl = o->flags;
	if (fl & MN103_OPERAND_PCREL) {
		r_strbuf_appendf (sb, "0x%08x", (ut32)o->value);
	} else if (fl & (MN103_OPERAND_MEMADDR | MN103_OPERAND_SPLIT)) {
		r_strbuf_appendf (sb, "0x%x", (ut32)o->value);
	} else if (o->value < 0) {
		r_strbuf_appendf (sb, "-0x%x", (ut32)(-(st64)o->value));
	} else {
		r_strbuf_appendf (sb, "0x%x", (ut32)o->value);
	}
}

static void mn103_format_reglist(RStrBuf *sb, ut32 value) {
	static const struct { ut32 bit; const char *name; } names[] = {
		{ MN103_REGS_D2, "d2" }, { MN103_REGS_D3, "d3" }, { MN103_REGS_A2, "a2" }, { MN103_REGS_A3, "a3" },
		{ MN103_REGS_OTHER, "other" }, { MN103_REGS_EXREG0, "exreg0" }, { MN103_REGS_EXREG1, "exreg1" },
		{ MN103_REGS_EXOTHER, "exother" },
	};
	size_t i;
	bool comma = false;
	r_strbuf_append (sb, "[");
	for (i = 0; i < R_ARRAY_SIZE (names); i++) {
		if (value & names[i].bit) {
			r_strbuf_appendf (sb, "%s%s", comma? ",": "", names[i].name);
			comma = true;
		}
	}
	r_strbuf_append (sb, "]");
}

void mn103_format(RStrBuf *sb, const Mn103Insn *in) {
	if (!in->desc) {
		r_strbuf_appendf (sb, "unknown 0x%04x", in->insn);
		return;
	}
	r_strbuf_append (sb, in->desc->name);
	int i;
	bool nocomma = true;
	bool paren = false;
	for (i = 0; i < in->nops; i++) {
		const Mn103Operand *o = &in->ops[i];
		const ut32 fl = o->flags;
		if (o->index == MN103_OP_UNUSED) {
			continue;
		}
		if (fl & MN103_OPERAND_PLUS) {
			nocomma = true;
		}
		if (!nocomma && (!paren || !(fl & MN103_OPERAND_PAREN))) {
			r_strbuf_append (sb, ", ");
		} else if (i == 0) {
			r_strbuf_append (sb, " ");
		}
		nocomma = false;
		if (o->reg) {
			r_strbuf_append (sb, o->reg);
		} else if (fl & MN103_OPERAND_PLUS) {
			r_strbuf_append (sb, "+");
		} else if (fl & MN103_OPERAND_PAREN) {
			if (paren) {
				r_strbuf_append (sb, ")");
			} else {
				r_strbuf_append (sb, "(");
				nocomma = true;
			}
			paren = !paren;
		} else if (fl & MN103_OPERAND_REG_LIST) {
			mn103_format_reglist (sb, (ut32)o->value);
		} else {
			mn103_format_imm (sb, o);
		}
	}
}
