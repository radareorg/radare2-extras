/* radare - LGPL - Copyright 2018 - damo22 */

#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>
#include <r_anal.h>

#include "../../asm/arch/atombios/atombios.h"

typedef struct {
	_RAnalOpType optype;
	const char *reg;
} atombios_ops_t;

atombios_ops_t atombios_ops[256] = {
	[0x00] = {R_ANAL_OP_TYPE_NULL, NULL	},

	[0x01] = {R_ANAL_OP_TYPE_IO, "r"	},
	[0x02] = {R_ANAL_OP_TYPE_MOV, "p"	},
	[0x03] = {R_ANAL_OP_TYPE_MOV, "w"	},
	[0x04] = {R_ANAL_OP_TYPE_MOV, "f"	},
	[0x05] = {R_ANAL_OP_TYPE_MOV, "pll"	},
	[0x06] = {R_ANAL_OP_TYPE_MOV, "mc"	},
	[0x07] = {R_ANAL_OP_TYPE_IO, "r"	},
	[0x08] = {R_ANAL_OP_TYPE_AND, "p"	},
	[0x09] = {R_ANAL_OP_TYPE_AND, "w"	},
	[0x0a] = {R_ANAL_OP_TYPE_AND, "f"	},
	[0x0b] = {R_ANAL_OP_TYPE_AND, "pll"	},
	[0x0c] = {R_ANAL_OP_TYPE_AND, "mc"	},
	[0x0d] = {R_ANAL_OP_TYPE_IO, "r"	},
	[0x0e] = {R_ANAL_OP_TYPE_OR, "p"	},
	[0x0f] = {R_ANAL_OP_TYPE_OR, "w"	},
	[0x10] = {R_ANAL_OP_TYPE_OR, "f"	},
	[0x11] = {R_ANAL_OP_TYPE_OR, "pll"	},
	[0x12] = {R_ANAL_OP_TYPE_OR, "mc"	},

	[0x13] = {R_ANAL_OP_TYPE_IO, "r"	}, // imm
	[0x14] = {R_ANAL_OP_TYPE_SHL, "p"	},
	[0x15] = {R_ANAL_OP_TYPE_SHL, "w"	},
	[0x16] = {R_ANAL_OP_TYPE_SHL, "f"	},
	[0x17] = {R_ANAL_OP_TYPE_SHL, "pll"	},
	[0x18] = {R_ANAL_OP_TYPE_SHL, "mc"	},
	[0x19] = {R_ANAL_OP_TYPE_IO, "r"	}, // imm
	[0x1a] = {R_ANAL_OP_TYPE_SHR, "p"	},
	[0x1b] = {R_ANAL_OP_TYPE_SHR, "w"	},
	[0x1c] = {R_ANAL_OP_TYPE_SHR, "f"	},
	[0x1d] = {R_ANAL_OP_TYPE_SHR, "pll"	},
	[0x1e] = {R_ANAL_OP_TYPE_SHR, "mc"	},

	[0x1f] = {R_ANAL_OP_TYPE_IO, "r"	},
	[0x20] = {R_ANAL_OP_TYPE_MUL, "p"	},
	[0x21] = {R_ANAL_OP_TYPE_MUL, "w"	},
	[0x22] = {R_ANAL_OP_TYPE_MUL, "f"	},
	[0x23] = {R_ANAL_OP_TYPE_MUL, "pll"	},
	[0x24] = {R_ANAL_OP_TYPE_MUL, "mc"	},
	[0x25] = {R_ANAL_OP_TYPE_IO, "r"	},
	[0x26] = {R_ANAL_OP_TYPE_DIV, "p"	},
	[0x27] = {R_ANAL_OP_TYPE_DIV, "w"	},
	[0x28] = {R_ANAL_OP_TYPE_DIV, "f"	},
	[0x29] = {R_ANAL_OP_TYPE_DIV, "pll"	},
	[0x2a] = {R_ANAL_OP_TYPE_DIV, "mc"	},
	[0x2b] = {R_ANAL_OP_TYPE_IO, "r"	},
	[0x2c] = {R_ANAL_OP_TYPE_ADD, "p"	},
	[0x2d] = {R_ANAL_OP_TYPE_ADD, "w"	},
	[0x2e] = {R_ANAL_OP_TYPE_ADD, "f"	},
	[0x2f] = {R_ANAL_OP_TYPE_ADD, "pll"	},
	[0x30] = {R_ANAL_OP_TYPE_ADD, "mc"	},
	[0x31] = {R_ANAL_OP_TYPE_IO, "r"	},
	[0x32] = {R_ANAL_OP_TYPE_SUB, "p"	},
	[0x33] = {R_ANAL_OP_TYPE_SUB, "w"	},
	[0x34] = {R_ANAL_OP_TYPE_SUB, "f"	},
	[0x35] = {R_ANAL_OP_TYPE_SUB, "pll"	},
	[0x36] = {R_ANAL_OP_TYPE_SUB, "mc"	},

	[0x37] = {R_ANAL_OP_TYPE_MOV, "md"	}, // imm16 SET MODE {0-4}={INDIRECT_MM, INDIRECT_PLL, INDIRECT_MC, INDIRECT_PCIE, DIRECT_PCIE}
	[0x38] = {R_ANAL_OP_TYPE_MOV, "md"	}, // null  SET MODE DIRECT_PCIE
	[0x39] = {R_ANAL_OP_TYPE_MOV, "md"	}, // null  SET MODE DIRECT_SYSTEMIO
	[0x3a] = {R_ANAL_OP_TYPE_MOV, "rb"	}, // imm16 SET REG BLOCK     allreg = allreg + (imm16 << 2)
	[0x3b] = {R_ANAL_OP_TYPE_MOV, "fb"	}, // src   SET FB BASE       fb = srcalign(reg[regtype])

	[0x3c] = {R_ANAL_OP_TYPE_IO, "r"	},
	[0x3d] = {R_ANAL_OP_TYPE_CMP, "p"	},
	[0x3e] = {R_ANAL_OP_TYPE_CMP, "w"	},
	[0x3f] = {R_ANAL_OP_TYPE_CMP, "f"	},
	[0x40] = {R_ANAL_OP_TYPE_CMP, "pll"	},
	[0x41] = {R_ANAL_OP_TYPE_CMP, "mc"	},

	[0x42] = {R_ANAL_OP_TYPE_SWITCH, NULL	},

	[0x43] = {R_ANAL_OP_TYPE_JMP, NULL	},
	[0x44] = {R_ANAL_OP_TYPE_CJMP, "=="	},
	[0x45] = {R_ANAL_OP_TYPE_CJMP, "<"	},
	[0x46] = {R_ANAL_OP_TYPE_CJMP, ">"	},
	[0x47] = {R_ANAL_OP_TYPE_CJMP, "<="	},
	[0x48] = {R_ANAL_OP_TYPE_CJMP, ">="	},
	[0x49] = {R_ANAL_OP_TYPE_CJMP, "!="	},

	[0x4a] = {R_ANAL_OP_TYPE_IO, "r"	}, // TEST
	[0x4b] = {R_ANAL_OP_TYPE_ACMP, "p"	},
	[0x4c] = {R_ANAL_OP_TYPE_ACMP, "w"	},
	[0x4d] = {R_ANAL_OP_TYPE_ACMP, "f"	},
	[0x4e] = {R_ANAL_OP_TYPE_ACMP, "pll"	},
	[0x4f] = {R_ANAL_OP_TYPE_ACMP, "mc"	},

	[0x50] = {R_ANAL_OP_TYPE_IO, "m"	}, // mdelay
	[0x51] = {R_ANAL_OP_TYPE_IO, "u"	}, // udelay
	[0x52] = {R_ANAL_OP_TYPE_CALL, NULL	},
	[0x53] = {R_ANAL_OP_TYPE_REP, NULL	},
	[0x54] = {R_ANAL_OP_TYPE_IO, "r"	}, // = 0
	[0x55] = {R_ANAL_OP_TYPE_MOV, "p"	},
	[0x56] = {R_ANAL_OP_TYPE_MOV, "w"	},
	[0x57] = {R_ANAL_OP_TYPE_MOV, "f"	},
	[0x58] = {R_ANAL_OP_TYPE_MOV, "pll"	},
	[0x59] = {R_ANAL_OP_TYPE_MOV, "mc"	},
	[0x5a] = {R_ANAL_OP_TYPE_NOP, NULL	},
	[0x5b] = {R_ANAL_OP_TYPE_RET, NULL	},
	[0x5c] = {R_ANAL_OP_TYPE_IO, "r"	}, // MASK reg = reg & imm1 | imm2
	[0x5d] = {R_ANAL_OP_TYPE_AND, "p"	},
	[0x5e] = {R_ANAL_OP_TYPE_AND, "w"	},
	[0x5f] = {R_ANAL_OP_TYPE_AND, "f"	},
	[0x60] = {R_ANAL_OP_TYPE_AND, "pll"	},
	[0x61] = {R_ANAL_OP_TYPE_AND, "mc"	},
	[0x62] = {R_ANAL_OP_TYPE_IO, "p80"	}, // POST CODE imm8
	[0x63] = {R_ANAL_OP_TYPE_IO, "b"	}, // BEEP
	[0x64] = {R_ANAL_OP_TYPE_PUSH, NULL	}, // SAVE REG (depr) 100
	[0x65] = {R_ANAL_OP_TYPE_POP, NULL	}, // RESTORE REG (depr)
	[0x66] = {R_ANAL_OP_TYPE_MOV, "dt"	}, // imm8 SET DATA BLOCK dataptr = &data[datatable[imm8]]

	[0x67] = {R_ANAL_OP_TYPE_IO, "r"	},
	[0x68] = {R_ANAL_OP_TYPE_XOR, "p"	},
	[0x69] = {R_ANAL_OP_TYPE_XOR, "w"	},
	[0x6a] = {R_ANAL_OP_TYPE_XOR, "f"	},
	[0x6b] = {R_ANAL_OP_TYPE_XOR, "pll"	},
	[0x6c] = {R_ANAL_OP_TYPE_XOR, "mc"	},
	[0x6d] = {R_ANAL_OP_TYPE_IO, "r"	}, // dest align and src align
	[0x6e] = {R_ANAL_OP_TYPE_SHL, "p"	},
	[0x6f] = {R_ANAL_OP_TYPE_SHL, "w"	},
	[0x70] = {R_ANAL_OP_TYPE_SHL, "f"	},
	[0x71] = {R_ANAL_OP_TYPE_SHL, "pll"	},
	[0x72] = {R_ANAL_OP_TYPE_SHL, "mc"	},
	[0x73] = {R_ANAL_OP_TYPE_IO, "r"	}, // dest align and src align
	[0x74] = {R_ANAL_OP_TYPE_SHR, "p"	},
	[0x75] = {R_ANAL_OP_TYPE_SHR, "w"	},
	[0x76] = {R_ANAL_OP_TYPE_SHR, "f"	},
	[0x77] = {R_ANAL_OP_TYPE_SHR, "pll"	},
	[0x78] = {R_ANAL_OP_TYPE_SHR, "mc"	},

	[0x79] = {R_ANAL_OP_TYPE_TRAP, NULL	}, // DEBUG
	[0x7a] = {R_ANAL_OP_TYPE_UNK, NULL	}, // DATA TABLE

	[0x80] = { R_ANAL_OP_TYPE_ILL, NULL	}, // not implemented (extended)
	[0xff] = { R_ANAL_OP_TYPE_ILL, NULL	}, // not implemented (reserved)
};

static int atombios_op(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *b, int len, RAnalOpMask unused) {
	if (!op)
		return -1;
	memset (op, 0, sizeof (RAnalOp));
	op->nopcode = 1;
	op->size = atombios_inst_len (b);
	op->type = atombios_ops[*b].optype;
	if (len < op->size) {
		op->type = R_ANAL_OP_TYPE_ILL;
		return -1;
	}

	if (*b > 0x7a) {
		op->type = R_ANAL_OP_TYPE_ILL;
		return -1;
	}

	switch (b[0]) {
	// op REG IO
	case 0x01:
	case 0x07:
	case 0x0d:
	case 0x13:
	case 0x19:
	case 0x1f:
	case 0x25:
	case 0x2b:
	case 0x31:
	//case 0x3c:
	case 0x4a:
	case 0x54:
	case 0x5c:
	case 0x67:
	case 0x6d:
	case 0x73:
		break;

	// SET MODE imm16 {0-4}={INDIRECT_MM, INDIRECT_PLL, INDIRECT_MC, INDIRECT_PCIE, DIRECT_PCIE}
	case 0x37:
		esilprintf (op, "0x%04x,md,=", r_read_at_le16(b, 1));
		break;

	// SET MODE DIRECT_PCIE
	case 0x38:
		esilprintf (op, "0x0004,md,=");
		break;

	// SET MODE DIRECT_SYSTEMIO
	case 0x39:
		esilprintf (op, "0x0005,md,=");
		break;

	// SET REG BLOCK imm16 allreg = allreg + (imm16 << 2)
	case 0x3a:
		esilprintf (op, "0x%04x,rb,=", r_read_at_le16(b, 1));
		break;

	// SET FB BASE fb = srcalign(reg[regtype])
	case 0x3b:
		{
			ut8 szsrc = 0;
			ut8 attr = b[1];
			ut8 srctype = attr & 0x7;
			ut8 srcalign = size_align[(attr & 0x38) >> 3];
			ut32 val = 0;
			const char *idx;
			char tmpsrc[256] = {0};
			char *t;

			// SOURCE
			t = &tmpsrc[0];
			switch (srctype) {
			case D_IM:
				szsrc = srcalign;
				break;
			case D_PS:
			case D_WS:
			case D_FB:
			case D_PLL:
			case D_MC:
				szsrc = 1;
				break;
			case D_REG:
			case D_ID:
				szsrc = 2;
				break;
			}

			switch (szsrc) {
			case 1:
				val = (ut8)b[2];
				break;
			case 2:
				val = r_read_at_le16(b, 2);
				break;
			case 4:
				val = r_read_at_le32(b, 2);
				break;
			}

			if (srctype == D_IM) {
				t += sprintf (t, addrtypes_im[srcalign], val);
			} else if(srctype == D_WS) {
				idx = get_index (INDEX_WORK_REG, val);
				t += sprintf (t, "%s", idx);
				t += sprintf (t, "%s", align_source_esil[srcalign]);
			} else {
				t += sprintf (t, addrtypes_esil[srctype], val << addrtypes_shift[srctype]);
				t += sprintf (t, "%s", align_source_esil[srcalign]);
			}
			if (srctype == D_REG || srctype == D_FB || srctype == D_PLL || srctype == D_MC)
				op->type = R_ANAL_OP_TYPE_IO;
			else
				esilprintf (op, "%s,fb,=", tmpsrc);
		} break;

	// op switch
	case 0x42:
		{

		} break;

	// op dest = 0
	//case 0x54:
	case 0x55:
	case 0x56:
	case 0x57:
	case 0x58:
	case 0x59:
		{
			ut8 szdst = 0;
			ut8 attr = b[1];
			ut8 dsttype = optable[*b].desttype;
			ut8 dstalign = (attr & 0x38) >> 3;
			ut8 size = size_align[dstalign];
			ut32 val = 0;
			const char *idx;
			char tmpdst[256] = {0};
			char *t;

			// DESTINATION
			t = &tmpdst[0];
			switch (dsttype) {
			case D_IM:
				szdst = size;
				break;
			case D_PS:
			case D_WS:
			case D_FB:
			case D_PLL:
			case D_MC:
				szdst = 1;
				break;
			case D_REG:
			case D_ID:
				szdst = 2;
				break;
			}

			switch (szdst) {
			case 1:
				val = b[2];
				break;
			case 2:
				val = r_read_at_le16(b, 2);
				break;
			case 4:
				val = r_read_at_le32(b, 2);
				break;
			}

			if (dsttype == D_IM) {
				t += sprintf (t, addrtypes_im[dstalign], val);
			} else if(dsttype == D_WS) {
				idx = get_index (INDEX_WORK_REG, val);
				t += sprintf (t, "%s", idx);
				t += sprintf (t, "%s", align_source_esil[dstalign]);
			} else {
				t += sprintf (t, addrtypes_esil[dsttype], val << addrtypes_shift[dsttype]);
				t += sprintf (t, "%s", align_source_esil[dstalign]);
			}
			if (dsttype == D_REG || dsttype == D_FB || dsttype == D_PLL || dsttype == D_MC)
				op->type = R_ANAL_OP_TYPE_IO;
			else {
				esilprintf (op, "0,%s,=", tmpdst);
				//printf ("0,%s,=", tmpdst);
			}
		} break;

	// op mask
	//case 0x5c:
	case 0x5d:
	case 0x5e:
	case 0x5f:
	case 0x60:
	case 0x61:
		{

		} break;

	// op (null)
	case 0x5a: // nop
	case 0x64: // save
	case 0x65: // restore
	case 0x79: // debug
		break;

	case 0x5b: // ret
		op->eob = true;
		esilprintf (op, "sp,[4],pc,=,4,sp,+=");
		break;

	// op ds (imm data table)
	case 0x7a:
		op->size = 3;// + r_read_at_le16(b, 1);
		break;

	// op imm8
	case 0x50:
	case 0x51:
	case 0x53:
	case 0x62:
	case 0x63:
		break;

	case 0x52: // call
		{
			ut8 idx;
			const RList *sects;

			if (!(sects = r_bin_get_sections(anal->binb.bin))) {
				op->type = R_ANAL_OP_TYPE_ILL;
				return op->size;
			}
			idx = b[1];
			RBinSection *sect = (RBinSection *)r_list_get_n(sects, idx);
			if (!sect) {
				op->type = R_ANAL_OP_TYPE_ILL;
				return op->size;
			} else if (!sect->paddr) {
				op->type = R_ANAL_OP_TYPE_ILL;
				return op->size;
			}
			op->cond = R_ANAL_COND_AL;
			op->jump = sect->paddr;
			op->eob = true;
			esilprintf (op, "0x%08x,pc,4,sp,-=,sp,=[],pc,=", op->jump);
		} break;

	// jmp imm16
	case 0x43:
		{
			RBinSection* cursect;
			if (!(cursect = anal->binb.get_vsect_at (anal->binb.bin, addr))) {
				op->type = R_ANAL_OP_TYPE_ILL;
				return op->size;
			}
			op->cond = R_ANAL_COND_AL;
			op->jump = cursect->paddr + r_read_at_le16(b, 1);
			op->eob = true;
			esilprintf (op, "0x%08x,pc,=", op->jump);
		} break;
	case 0x44:
		{
			RBinSection* cursect;
			if (!(cursect = anal->binb.get_vsect_at (anal->binb.bin, addr))) {
				op->type = R_ANAL_OP_TYPE_ILL;
				return op->size;
			}
			op->cond = R_ANAL_COND_EQ;
			op->jump = cursect->paddr + r_read_at_le16(b, 1);
			op->fail = addr + op->size;
			op->eob = true;
			esilprintf (op, "$z,?{,0x%08x,pc,=,}", op->jump);
		} break;
	case 0x45:
		{
			RBinSection* cursect;
			if (!(cursect = anal->binb.get_vsect_at (anal->binb.bin, addr))) {
				op->type = R_ANAL_OP_TYPE_ILL;
				return op->size;
			}
			op->cond = R_ANAL_COND_LT;
			op->jump = cursect->paddr + r_read_at_le16(b, 1);
			op->fail = addr + op->size;
			op->eob = true;
			esilprintf (op, "$of,$sf,!=,?{,0x%08x,pc,=,}", op->jump);
		} break;
	case 0x46:
		{
			RBinSection* cursect;
			if (!(cursect = anal->binb.get_vsect_at (anal->binb.bin, addr))) {
				op->type = R_ANAL_OP_TYPE_ILL;
				return op->size;
			}
			op->cond = R_ANAL_COND_GT;
			op->jump = cursect->paddr + r_read_at_le16(b, 1);
			op->fail = addr + op->size;
			op->eob = true;
			esilprintf (op, "$z,!,$of,$sf,==,&,?{,0x%08x,pc,=,}", op->jump);
		} break;
	case 0x47:
		{
			RBinSection* cursect;
			if (!(cursect = anal->binb.get_vsect_at (anal->binb.bin, addr))) {
				op->type = R_ANAL_OP_TYPE_ILL;
				return op->size;
			}
			op->cond = R_ANAL_COND_LE;
			op->jump = cursect->paddr + r_read_at_le16(b, 1);
			op->fail = addr + op->size;
			op->eob = true;
			esilprintf (op, "$z,$of,$sf,!=,|,?{,0x%08x,pc,=,}", op->jump);
		} break;
	case 0x48:
		{
			RBinSection* cursect;
			if (!(cursect = anal->binb.get_vsect_at (anal->binb.bin, addr))) {
				op->type = R_ANAL_OP_TYPE_ILL;
				return op->size;
			}
			op->cond = R_ANAL_COND_GE;
			op->jump = cursect->paddr + r_read_at_le16(b, 1);
			op->fail = addr + op->size;
			op->eob = true;
			esilprintf (op, "$of,$sf,==,?{,0x%08x,pc,=,}", op->jump);
		} break;
	case 0x49:
		{
			RBinSection* cursect;
			if (!(cursect = anal->binb.get_vsect_at (anal->binb.bin, addr))) {
				op->type = R_ANAL_OP_TYPE_ILL;
				return op->size;
			}
			op->cond = R_ANAL_COND_NE;
			op->jump = cursect->paddr + r_read_at_le16(b, 1);
			op->fail = addr + op->size;
			op->eob = true;
			esilprintf (op, "$z,!,?{,0x%08x,pc,=,}", op->jump);
		} break;

	// SET DATA BLOCK imm8 dataptr = &data[datatable[imm8]]
	case 0x66:
		esilprintf (op, "0x%02x,db,=", b[1]);
		break;

	// shift imm
	//case 0x13:
	case 0x14:
	case 0x15:
	case 0x16:
	case 0x17:
	case 0x18:
	//case 0x19:
	case 0x1a:
	case 0x1b:
	case 0x1c:
	case 0x1d:
	case 0x1e:
		{
			ut8 szdst = 0;
			ut8 attr = b[1];
			ut8 dsttype = optable[*b].desttype;
			ut8 dstalign = (attr & 0x38) >> 3;
			ut8 size = size_align[dstalign];

			ut32 val = 0;
			const char *idx;
			char tmpdst[256] = {0};
			char *t;

			// DESTINATION
			t = &tmpdst[0];
			switch (dsttype) {
			case D_IM:
				szdst = size;
				break;
			case D_PS:
			case D_WS:
			case D_FB:
			case D_PLL:
			case D_MC:
				szdst = 1;
				break;
			case D_REG:
			case D_ID:
				szdst = 2;
				break;
			}

			switch (szdst) {
			case 1:
				val = b[2];
				break;
			case 2:
				val = r_read_at_le16(b, 2);
				break;
			case 4:
				val = r_read_at_le32(b, 2);
				break;
			}

			if (dsttype == D_IM) {
				t += sprintf (t, addrtypes_im[size], val);
			} else if (dsttype == D_WS) {
				idx = get_index (INDEX_WORK_REG, val);
				t += sprintf (t, "%s", idx);
				t += sprintf (t, "%s", align_source_esil[dstalign]);
			} else if (dsttype == D_ID) {
				const RList *sects;
				RBinSection *sect;
				ut32 dataimm;
				ut64 datablock;
				if (!(sects = r_bin_get_sections(anal->binb.bin))) {
					op->type = R_ANAL_OP_TYPE_ILL;
					return op->size;
				}
				r_anal_esil_reg_read (anal->esil, "db", &datablock, NULL);

				if (datablock != 0xff) {
					// Access a global data table
					sect = (RBinSection *)r_list_get_n (sects, datablock + N_TABLES_CMD);
					if (!sect) {
						op->type = R_ANAL_OP_TYPE_ILL;
						return op->size;
					} else if (!sect->paddr) {
						op->type = R_ANAL_OP_TYPE_ILL;
						return op->size;
					}
					dataimm = sect->paddr;
					t += sprintf (t, "0x%08x,[4],dt,=", dataimm + val);
					t += sprintf (t, ",dt%s", align_source_esil[dstalign]);
				} else {
					// Access the local data table in this function
					sect = (RBinSection *)r_bin_get_section_at (anal->binb.bin->cur->o, addr, false);
					if (!sect) {
						op->type = R_ANAL_OP_TYPE_ILL;
						return op->size;
					} else if (!sect->paddr) {
						op->type = R_ANAL_OP_TYPE_ILL;
						return op->size;
					}
					dataimm = sect->paddr + sect->size;
					t += sprintf (t, "0x%08x,[4],dt,=", dataimm + val);
					t += sprintf (t, ",dt%s", align_source_esil[dstalign]);
				}
			}
			if (dsttype == D_REG || dsttype == D_FB || dsttype == D_PLL || dsttype == D_MC)
				op->type = R_ANAL_OP_TYPE_IO;
			else {
				esilprintf (op, "0x%02x,%s,%s", (ut8)b[2 + szdst], tmpdst, optable[*b].esilop);
				//eprintf ("0x%02x,%s,%s", b[2 + szdst], tmpdst, optable[*b].esilop);
			}
		}
		break;

	// op dest src
	//case 0x01:
	case 0x02:
	case 0x03:
	case 0x04:
	case 0x05:
	case 0x06:
	//case 0x07:
	case 0x08:
	case 0x09:
	case 0x0a:
	case 0x0b:
	case 0x0c:
	//case 0x0d:
	case 0x0e:
	case 0x0f:
	case 0x10:
	case 0x11:
	case 0x12:
	//case 0x1f:
	case 0x20:
	case 0x21:
	case 0x22:
	case 0x23:
	case 0x24:
	//case 0x25:
	case 0x26:
	case 0x27:
	case 0x28:
	case 0x29:
	case 0x2a:
	//case 0x2b:
	case 0x2c:
	case 0x2d:
	case 0x2e:
	case 0x2f:
	case 0x30:
	//case 0x31:
	case 0x32:
	case 0x33:
	case 0x34:
	case 0x35:
	case 0x36:
	case 0x3c:
	case 0x3d:
	case 0x3e:
	case 0x3f:
	case 0x40:
	case 0x41:
	//case 0x4a:
	case 0x4b:
	case 0x4c:
	case 0x4d:
	case 0x4e:
	case 0x4f:
	//case 0x67:
	case 0x68:
	case 0x69:
	case 0x6a:
	case 0x6b:
	case 0x6c:
	//case 0x6d:
	case 0x6e:
	case 0x6f:
	case 0x70:
	case 0x71:
	case 0x72:
	//case 0x73:
	case 0x74:
	case 0x75:
	case 0x76:
	case 0x77:
	case 0x78:
		{
			ut8 szsrc = 0;
			ut8 szdst = 0;
			ut8 attr = b[1];
			ut8 srctype = attr & 0x7;
			ut8 dsttype = optable[*b].desttype;
			ut8 srcalign = (attr & 0x38) >> 3;
			ut8 dstalign = attr >> 6;
			ut8 size = size_align[srcalign];
			ut32 val = 0;
			const char *idx;
			char tmpsrc[256] = {0};
			char tmpdst[256] = {0};
			char *t;

			// DESTINATION
			t = &tmpdst[0];
			switch (dsttype) {
			case D_REG:
				val = r_read_at_le16(b, 2);
				szdst = 2;
			case D_ID:
			case D_IM:
				op->type = R_ANAL_OP_TYPE_ILL;
				return -1;
			default:
				val = b[2];
				szdst = 1;
				break;
			}

			if (dsttype == D_WS) {
				idx = get_index (INDEX_WORK_REG, val);
				t += sprintf (t, "%s", idx);
			} else {
				t += sprintf (t, addrtypes_esil[dsttype], val << addrtypes_shift[dsttype]);
			}
			switch (size) {
			case 1:
				t += sprintf (t, "%s", align_byte_esil[dstalign]);
				break;
			case 2:
				t += sprintf (t, "%s", align_word_esil[dstalign]);
				break;
			case 4:
				t += sprintf (t, "%s", align_long_esil[dstalign]);
				break;
			}
			if (dsttype == D_REG || dsttype == D_FB || dsttype == D_PLL || dsttype == D_MC)
				op->type = R_ANAL_OP_TYPE_IO;

			// missing some (%s) here... ?

			// SOURCE
			t = &tmpsrc[0];
			switch (srctype) {
			case D_IM:
				szsrc = size;
				break;
			case D_PS:
			case D_WS:
			case D_FB:
			case D_PLL:
			case D_MC:
				szsrc = 1;
				break;
			case D_REG:
			case D_ID:
				szsrc = 2;
				break;
			}

			switch (szsrc) {
			case 1:
				val = b[2 + szdst];
				break;
			case 2:
				val = r_read_at_le16(b, 2 + szdst);
				break;
			case 4:
				val = r_read_at_le32(b, 2 + szdst);
				break;
			}

			if (srctype == D_IM) {
				t += sprintf (t, addrtypes_im[size], val);
			} else if (srctype == D_WS) {
				idx = get_index (INDEX_WORK_REG, val);
				t += sprintf (t, "%s", idx);
				t += sprintf (t, "%s", align_source_esil[srcalign]);
			} else if (srctype == D_ID) {
				const RList *sects;
				RBinSection *sect;
				ut32 dataimm;
				ut64 datablock;
				if (!(sects = r_bin_get_sections(anal->binb.bin))) {
					op->type = R_ANAL_OP_TYPE_ILL;
					return op->size;
				}
				r_anal_esil_reg_read (anal->esil, "db", &datablock, NULL);
				datablock &= 0xff;

				if (datablock != 0xff) {
					// Access a global data table
					sect = (RBinSection *)r_list_get_n (sects, datablock + N_TABLES_CMD);
					if (!sect) {
						op->type = R_ANAL_OP_TYPE_ILL;
						return op->size;
					} else if (!sect->paddr) {
						op->type = R_ANAL_OP_TYPE_ILL;
						return op->size;
					}
					dataimm = sect->paddr;
					t += sprintf (t, "0x%08x,[4],dt,=", dataimm + val);
					t += sprintf (t, ",dt%s", align_source_esil[srcalign]);
				} else {
					// Access the local data table in this function
					sect = (RBinSection *)r_bin_get_section_at (anal->binb.bin->cur->o, addr, false);
					if (!sect) {
						op->type = R_ANAL_OP_TYPE_ILL;
						return op->size;
					} else if (!sect->paddr) {
						op->type = R_ANAL_OP_TYPE_ILL;
						return op->size;
					}
					dataimm = sect->paddr + sect->size;
					t += sprintf (t, "0x%08x,[4],dt,=", dataimm + val);
					t += sprintf (t, ",dt%s", align_source_esil[srcalign]);
				}
				//eprintf ("%llx:  %s,%s,%s\n", addr, tmpsrc, tmpdst, optable[*b].esilop);
			} else {
				t += sprintf (t, addrtypes_esil[srctype], val << addrtypes_shift[srctype]);
				t += sprintf (t, "%s", align_source_esil[srcalign]);
			}
			if (srctype == D_REG || srctype == D_FB || srctype == D_PLL || srctype == D_MC) {
				op->type = R_ANAL_OP_TYPE_IO;
				//esilprintf (op, "0,%s,%s", tmpdst, optable[*b].esilop);
				//eprintf ("WARNING: IO assumed 0\n");
			} else {
				esilprintf (op, "%s,%s,%s", tmpsrc, tmpdst, optable[*b].esilop);
			}
		} break;
	}

	return op->size;
}

static int archinfo(RAnal *anal, int query) {
	switch (query) {
	case R_ANAL_ARCHINFO_MIN_OP_SIZE:
		return 1;
	case R_ANAL_ARCHINFO_MAX_OP_SIZE:
		return 1024;
	default:
		return -1;
	}
}

static bool set_reg_profile(RAnal *anal) {
	const char *p =
	"=PC    pc\n"
	"=SP    sp\n"
	"=BP    bp\n"
	"gpr    w0      .32     0       0\n"
	"gpr    w0_01   .16     0       0\n"
	"gpr    w0_12   .16     1       0\n"
	"gpr    w0_23   .16     2       0\n"
	"gpr    w0_0    .8      0       0\n"
	"gpr    w0_1    .8      1       0\n"
	"gpr    w0_2    .8      2       0\n"
	"gpr    w0_3    .8      3       0\n"

	"gpr    w1      .32     4       0\n"
	"gpr    w1_01   .16     4       0\n"
	"gpr    w1_12   .16     5       0\n"
	"gpr    w1_23   .16     6       0\n"
	"gpr    w1_0    .8      4       0\n"
	"gpr    w1_1    .8      5       0\n"
	"gpr    w1_2    .8      6       0\n"
	"gpr    w1_3    .8      7       0\n"

	"gpr    w2      .32     8       0\n"
	"gpr    w2_01   .16     8       0\n"
	"gpr    w2_12   .16     9       0\n"
	"gpr    w2_23   .16     10      0\n"
	"gpr    w2_0    .8      8       0\n"
	"gpr    w2_1    .8      9       0\n"
	"gpr    w2_2    .8      10      0\n"
	"gpr    w2_3    .8      11      0\n"

	"gpr    w3      .32     12      0\n"
	"gpr    w3_01   .16     12      0\n"
	"gpr    w3_12   .16     13      0\n"
	"gpr    w3_23   .16     14      0\n"
	"gpr    w3_0    .8      12      0\n"
	"gpr    w3_1    .8      13      0\n"
	"gpr    w3_2    .8      14      0\n"
	"gpr    w3_3    .8      15      0\n"

	"gpr    w4      .32     16      0\n"
	"gpr    w4_01   .16     16      0\n"
	"gpr    w4_12   .16     17      0\n"
	"gpr    w4_23   .16     18      0\n"
	"gpr    w4_0    .8      16      0\n"
	"gpr    w4_1    .8      17      0\n"
	"gpr    w4_2    .8      18      0\n"
	"gpr    w4_3    .8      19      0\n"

	"gpr    w5      .32     20      0\n"
	"gpr    w5_01   .16     20      0\n"
	"gpr    w5_12   .16     21      0\n"
	"gpr    w5_23   .16     22      0\n"
	"gpr    w5_0    .8      20      0\n"
	"gpr    w5_1    .8      21      0\n"
	"gpr    w5_2    .8      22      0\n"
	"gpr    w5_3    .8      23      0\n"

	"gpr    w6      .32     24      0\n"
	"gpr    w6_01   .16     24      0\n"
	"gpr    w6_12   .16     25      0\n"
	"gpr    w6_23   .16     26      0\n"
	"gpr    w6_0    .8      24      0\n"
	"gpr    w6_1    .8      25      0\n"
	"gpr    w6_2    .8      26      0\n"
	"gpr    w6_3    .8      27      0\n"

	"gpr    w7      .32     28      0\n"
	"gpr    w7_01   .16     28      0\n"
	"gpr    w7_12   .16     29      0\n"
	"gpr    w7_23   .16     30      0\n"
	"gpr    w7_0    .8      28      0\n"
	"gpr    w7_1    .8      29      0\n"
	"gpr    w7_2    .8      30      0\n"
	"gpr    w7_3    .8      31      0\n"

	"gpr    w8      .32     32      0\n"
	"gpr    w8_01   .16     32      0\n"
	"gpr    w8_12   .16     33      0\n"
	"gpr    w8_23   .16     34      0\n"
	"gpr    w8_0    .8      32      0\n"
	"gpr    w8_1    .8      33      0\n"
	"gpr    w8_2    .8      34      0\n"
	"gpr    w8_3    .8      35      0\n"

	"gpr    p0      .32     36      0\n"
	"gpr    p0_01   .16     36      0\n"
	"gpr    p0_12   .16     37      0\n"
	"gpr    p0_23   .16     38      0\n"
	"gpr    p0_0    .8      36      0\n"
	"gpr    p0_1    .8      37      0\n"
	"gpr    p0_2    .8      38      0\n"
	"gpr    p0_3    .8      39      0\n"

	"gpr    p1      .32     40      0\n"
	"gpr    p1_01   .16     40      0\n"
	"gpr    p1_12   .16     41      0\n"
	"gpr    p1_23   .16     42      0\n"
	"gpr    p1_0    .8      40      0\n"
	"gpr    p1_1    .8      41      0\n"
	"gpr    p1_2    .8      42      0\n"
	"gpr    p1_3    .8      43      0\n"

	"gpr    p2      .32     44      0\n"
	"gpr    p2_01   .16     44      0\n"
	"gpr    p2_12   .16     45      0\n"
	"gpr    p2_23   .16     46      0\n"
	"gpr    p2_0    .8      44      0\n"
	"gpr    p2_1    .8      45      0\n"
	"gpr    p2_2    .8      46      0\n"
	"gpr    p2_3    .8      47      0\n"

	"gpr    p3      .32     48      0\n"
	"gpr    p3_01   .16     48      0\n"
	"gpr    p3_12   .16     49      0\n"
	"gpr    p3_23   .16     50      0\n"
	"gpr    p3_0    .8      48      0\n"
	"gpr    p3_1    .8      49      0\n"
	"gpr    p3_2    .8      50      0\n"
	"gpr    p3_3    .8      51      0\n"

	"gpr    p4      .32     52      0\n"
	"gpr    p4_01   .16     52      0\n"
	"gpr    p4_12   .16     53      0\n"
	"gpr    p4_23   .16     54      0\n"
	"gpr    p4_0    .8      52      0\n"
	"gpr    p4_1    .8      53      0\n"
	"gpr    p4_2    .8      54      0\n"
	"gpr    p4_3    .8      55      0\n"

	"gpr    p5      .32     56      0\n"
	"gpr    p5_01   .16     56      0\n"
	"gpr    p5_12   .16     57      0\n"
	"gpr    p5_23   .16     58      0\n"
	"gpr    p5_0    .8      56      0\n"
	"gpr    p5_1    .8      57      0\n"
	"gpr    p5_2    .8      58      0\n"
	"gpr    p5_3    .8      59      0\n"

	"gpr    r       .32     60      0\n"
	"gpr    r_01    .16     60      0\n"
	"gpr    r_12    .16     61      0\n"
	"gpr    r_23    .16     62      0\n"
	"gpr    r_0     .8      60      0\n"
	"gpr    r_1     .8      61      0\n"
	"gpr    r_2     .8      62      0\n"
	"gpr    r_3     .8      63      0\n"

	"gpr    rb      .32     64      0\n"
	"gpr    rb_01   .16     64      0\n"
	"gpr    rb_12   .16     65      0\n"
	"gpr    rb_23   .16     66      0\n"
	"gpr    rb_0    .8      64      0\n"
	"gpr    rb_1    .8      65      0\n"
	"gpr    rb_2    .8      66      0\n"
	"gpr    rb_3    .8      67      0\n"

	"gpr    f       .32     68      0\n"
	"gpr    f_01    .16     68      0\n"
	"gpr    f_12    .16     69      0\n"
	"gpr    f_23    .16     70      0\n"
	"gpr    f_0     .8      68      0\n"
	"gpr    f_1     .8      69      0\n"
	"gpr    f_2     .8      70      0\n"
	"gpr    f_3     .8      71      0\n"

	"gpr    fb      .32     72      0\n"
	"gpr    fb_01   .16     72      0\n"
	"gpr    fb_12   .16     73      0\n"
	"gpr    fb_23   .16     74      0\n"
	"gpr    fb_0    .8      72      0\n"
	"gpr    fb_1    .8      73      0\n"
	"gpr    fb_2    .8      74      0\n"
	"gpr    fb_3    .8      75      0\n"

	"gpr    pll     .32     76      0\n"
	"gpr    pll_01  .16     76      0\n"
	"gpr    pll_12  .16     77      0\n"
	"gpr    pll_23  .16     78      0\n"
	"gpr    pll_0   .8      76      0\n"
	"gpr    pll_1   .8      77      0\n"
	"gpr    pll_2   .8      78      0\n"
	"gpr    pll_3   .8      79      0\n"

	"gpr    mc      .32     80      0\n"
	"gpr    mc_01   .16     80      0\n"
	"gpr    mc_12   .16     81      0\n"
	"gpr    mc_23   .16     82      0\n"
	"gpr    mc_0    .8      80      0\n"
	"gpr    mc_1    .8      81      0\n"
	"gpr    mc_2    .8      82      0\n"
	"gpr    mc_3    .8      83      0\n"

	"gpr    dt      .32     84      0\n"
	"gpr    dt_01   .16     84      0\n"
	"gpr    dt_12   .16     85      0\n"
	"gpr    dt_23   .16     86      0\n"
	"gpr    dt_0    .8      84      0\n"
	"gpr    dt_1    .8      85      0\n"
	"gpr    dt_2    .8      86      0\n"
	"gpr    dt_3    .8      87      0\n"

	"gpr    md      .16     88      0\n"
	"gpr    db      .8      90      0\n"

	"gpr    pc      .32     91      0\n"
	"gpr    sp      .32     95      0\n"
	"gpr    bp      .32     99      0\n"
	;
	return r_reg_set_profile_string (anal->reg, p);
}

RAnalPlugin r_anal_plugin_atombios = {
	.name = "atombios",
	.arch = "atombios",
	.set_reg_profile = &set_reg_profile,
	.desc = "AtomBIOS",
	.license = "LGPL3",
	.arch = "atombios",
	.bits = 32 | 64,
	.op = &atombios_op,
	.archinfo = archinfo,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_atombios,
	.version = R2_VERSION
};
#endif
