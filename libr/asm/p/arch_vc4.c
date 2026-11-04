/* radare - LGPL - Copyright 2016-2025 - pancake */

#include <r_lib.h>
#include <r_asm.h>
#include <r_arch.h>
#include <sysdep.h>

#define BUFSZ 16
#include "disas-asm.h"
#include "vc4-desc.h"
#include "vc4-opc.h"

static int vc4_buffer_read_memory (bfd_vma memaddr, bfd_byte *myaddr, ut32 length, struct disassemble_info *info) {
	int delta = (memaddr - info->buffer_vma);
	if (delta < 0) {
		return -1; // disable backward reads
	}
	if (delta >= BUFSZ) {
		return -1;
	}
	ut8 *bytes = info->buffer;
	int nlen = R_MIN (length, BUFSZ - delta);
	if (nlen > 0) {
		memcpy (myaddr, bytes + delta, nlen);
	}
	return 0;
}

static int symbol_at_address(bfd_vma addr, struct disassemble_info * info) {
	return 0;
}

static void memory_error_func(int status, bfd_vma memaddr, struct disassemble_info *info) {
	//--
}

DECLARE_GENERIC_PRINT_ADDRESS_FUNC_NOGLOBALS()
DECLARE_GENERIC_FPRINTF_FUNC_NOGLOBALS()

#include "vc4_anal.inc.c"

// the 32 alu ops of the 5 bit opcode field, addscale ops shift by n
static const char *vc4_aluops[32] = {
	"mov", "cmn", "add", "bic", "mul", "eor", "sub", "and",
	"not", "ror", "cmp", "rsub", "btest", "or", "bmask", "max",
	"bitset", "min", "bitclear", NULL, "bitflip", NULL, NULL, NULL,
	"signext", "neg", "lsr", "msb", "shl", "brev", "asr", "abs"
};

static int vc4_addscale_shift(int op) {
	switch (op) {
	case 19: return 1;
	case 21: return 2;
	case 22: return 3;
	case 23: return 4;
	}
	return 0;
}

// encodings the cgen tables get wrong or do not have
static char *vc4_predecode(ut64 addr, const ut8 *b, int len, int *size) {
	if (len < 2) {
		return NULL;
	}
	ut32 hw = r_read_le16 (b);
	if ((hw & 0xffc0) == 0x0080) {
		// cgen prints both table branches as "switch"
		*size = 2;
		return r_str_newf ("%s r%d", (hw & 0x20)? "tbh": "tbb", hw & 31);
	}
	if (len >= 4 && (hw & 0xfc00) == 0xb000) {
		// add rd, #imm16 << n, cgen drops the shift
		int op = (hw >> 5) & 31;
		int sh = vc4_addscale_shift (op);
		if (sh) {
			st32 imm = (st16)r_read_le16 (b + 2);
			*size = 4;
			return r_str_newf ("add %s,%d", vc4_regstr (hw & 31), imm * (1 << sh));
		}
	}
	if (len < 6) {
		return NULL;
	}
	ut32 imm = r_read_le32 (b + 2);
	if (hw == 0xe100 || hw == 0xe300) {
		// b / bl pc + o32
		*size = 6;
		return r_str_newf ("%s 0x%08"PFMT64x, (hw == 0xe100)? "b": "bl", (addr + (st32)imm) & UT32_MAX);
	}
	if ((hw & 0xfc00) == 0xe800) {
		// op rd, #imm32, only some ops have cgen entries
		int op = (hw >> 5) & 31;
		int sh = vc4_addscale_shift (op);
		const char *rd = vc4_regstr (hw & 31);
		*size = 6;
		if (sh) {
			return r_str_newf ("add %s,0x%x", rd, (ut32)(imm << sh));
		}
		if (vc4_aluops[op] && !strstr ("mov cmn add bic mul eor sub and cmp rsub or max min", vc4_aluops[op])) {
			return r_str_newf ("%s %s,0x%x", vc4_aluops[op], rd, imm);
		}
	}
	return NULL;
}

// disassemble one instruction, returns NULL with size -1 on read errors
static char *vc4_disasm(ut64 addr, const ut8 *buf, int len, int *size) {
	ut8 bytes[BUFSZ] = {0};
	memcpy (bytes, buf, R_MIN (len, BUFSZ));
	char *instr = vc4_predecode (addr, bytes, R_MIN (len, BUFSZ), size);
	if (instr) {
		return instr;
	}
	struct disassemble_info disasm_obj = {0};
	RStrBuf *sb = r_strbuf_new (NULL);
	disasm_obj.buffer = bytes;
	disasm_obj.buffer_vma = addr;
	disasm_obj.read_memory_func = &vc4_buffer_read_memory;
	disasm_obj.symbol_at_address_func = &symbol_at_address;
	disasm_obj.memory_error_func = &memory_error_func;
	disasm_obj.print_address_func = &generic_print_address_func;
	disasm_obj.endian = BFD_ENDIAN_LITTLE; // vc4 is little endian only
	disasm_obj.fprintf_func = &generic_fprintf_func;
	disasm_obj.stream = sb;
	*size = print_insn_vc4 ((bfd_vma)addr, &disasm_obj);
	if (*size == -1) {
		r_strbuf_free (sb);
		return NULL;
	}
	instr = r_strbuf_drain (sb);
	r_str_replace_char (instr, '\t', ' ');
	return instr;
}

static bool decode(RArchSession *a, RAnalOp *op, RArchDecodeMask mask) {
	if (op->size < 2) {
		op->mnemonic = strdup ("truncated");
		return false;
	}
	int size = 0;
	char *instr = vc4_disasm (op->addr, op->bytes, op->size, &size);
	op->size = size;
	if (!instr) {
		op->type = R_ANAL_OP_TYPE_ILL;
		return false;
	}
	if (op->size > 0) {
		vc4_anal (a, op, instr, mask);
	}
	if (mask & R_ARCH_OP_MASK_DISASM) {
		if (op->size > 0) {
			op->mnemonic = instr;
		} else {
			free (instr);
			op->mnemonic = strdup ("(data)");
		}
	} else {
		free (instr);
	}
	return true;
}

extern const CGEN_INSN *vc4_cgen_assemble_insn_at (CGEN_CPU_DESC, const char *,
	CGEN_FIELDS *, CGEN_INSN_BYTES_PTR, bfd_vma, int, char **);
extern void vc4_cgen_init_asm (CGEN_CPU_DESC);

// replaces the gas expression parser used by binutils, numbers only
static const char *parse_operand(CGEN_CPU_DESC cd, enum cgen_parse_operand_type type,
		const char **strp, int opindex, int opinfo,
		enum cgen_parse_operand_result *resultp, bfd_vma *valuep) {
	if (type == CGEN_PARSE_OPERAND_INIT) {
		return NULL;
	}
	const char *s = *strp;
	const char *e = s;
	if (*e == '-' || *e == '+') {
		e++;
	}
	while (isalnum ((ut8)*e) || *e == '_' || *e == '$') {
		e++;
	}
	if (e == s || !isdigit ((ut8)(*s == '-' || *s == '+'? s[1]: *s))) {
		return "expected a number";
	}
	char *num = r_str_ndup (s, e - s);
	RNum rn = {0};
	*valuep = r_num_math (&rn, num);
	free (num);
	if (rn.nc.errors) {
		return "invalid number";
	}
	*resultp = CGEN_PARSE_OPERAND_RESULT_NUMBER;
	*strp = e;
	return NULL;
}

static bool vc4_set_bytes(RAnalOp *op, const ut8 *buf, int size) {
	free (op->bytes);
	op->bytes = r_mem_dup (buf, size);
	op->size = size;
	return true;
}

// 48 bit forms cgen cannot assemble: far b/bl and the alu ops it lacks
static bool vc4_encode_fallback(RAnalOp *op, const char *str) {
	Vc4Insn in;
	if (!vc4_parse (str, &in) || in.cond != 14) {
		return false;
	}
	ut8 buf[6];
	if (in.nops == 1 && in.ops[0].type == VC4_OP_IMM && (!strcmp (in.base, "b") || !strcmp (in.base, "bl"))) {
		r_write_le16 (buf, (in.base[1] == 'l')? 0xe300: 0xe100);
		r_write_le32 (buf + 2, (ut32)(in.ops[0].imm - op->addr));
		return vc4_set_bytes (op, buf, 6);
	}
	if (in.nops == 2 && in.ops[0].type == VC4_OP_REG && in.ops[1].type == VC4_OP_IMM) {
		int i, rd = vc4_regnum (in.ops[0].reg);
		for (i = 0; i < 32; i++) {
			if (vc4_aluops[i] && !strcmp (vc4_aluops[i], in.base)) {
				r_write_le16 (buf, 0xe800 | (i << 5) | rd);
				r_write_le32 (buf + 2, (ut32)in.ops[1].imm);
				return vc4_set_bytes (op, buf, 6);
			}
		}
	}
	return false;
}

// collect the non zero numbers of an instruction (immediates, offsets, targets)
static int vc4_numbers(const char *text, double *nums, int max) {
	Vc4Insn in;
	if (!vc4_parse (text, &in)) {
		return -1;
	}
	int i, n = 0;
	for (i = 0; i < in.nops && n < max; i++) {
		const Vc4Operand *o = &in.ops[i];
		if (o->type == VC4_OP_IMM && o->fimm != 0) {
			nums[n++] = (o->fimm == (double)o->imm)? (double)((ut64)o->imm & UT32_MAX): o->fimm;
		} else if (o->type == VC4_OP_MEM && o->has_imm && o->imm) {
			nums[n++] = (double)((ut64)o->imm & UT32_MAX);
		} else if ((o->type == VC4_OP_REG || o->type == VC4_OP_MEM) && o->shift) {
			nums[n++] = o->shift;
		}
	}
	return n;
}

// cgen silently truncates some fields (pc relative offsets), so check that
// the encoded bytes disassemble back to the same numbers
static bool vc4_encoded_same(ut64 addr, const ut8 *buf, int len, const char *str) {
	int size = 0;
	char *back = vc4_disasm (addr, buf, len, &size);
	if (!back || size != len) {
		free (back);
		return false;
	}
	double a[VC4_MAXOPS], b[VC4_MAXOPS];
	int na = vc4_numbers (str, a, VC4_MAXOPS);
	int nb = vc4_numbers (back, b, VC4_MAXOPS);
	free (back);
	if (na < 0 || nb < 0) {
		return true; // cannot tell, trust cgen
	}
	return na == nb && !memcmp (a, b, na * sizeof (double));
}

static bool encode(RArchSession *s, RAnalOp *op, RArchEncodeMask mask) {
	static CGEN_CPU_DESC cd = NULL;
	if (!cd) {
		cd = vc4_cgen_cpu_open (CGEN_CPU_OPEN_BFDMACH, "vc4",
			CGEN_CPU_OPEN_ENDIAN, CGEN_ENDIAN_LITTLE, CGEN_CPU_OPEN_END);
		if (!cd) {
			return false;
		}
		vc4_cgen_init_asm (cd);
		cgen_set_parse_operand_fn (cd, parse_operand);
	}
	CGEN_FIELDS fields = {0};
	ut8 buf[CGEN_MAX_INSN_SIZE] = {0};
	char *errmsg = NULL;
	char *str = r_str_trim_dup (op->mnemonic);
	const CGEN_INSN *insn = vc4_cgen_assemble_insn_at (cd, str, &fields, buf, op->addr, 0, &errmsg);
	if (insn && !vc4_encoded_same (op->addr, buf, CGEN_FIELDS_BITSIZE (&fields) / 8, str)) {
		insn = NULL;
	}
	if (!insn) {
		// retry with the wider forms gas picks when relaxing
		memset (buf, 0, sizeof (buf));
		insn = vc4_cgen_assemble_insn_at (cd, str, &fields, buf, op->addr, 1, &errmsg);
		if (insn && !vc4_encoded_same (op->addr, buf, CGEN_FIELDS_BITSIZE (&fields) / 8, str)) {
			insn = NULL;
		}
	}
	if (!insn) {
		bool ok = vc4_encode_fallback (op, str);
		if (!ok) {
			R_LOG_DEBUG ("vc4: %s", errmsg? errmsg: "cannot assemble");
		}
		free (str);
		return ok;
	}
	free (str);
	return vc4_set_bytes (op, buf, CGEN_FIELDS_BITSIZE (&fields) / 8);
}

static int info(RArchSession *s, ut32 q) {
#if R2_VERSION_NUMBER >= 50909
	switch (q) {
	case R_ARCH_INFO_MINOP_SIZE:
		return 2;
	case R_ARCH_INFO_MAXOP_SIZE:
		return 10;
	}
#else
	switch (q) {
	case R_ARCH_INFO_MIN_OP_SIZE:
		return 2;
	case R_ARCH_INFO_MAX_OP_SIZE:
		return 10;
	}
#endif
	return 2;
}

static char *getregs(RArchSession *as) {
	const char *const p =
		"=PC	pc\n"
		"=SP	sp\n"
		"=GP	gp\n"
		"=SR	sr\n"
		"=LR	lr\n"
		"=A0	r0\n"
		"=A1	r1\n"
		"=A2	r2\n"
		"=A3	r3\n"
		"=A4	r4\n"
		"=A5	r5\n"
		"=R0	r0\n"
		"=SN	r0\n"	// Avoid warning but wrong: register holding
						// syscall number changes depending on the
						// instructions (swi r0, swi r1, ...)
		"gpr	r0	.32	0	0\n"
		"gpr	r1	.32	8	0\n"
		"gpr	r2	.32	16	0\n"
		"gpr	r3	.32	24	0\n"
		"gpr	r4	.32	32	0\n"
		"gpr	r5	.32	40	0\n"
		"gpr	r6	.32	48	0\n"
		"gpr	r7	.32	56	0\n"
		"gpr	r8	.32	64	0\n"
		"gpr	r9	.32	72	0\n"
		"gpr	r10	.32	80	0\n"
		"gpr	r11	.32	88	0\n"
		"gpr	r12	.32	96	0\n"
		"gpr	r13	.32	104	0\n"
		"gpr	r14	.32	112	0\n"
		"gpr	r15	.32	120	0\n"
		"gpr	r16	.32	128	0\n"
		"gpr	r17	.32	136	0\n"
		"gpr	r18	.32	144	0\n"
		"gpr	r19	.32	152	0\n"
		"gpr	r20	.32	160	0\n"
		"gpr	r21	.32	168	0\n"
		"gpr	r22	.32	176	0\n"
		"gpr	r23	.32	184	0\n"
		"gpr	gp	.32	192	0\n"
		"gpr	sp	.32	200	0\n"
		"gpr	lr	.32	208	0\n"
		"gpr	r27	.32	216	0\n"
		"gpr	r28	.32	224	0\n"
		"gpr	r29	.32	232	0\n"
		"gpr	sr	.32	240	0\n"
		"gpr	pc	.32	248	0\n"
		"flg	vf	.1	.1920	0\n"
		"flg	cf	.1	.1921	0\n"
		"flg	nf	.1	.1922	0\n"
		"flg	zf	.1	.1923	0\n"
		;
	return strdup (p);
}

RArchPlugin r_arch_plugin_vc4 = {
	.meta = {
		.name = "vc4",
		.desc = "VideoCore IV",
		.license = "GPL-3.0-only",
		.status = R_PLUGIN_STATUS_OK,
	},
	.arch = "vc4",
	.bits = R_SYS_BITS_PACK1 (32),
	.endian = R_SYS_ENDIAN_LITTLE,
	.info = &info,
	.regs = getregs,
	.decode = &decode,
	.encode = &encode
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ARCH,
	.data = &r_arch_plugin_vc4,
	.version = R2_VERSION
};
#endif
