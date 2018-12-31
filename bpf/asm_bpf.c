/*
 * Most of this is copied and pasted from linux source (except
 * for the assembler part).
 *
 * Copyright 2015 - mrmacete <mrmacete@protonmail.ch>
 * Licensed under the GNU General Public License, version 2.0 (GPLv2)
 */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_asm.h>
#include "bpf.h"

static int disassemble(RAsm *a, RAsmOp *r_op, const ut8 *buf, int len) {
	const char *op, *fmt;
	RBpfSockFilter *f = (RBpfSockFilter *)buf;
	int val = f->k;
	char vbuf[256];

	switch (f->code) {
	case BPF_RET | BPF_K:
		op = r_bpf_op_table[BPF_RET];
		fmt = "%#x";
		break;
	case BPF_RET | BPF_A:
		op = r_bpf_op_table[BPF_RET];
		fmt = "a";
		break;
	case BPF_RET | BPF_X:
		op = r_bpf_op_table[BPF_RET];
		fmt = "x";
		break;
	case BPF_MISC_TAX:
		op = r_bpf_op_table[BPF_MISC_TAX];
		fmt = "";
		break;
	case BPF_MISC_TXA:
		op = r_bpf_op_table[BPF_MISC_TXA];
		fmt = "";
		break;
	case BPF_ST:
		op = r_bpf_op_table[BPF_ST];
		fmt = "M[%d]";
		break;
	case BPF_STX:
		op = r_bpf_op_table[BPF_STX];
		fmt = "M[%d]";
		break;
	case BPF_LD_W | BPF_ABS:
		op = r_bpf_op_table[BPF_LD_W];
		fmt = "[%d]";
		break;
	case BPF_LD_H | BPF_ABS:
		op = r_bpf_op_table[BPF_LD_H];
		fmt = "[%d]";
		break;
	case BPF_LD_B | BPF_ABS:
		op = r_bpf_op_table[BPF_LD_B];
		fmt = "[%d]";
		break;
	case BPF_LD_W | BPF_LEN:
		op = r_bpf_op_table[BPF_LD_W];
		fmt = "len";
		break;
	case BPF_LD_W | BPF_IND:
		op = r_bpf_op_table[BPF_LD_W];
		fmt = "[x+%d]";
		break;
	case BPF_LD_H | BPF_IND:
		op = r_bpf_op_table[BPF_LD_H];
		fmt = "[x+%d]";
		break;
	case BPF_LD_B | BPF_IND:
		op = r_bpf_op_table[BPF_LD_B];
		fmt = "[x+%d]";
		break;
	case BPF_LD | BPF_IMM:
		op = r_bpf_op_table[BPF_LD_W];
		fmt = "%#x";
		break;
	case BPF_LDX | BPF_IMM:
		op = r_bpf_op_table[BPF_LDX];
		fmt = "%#x";
		break;
	case BPF_LDX | BPF_LEN:
		op = r_bpf_op_table[BPF_LDX];
		fmt = "len";
		break;
	case BPF_LDX | BPF_ABS:
		op = r_bpf_op_table[BPF_LDX];
		fmt = "[%d]";
		break;
	case BPF_LDX_B | BPF_MSH:
		op = r_bpf_op_table[BPF_LDX_B];
		fmt = "4*([%d]&0xf)";
		break;
	case BPF_LD | BPF_MEM:
		op = r_bpf_op_table[BPF_LD_W];
		fmt = "M[%d]";
		break;
	case BPF_LDX | BPF_MEM:
		op = r_bpf_op_table[BPF_LDX];
		fmt = "M[%d]";
		break;
	case BPF_JMP_JA:
		op = r_bpf_op_table[BPF_JMP_JA];
		fmt = "%d";
		val = a->pc + 8 + f->k * 8;
		break;
	case BPF_JMP_JGT | BPF_X:
		op = r_bpf_op_table[BPF_JMP_JGT];
		fmt = "x";
		break;
	case BPF_JMP_JGT | BPF_K:
		op = r_bpf_op_table[BPF_JMP_JGT];
		fmt = "%#x";
		break;
	case BPF_JMP_JGE | BPF_X:
		op = r_bpf_op_table[BPF_JMP_JGE];
		fmt = "x";
		break;
	case BPF_JMP_JGE | BPF_K:
		op = r_bpf_op_table[BPF_JMP_JGE];
		fmt = "%#x";
		break;
	case BPF_JMP_JEQ | BPF_X:
		op = r_bpf_op_table[BPF_JMP_JEQ];
		fmt = "x";
		break;
	case BPF_JMP_JEQ | BPF_K:
		op = r_bpf_op_table[BPF_JMP_JEQ];
		fmt = "%#x";
		break;
	case BPF_JMP_JSET | BPF_X:
		op = r_bpf_op_table[BPF_JMP_JSET];
		fmt = "x";
		break;
	case BPF_JMP_JSET | BPF_K:
		op = r_bpf_op_table[BPF_JMP_JSET];
		fmt = "%#x";
		break;
	case BPF_ALU_NEG:
		op = r_bpf_op_table[BPF_ALU_NEG];
		fmt = "";
		break;
	case BPF_ALU_LSH | BPF_X:
		op = r_bpf_op_table[BPF_ALU_LSH];
		fmt = "x";
		break;
	case BPF_ALU_LSH | BPF_K:
		op = r_bpf_op_table[BPF_ALU_LSH];
		fmt = "%d";
		break;
	case BPF_ALU_RSH | BPF_X:
		op = r_bpf_op_table[BPF_ALU_RSH];
		fmt = "x";
		break;
	case BPF_ALU_RSH | BPF_K:
		op = r_bpf_op_table[BPF_ALU_RSH];
		fmt = "%d";
		break;
	case BPF_ALU_ADD | BPF_X:
		op = r_bpf_op_table[BPF_ALU_ADD];
		fmt = "x";
		break;
	case BPF_ALU_ADD | BPF_K:
		op = r_bpf_op_table[BPF_ALU_ADD];
		fmt = "%d";
		break;
	case BPF_ALU_SUB | BPF_X:
		op = r_bpf_op_table[BPF_ALU_SUB];
		fmt = "x";
		break;
	case BPF_ALU_SUB | BPF_K:
		op = r_bpf_op_table[BPF_ALU_SUB];
		fmt = "%d";
		break;
	case BPF_ALU_MUL | BPF_X:
		op = r_bpf_op_table[BPF_ALU_MUL];
		fmt = "x";
		break;
	case BPF_ALU_MUL | BPF_K:
		op = r_bpf_op_table[BPF_ALU_MUL];
		fmt = "%d";
		break;
	case BPF_ALU_DIV | BPF_X:
		op = r_bpf_op_table[BPF_ALU_DIV];
		fmt = "x";
		break;
	case BPF_ALU_DIV | BPF_K:
		op = r_bpf_op_table[BPF_ALU_DIV];
		fmt = "%d";
		break;
	case BPF_ALU_MOD | BPF_X:
		op = r_bpf_op_table[BPF_ALU_MOD];
		fmt = "x";
		break;
	case BPF_ALU_MOD | BPF_K:
		op = r_bpf_op_table[BPF_ALU_MOD];
		fmt = "%d";
		break;
	case BPF_ALU_AND | BPF_X:
		op = r_bpf_op_table[BPF_ALU_AND];
		fmt = "x";
		break;
	case BPF_ALU_AND | BPF_K:
		op = r_bpf_op_table[BPF_ALU_AND];
		fmt = "%#x";
		break;
	case BPF_ALU_OR | BPF_X:
		op = r_bpf_op_table[BPF_ALU_OR];
		fmt = "x";
		break;
	case BPF_ALU_OR | BPF_K:
		op = r_bpf_op_table[BPF_ALU_OR];
		fmt = "%#x";
		break;
	case BPF_ALU_XOR | BPF_X:
		op = r_bpf_op_table[BPF_ALU_XOR];
		fmt = "x";
		break;
	case BPF_ALU_XOR | BPF_K:
		op = r_bpf_op_table[BPF_ALU_XOR];
		fmt = "%#x";
		break;
	default:
		op = "invalid";
		fmt = "%#x";
		val = f->code;
		break;
	}

	memset (vbuf, 0, sizeof (vbuf));
	snprintf (vbuf, sizeof (vbuf), fmt, val);
	vbuf[sizeof (vbuf) - 1] = 0;

	if ((BPF_CLASS (f->code) == BPF_JMP && BPF_OP (f->code) != BPF_JA))
		r_strbuf_setf (&r_op->buf_asm, "%s %s, 0x%08" PFMT64x ", 0x%08" PFMT64x "", op, vbuf,
			a->pc + 8 + f->jt * 8, a->pc + 8 + f->jf * 8);
	else r_strbuf_setf (&r_op->buf_asm, "%s %s", op, vbuf);

	return r_op->size = 8;
}

/* start of ASSEMBLER code */

#define PARSER_MAX_TOKENS 4

#define COPY_AND_RET(a, b)\
	r_strbuf_setbin (&a, (const ut8 *)b, sizeof (*b) + 1);\
	return 0;

#define PARSE_FAILURE(message, arg...)\
	{\
		eprintf ("PARSE FAILURE: " message "\n", ##arg);\
		return -1;\
	}

#define CMP4(tok, n, x, y, z, w)\
	(tok[n][0] == x && tok[n][1] == y && tok[n][2] == z && tok[n][3] == w)

#define CMP3(tok, n, x, y, z)\
	(tok[n][0] == x && tok[n][1] == y && tok[n][2] == z)

#define CMP2(tok, n, x, y)\
	(tok[n][0] == x && tok[n][1] == y)

#define IS_K_TOK(tok, n)\
	(tok[n][0] == '-' || R_BETWEEN ('0', tok[n][0], '9'))

#define IS_LEN(tok, n)\
	CMP4 (tok, n, 'l', 'e', 'n', '\0')

#define PARSE_K_OR_FAIL(dst, tok, n)\
	dst = strtol (&tok[n][0], &end, 0);\
	if (*end != '\0' && *end != ',')\
		PARSE_FAILURE ("could not parse k");

#define PARSE_LABEL_OR_FAIL(dst, tok, n)\
	dst = strtoul (&tok[n][0], &end, 0);\
	if (*end != '\0' && *end != ',') {\
		return -1;\
	}

#define PARSE_OFFSET_OR_FAIL(dst, tok, n, off)\
	dst = strtoul (&tok[n][off], &end, 10);\
	if (*end != ']')\
		PARSE_FAILURE ("could not parse offset value");

#define PARSE_IND_ABS_OR_FAIL(f, tok, n)\
	if (CMP3 (tok, 1, '[', 'x', '+')) {\
		f->code = f->code | BPF_IND;\
		PARSE_OFFSET_OR_FAIL (f->k, tok, 1, 3);\
		return 0;\
	} else if (tok[1][0] == '[') {\
		f->code = f->code | BPF_ABS;\
		PARSE_OFFSET_OR_FAIL (f->k, tok, 1, 1);\
		return 0;\
	}\
	PARSE_FAILURE ("could not parse addressing mode");

#define PARSE_K_OR_X_OR_FAIL(f, tok)\
	if (IS_K_TOK (tok, 1)) {\
		PARSE_K_OR_FAIL (f->k, tok, 1);\
		f->code = f->code | BPF_K;\
	} else if (tok[1][0] == 'x' && (tok[1][1] == '\0' || tok[1][1] == ',')) {\
		f->code = f->code | BPF_X;\
	} else {\
		PARSE_FAILURE ("could not parse k or x: %s", tok[1]);\
	}

#define PARSE_A_OR_X_OR_FAIL(f, tok)\
	if (tok[1][0] == 'x' && (tok[1][1] == '\0' || tok[1][1] == ',')) {\
		f->code = f->code | BPF_X;\
	} else if (tok[1][0] == 'a' && (tok[1][1] == '\0' || tok[1][1] == ',')) {\
		f->code = f->code | BPF_A;\
	} else {\
		PARSE_FAILURE ("could not parse a or x");\
	}

#define PARSE_JUMP_TARGETS(a, f, tok, count)\
	PARSE_K_OR_X_OR_FAIL (f, tok);\
	if (count >= 3) {\
		PARSE_LABEL_OR_FAIL (label, tok, 2);\
		f->jt = (st64) (label - a->pc - 8) / 8;\
		f->jf = (a->pc >> 3) + 1;\
	}\
	if (count == 4) {\
		PARSE_LABEL_OR_FAIL (label, tok, 3);\
		f->jf = (st64) (label - a->pc - 8) / 8;\
	}

#define SWAP_JUMP_TARGETS(f)\
	temp = f->jt;\
	f->jt = f->jf;\
	f->jf = temp;

#define ENFORCE_COUNT(count, n)\
	if (count != n)\
		PARSE_FAILURE ("invalid argument count, try to omit '#'");

#define ENFORCE_COUNT_GE(count, n)\
	if (count < n)\
		PARSE_FAILURE ("invalid argument count, try to omit '#'");

static int assemble_ld(RAsm *a, RAsmOp *op,
	char *tok[PARSER_MAX_TOKENS], int count, RBpfSockFilter *f) {
	char *end;

	switch (tok[0][2]) {
	case '\0':
		if (CMP2 (tok, 1, 'm', '[')) {
			f->code = BPF_LD | BPF_MEM;
			PARSE_OFFSET_OR_FAIL (f->k, tok, 1, 2);
		} else if (IS_K_TOK (tok, 1)) {
			f->code = BPF_LD | BPF_IMM;
			PARSE_K_OR_FAIL (f->k, tok, 1);
		} else if (IS_LEN (tok, 1)) {
			f->code = BPF_LD | BPF_LEN;
		} else {
			f->code = BPF_LD_W;
			PARSE_IND_ABS_OR_FAIL (f, tok, 1);
		}
		break;
	case 'i':
		if (IS_K_TOK (tok, 1)) {
			f->code = BPF_LD | BPF_IMM;
			PARSE_K_OR_FAIL (f->k, tok, 1);
		} else {
			PARSE_FAILURE ("ldi without k");
		}
		break;
	case 'b':
		f->code = BPF_LD_B;
		PARSE_IND_ABS_OR_FAIL (f, tok, 1);
		break;
	case 'h':
		f->code = BPF_LD_H;
		PARSE_IND_ABS_OR_FAIL (f, tok, 1);
		break;
	case 'x':
		switch (tok[0][3]) {
		case '\0':
			if (CMP2 (tok, 1, 'm', '[')) {
				f->code = BPF_LDX | BPF_MEM;
				PARSE_OFFSET_OR_FAIL (f->k, tok, 1, 2);
			} else if (IS_K_TOK (tok, 1)) {
				f->code = BPF_LDX | BPF_IMM;
				PARSE_K_OR_FAIL (f->k, tok, 1);
			} else if (IS_LEN (tok, 1)) {
				f->code = BPF_LDX | BPF_LEN;
			} else {
				f->code = BPF_LDX_W;
				PARSE_IND_ABS_OR_FAIL (f, tok, 1);
			}
			break;
		case 'i':
			if (IS_K_TOK (tok, 1)) {
				f->code = BPF_LDX | BPF_IMM;
				PARSE_K_OR_FAIL (f->k, tok, 1);
			} else {
				PARSE_FAILURE ("ldxi without k");
			}
			break;
		case 'b':
			f->code = BPF_LDX_B | BPF_MSH;
			if (sscanf (tok[1], "4*([%d]&0xf)", &f->k) != 1) {
				PARSE_FAILURE ("invalid nibble addressing");
			}
			break;
		}
		break;
	default:
		PARSE_FAILURE ("unsupported load instruction");
	}

	return 0;
}

static int assemble_j(RAsm *a, RAsmOp *op, char *tok[PARSER_MAX_TOKENS],
	int count, RBpfSockFilter *f) {
	int label;
	ut8 temp;
	char *end;

	if (CMP4 (tok, 0, 'j', 'm', 'p', '\0') ||
		CMP3 (tok, 0, 'j', 'a', '\0')) {
		ENFORCE_COUNT (count, 2);
		f->code = BPF_JMP_JA;
		PARSE_LABEL_OR_FAIL (f->k, tok, 1);
		return 0;
	}

	if (CMP4 (tok, 0, 'j', 'n', 'e', '\0') ||
		CMP4 (tok, 0, 'j', 'n', 'e', 'q')) {
		ENFORCE_COUNT_GE (count, 3);
		f->code = BPF_JMP_JEQ;
		PARSE_JUMP_TARGETS (a, f, tok, count);
		SWAP_JUMP_TARGETS (f);
		return 0;
	}

	if (CMP4 (tok, 0, 'j', 'e', 'q', '\0')) {
		ENFORCE_COUNT_GE (count, 3);
		f->code = BPF_JMP_JEQ;
		PARSE_JUMP_TARGETS (a, f, tok, count);
		return 0;
	}

	if (CMP4 (tok, 0, 'j', 'l', 't', '\0')) {
		ENFORCE_COUNT_GE (count, 3);
		f->code = BPF_JMP_JGE;
		PARSE_JUMP_TARGETS (a, f, tok, count);
		SWAP_JUMP_TARGETS (f);
		return 0;
	}

	if (CMP4 (tok, 0, 'j', 'l', 'e', '\0')) {
		ENFORCE_COUNT_GE (count, 3);
		f->code = BPF_JMP_JGT;
		PARSE_JUMP_TARGETS (a, f, tok, count);
		SWAP_JUMP_TARGETS (f);
		return 0;
	}

	if (CMP4 (tok, 0, 'j', 'g', 't', '\0')) {
		ENFORCE_COUNT_GE (count, 3);
		f->code = BPF_JMP_JGT;
		PARSE_JUMP_TARGETS (a, f, tok, count);
		return 0;
	}

	if (CMP4 (tok, 0, 'j', 'g', 'e', '\0')) {
		ENFORCE_COUNT_GE (count, 3);
		f->code = BPF_JMP_JGE;
		PARSE_JUMP_TARGETS (a, f, tok, count);
		return 0;
	}

	if (CMP4 (tok, 0, 'j', 's', 'e', 't')) {
		ENFORCE_COUNT_GE (count, 3);
		f->code = BPF_JMP_JSET;
		PARSE_JUMP_TARGETS (a, f, tok, count);
		return 0;
	}

	return -1;
}

static int assemble_alu(RAsm *a, RAsmOp *op, char *tok[PARSER_MAX_TOKENS],
	int count, RBpfSockFilter *f) {
	char *end;

	if (CMP4 (tok, 0, 'a', 'd', 'd', '\0')) {
		ENFORCE_COUNT (count, 2);
		f->code = BPF_ALU_ADD;
		PARSE_K_OR_X_OR_FAIL (f, tok);
		return 0;
	}

	if (CMP4 (tok, 0, 's', 'u', 'b', '\0')) {
		ENFORCE_COUNT (count, 2);
		f->code = BPF_ALU_SUB;
		PARSE_K_OR_X_OR_FAIL (f, tok);
		return 0;
	}

	if (CMP4 (tok, 0, 'm', 'u', 'l', '\0')) {
		ENFORCE_COUNT (count, 2);
		f->code = BPF_ALU_MUL;
		PARSE_K_OR_X_OR_FAIL (f, tok);
		return 0;
	}

	if (CMP4 (tok, 0, 'd', 'i', 'v', '\0')) {
		ENFORCE_COUNT (count, 2);
		f->code = BPF_ALU_DIV;
		PARSE_K_OR_X_OR_FAIL (f, tok);
		return 0;
	}

	if (CMP4 (tok, 0, 'm', 'o', 'd', '\0')) {
		ENFORCE_COUNT (count, 2);
		f->code = BPF_ALU_MOD;
		PARSE_K_OR_X_OR_FAIL (f, tok);
		return 0;
	}

	if (CMP4 (tok, 0, 'n', 'e', 'g', '\0')) {
		ENFORCE_COUNT (count, 1);
		f->code = BPF_ALU_NEG;
		return 0;
	}

	if (CMP4 (tok, 0, 'a', 'n', 'd', '\0')) {
		ENFORCE_COUNT (count, 2);
		f->code = BPF_ALU_AND;
		PARSE_K_OR_X_OR_FAIL (f, tok);
		return 0;
	}

	if (CMP3 (tok, 0, 'o', 'r', '\0')) {
		ENFORCE_COUNT (count, 2);
		f->code = BPF_ALU_OR;
		PARSE_K_OR_X_OR_FAIL (f, tok);
		return 0;
	}

	if (CMP4 (tok, 0, 'x', 'o', 'r', '\0')) {
		ENFORCE_COUNT (count, 2);
		f->code = BPF_ALU_XOR;
		PARSE_K_OR_X_OR_FAIL (f, tok);
		return 0;
	}

	if (CMP4 (tok, 0, 'l', 's', 'h', '\0')) {
		ENFORCE_COUNT (count, 2);
		f->code = BPF_ALU_LSH;
		PARSE_K_OR_X_OR_FAIL (f, tok);
		return 0;
	}

	if (CMP4 (tok, 0, 'r', 's', 'h', '\0')) {
		ENFORCE_COUNT (count, 2);
		f->code = BPF_ALU_RSH;
		PARSE_K_OR_X_OR_FAIL (f, tok);
		return 0;
	}

	return -1;
}

static int assemble_tok(RAsm *a, RAsmOp *op,
	char *tok[PARSER_MAX_TOKENS], int count) {
	char *end;
	int oplen = 0;
	RBpfSockFilter f = { 0, 0, 0, 0 };
	oplen = strnlen (tok[0], 5);

	if (oplen < 2 || oplen > 4) {
		PARSE_FAILURE ("mnemonic length not valid");
	}

	if (CMP4 (tok, 0, 't', 'x', 'a', '\0')) {
		ENFORCE_COUNT (count, 1);
		f.code = BPF_MISC_TXA;
		COPY_AND_RET (op->buf, &f);
	}

	if (CMP4 (tok, 0, 't', 'a', 'x', '\0')) {
		ENFORCE_COUNT (count, 1);
		f.code = BPF_MISC_TAX;
		COPY_AND_RET (op->buf, &f);
	}

	if (CMP4 (tok, 0, 'r', 'e', 't', '\0')) {
		ENFORCE_COUNT (count, 2);
		if (IS_K_TOK (tok, 1)) {
			f.code = BPF_RET | BPF_K;
			PARSE_K_OR_FAIL (f.k, tok, 1);
		} else if (tok[1][0] == 'x') {
			f.code = BPF_RET | BPF_X;
		} else if (tok[1][0] == 'a') {
			f.code = BPF_RET | BPF_A;
		} else {
			PARSE_FAILURE ("unsupported ret instruction");
		}
		COPY_AND_RET (op->buf, &f);
	}

	if (CMP2 (tok, 0, 'l', 'd')) {
		ENFORCE_COUNT (count, 2);
		if (assemble_ld (a, op, tok, count, &f) == 0) {
			COPY_AND_RET (op->buf, &f);
		} else {
			return -1;
		}
	}

	if (CMP2 (tok, 0, 's', 't')) {
		ENFORCE_COUNT (count, 2);
		if (tok[0][2] == '\0') {
			f.code = BPF_ST;
		} else if (tok[0][2] == 'x') {
			f.code = BPF_STX;
		}

		if (CMP2 (tok, 1, 'm', '[')) {
			PARSE_OFFSET_OR_FAIL (f.k, tok, 1, 2);
			if (f.k > 15) {
				PARSE_FAILURE ("mem addressing out of bounds");
			}
			COPY_AND_RET (op->buf, &f);
		} else {
			PARSE_FAILURE ("invalid store addressing");
		}
	}

	if (tok[0][0] == 'j') {
		if (assemble_j (a, op, tok, count, &f) == 0) {
			COPY_AND_RET (op->buf, &f);
		} else {
			return -1;
		}
	}

	if (assemble_alu (a, op, tok, count, &f) == 0) {
		COPY_AND_RET (op->buf, &f);
	} else {
		return -1;
	}
}

static void lower_op(char *c) {
	if ((c[0] <= 'Z') && (c[0] >= 'A')) {
		c[0] += 0x20;
	}
}
#define R_TRUE 1
static void normalize(RStrBuf *buf) {
	int i;
	char *buf_asm;
	if (!buf)
		return;
	buf_asm = r_strbuf_get (buf);

	/* this normalization step is largely sub-optimal */

	i = strlen (buf_asm);
	while (strstr (buf_asm, "  ")) {
		r_str_replace_in (buf_asm, (ut32)i, "  ", " ", R_TRUE);
	}
	r_str_replace_in (buf_asm, (ut32)i, " ,", ",", R_TRUE);
	r_str_replace_in (buf_asm, (ut32)i, "[ ", "[", R_TRUE);
	r_str_replace_in (buf_asm, (ut32)i, " ]", "]", R_TRUE);
	r_str_replace_in (buf_asm, (ut32)i, "( ", "(", R_TRUE);
	r_str_replace_in (buf_asm, (ut32)i, " )", ")", R_TRUE);
	r_str_replace_in (buf_asm, (ut32)i, "+ ", "+", R_TRUE);
	r_str_replace_in (buf_asm, (ut32)i, " +", "+", R_TRUE);
	r_str_replace_in (buf_asm, (ut32)i, "* ", "*", R_TRUE);
	r_str_replace_in (buf_asm, (ut32)i, " *", "*", R_TRUE);
	r_str_replace_in (buf_asm, (ut32)i, "& ", "&", R_TRUE);
	r_str_replace_in (buf_asm, (ut32)i, " &", "&", R_TRUE);
	r_str_replace_in (buf_asm, (ut32)i, "%", "", R_TRUE);
	r_str_replace_in (buf_asm, (ut32)i, "#", "", R_TRUE);
	r_str_do_until_token (lower_op, buf_asm, '\0');
	r_strbuf_set (buf, buf_asm);
}

static int assemble(RAsm *a, RAsmOp *op, const char *buf) {
	char *tok[PARSER_MAX_TOKENS];
	char tmp[128];
	int i, j, l;
	const char *p = NULL;
	if (!a || !op || !buf) {
		return 0;
	}

	r_strbuf_set (&op->buf_asm, buf);
	normalize (&op->buf_asm);

	// tokenization, copied from profile.c
	j = 0;
	p = r_strbuf_get (&op->buf_asm);

	// For every word
	while (*p) {
		// Skip the whitespace
		while (*p == ' ' || *p == '\t') {
			p++;
		}
		// Skip the rest of the line is a comment is encountered
		if (*p == ';') {
			while (*p != '\0') {
				p++;
			}
		}
		// EOL ?
		if (*p == '\0') {
			break;
		}
		// Gather a handful of chars
		// Use isgraph instead of isprint because the latter considers ' ' printable
		for (i = 0; isgraph ((const unsigned char)*p) && i < sizeof (tmp) - 1;) {
			tmp[i++] = *p++;
		}
		tmp[i] = '\0';
		// Limit the number of tokens
		if (j > PARSER_MAX_TOKENS - 1) {
			break;
		}
		// Save the token
		tok[j++] = strdup (tmp);
	}

	if (j) {
		if (assemble_tok (a, op, tok, j) < 0) {
			return -1;
		}

		// Clean up
		for (i = 0; i < j; i++) {
			free (tok[i]);
		}
	}

	return op->size = 8;
}

RAsmPlugin r_asm_plugin_bpf = {
	.name = "bpf",
	.desc = "Berkeley Packet Filter disassembler",
	.license = "GPLv2",
	.arch = "bpf",
	.bits = 32,
	.disassemble = &disassemble,
	.assemble = &assemble
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_bpf,
	.version = R2_VERSION
};
#endif
