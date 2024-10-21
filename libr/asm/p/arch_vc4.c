/* radare - LGPL - Copyright 2016 - pancake */

#include <r_lib.h>
#include <r_asm.h>
#include <r_arch.h>
#include <sysdep.h>

#define BUFSZ 8
#include "opcode/cgen.h"
#include "disas-asm.h"
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

static void parse_immediate_in_instruction_str(char *instr, ut64* i1, ut64* i2, ut64* i3, ut64* i4, ut64* shift) {
	char *cur;

	// Go to the first operand
	cur = instr;
	cur = strchr (cur, ' ');
	if (cur) {
		cur++;

		// Skip potential leading '#'
		if (*cur == '#') {
			cur++;
		}

		// If it's a digit, get the integer
		if ('0' <= *cur && *cur <= '9') {
			*i1 = r_num_get (NULL, cur);
		}

		// Go to the next operand and repeat
		cur = strchr (cur, ',');
		if (cur) {
			cur++;

			if (*cur == '#') {
				cur++;
			}
			if ('0' <= *cur && *cur <= '9') {
				*i2 = r_num_get (NULL, cur);
			}

			cur = strchr (cur, ',');
			if (cur) {
				cur++;

				if (*cur == '#') {
					cur++;
				}
				if ('0' <= *cur && *cur <= '9') {
					*i3 = r_num_get (NULL, cur);
				}

				cur = strchr (cur, ',');
				if (cur) {
					cur++;

					if (*cur == '#') {
						cur++;
					}
					if ('0' <= *cur && *cur <= '9') {
						*i4 = r_num_get (NULL, cur);
					}
				}
			}
		}
	}

	// Catch "r1<<immediate" format
	if ((cur = strstr (instr, "<<")) || (cur = strstr (instr, ">>"))) {
		*shift = r_num_get (NULL, cur+2);
	}
}

static bool parse_one_register(char *str, char reg[4]) {
	ut64 register_number;

	// Skip the potential '('
	if (*str == '(') {
		str++;
	}

	if (*str == 'r') { // r0..r29
		str++; // go to the register number
		register_number = r_num_get (NULL, str);
		snprintf (reg, 4, "r%li", register_number);
	} else if (*str == 'p' || *str == 's' ||
			  *str == 'g' || *str == 'l') { // pc, sp, sr, gp or lr
		reg[0] = str[0];
		reg[1] = str[1];
		reg[2] = '\0';
	} else {
		reg[0] = '\0';
		return false;
	}

	return true;
}

static void parse_registers_in_instruction_str(char *instr, char reg1[4], char reg2[4], char reg3[4], char regEndRange[4]) {
	char *cur, *next, *deref;
	bool parsed;

	cur = instr;

	// Skip the mnemonic
	next = strchr (cur, ' ');
	if (next) {
		cur = next+1;
		parsed = parse_one_register (cur, reg1);

		// Go to the next operand
		next = strchr (cur, ',');

		// For "0xVV(rXX)" format
		deref = strstr (cur, "(");
		if (!parsed && deref) {
			// Check that we aren't parsing the next operand
			if (!next || deref < next) {
				cur = deref+1;
				parse_one_register (cur, reg1);
			}
		}

		if (next) {
			cur = next+1;
			parsed = parse_one_register (cur, reg2);

			next = strchr (cur, ',');

			// For "0xVV(rXX)" format
			deref = strchr (cur, '(');
			if (!parsed && deref) {
				// Check that we aren't parsing the next operand
				if (!next || deref < next) {
					cur = deref+1;
					parse_one_register (cur, reg2);
				}
			}

			if (next) {
				cur = next+1;
				parse_one_register (cur, reg3);

				// For "0xVV(rXX)" format
				deref = strchr (cur, '(');
				if (!parsed && deref) {
					cur = deref+1;
					parse_one_register (cur, reg2);
				}
			}
		}
	}

	// Catch range format "rX-rY"
	cur = strstr (instr, "-r");
	if (cur) {
		cur++;
		parse_one_register (cur, regEndRange);
	}
}

#define ADD_REG_TO_LIST_OR_BREAK(reg_list, access, reg) if (!_add_reg_to_list ((reg_list), (access), (reg))) break
static bool _add_reg_to_list(RList *reg_list, int access, const char* reg) {
	RAnalValue *val;

	val = r_anal_value_new ();
	if (!val) {
		return false;
	}

	val->type = R_ANAL_VAL_REG;
	val->access = access;
	val->reg = reg;
	r_list_append (reg_list, val);

	return true;
}

static bool decode(RArchSession *a, RAnalOp *op, RArchDecodeMask mask) {
	ut8 bytes[BUFSZ] = {0};
	struct disassemble_info disasm_obj = {0};
	if (op->size < 2) {
		op->mnemonic = strdup ("truncated");
		return false;
	}
	RStrBuf *sb = r_strbuf_new (NULL);
	memcpy (bytes, op->bytes, R_MIN (op->size, BUFSZ));

	/* prepare disassembler */
	disasm_obj.disassembler_options = (a->config->bits == 64)? "64": "";
	disasm_obj.buffer = bytes;
	disasm_obj.buffer_vma = op->addr;
	disasm_obj.read_memory_func = &vc4_buffer_read_memory;
	disasm_obj.symbol_at_address_func = &symbol_at_address;
	disasm_obj.memory_error_func = &memory_error_func;
	disasm_obj.print_address_func = &generic_print_address_func;
	disasm_obj.endian = a->config->big_endian;
	disasm_obj.fprintf_func = &generic_fprintf_func;
	disasm_obj.stream = sb;
	disasm_obj.private_data = NULL; // Used to get the insn for the switch case

	op->size = print_insn_vc4 ((bfd_vma)op->addr, &disasm_obj);
	if (op->size == -1) {
		op->type = R_ANAL_OP_TYPE_ILL;
		return false;
	}

	char *instr = sb? r_strbuf_drain (sb): NULL;

	if (instr) {
		if (disasm_obj.private_data != NULL) {
			const CGEN_INSN *cgen_insn = (const CGEN_INSN *) disasm_obj.private_data;
			ut64 i1 = 0, i2 = 0, i3 = 0, i4 = 0, shift = 0;
			char reg1[4] = {0}, reg2[4] = {0}, reg3[4] = {0}, regEndRange[4] = {0};
			bool is_pop = false;
			ut64 nb_stack_op;
			RList *access_list;
			RAnalValue *val;

			// Parse the string of the instruction to retrieve immediate
			// values and register numbers
			parse_immediate_in_instruction_str (instr, &i1, &i2, &i3, &i4, &shift);
			parse_registers_in_instruction_str (instr, reg1, reg2, reg3, regEndRange);

			op->type = R_ANAL_OP_TYPE_NULL;
			op->stackop = R_ANAL_STACK_NULL;

			switch (CGEN_INSN_NUM (cgen_insn)) {

			case VC4_INSN_INVALID:
				op->type = R_ANAL_OP_TYPE_ILL;
				break;

			case VC4_INSN_NOP:
				op->type = R_ANAL_OP_TYPE_NOP;
				break;

			case VC4_INSN_BKPT:
				op->type = R_ANAL_OP_TYPE_TRAP;
				break;

			case VC4_INSN_SWIIMM:
				op->type = R_ANAL_OP_TYPE_SWI;
				op->val = i1;
				break;

			case VC4_INSN_SWIREG:
				op->type = R_ANAL_OP_TYPE_SWI;
				op->reg = strdup (reg1);
				break;

			case VC4_INSN_RTI:
			case VC4_INSN_RTS:
				op->type = R_ANAL_OP_TYPE_RET;
				op->direction = R_ANAL_OP_DIR_EXEC;
				break;

			case VC4_INSN_MOV32:
			case VC4_INSN_MOVI32:
				op->type = R_ANAL_OP_TYPE_COND;
			case VC4_INSN_MOVI16:
			case VC4_INSN_MOVIU32:
			case VC4_INSN_MOVI48:
			case VC4_INSN_MOV16:
			case VC4_INSN_MOVCPUID:
				op->type |= R_ANAL_OP_TYPE_MOV;
				op->reg = strdup (reg1);
				break;

			case VC4_INSN_FCMPR:
			case VC4_INSN_FCMPI:
				op->family = R_ANAL_OP_FAMILY_FPU;
			case VC4_INSN_CMP32:
			case VC4_INSN_CMPI32:
				op->type = R_ANAL_OP_TYPE_COND;
			case VC4_INSN_CMP16:
			case VC4_INSN_CMPI16:
			case VC4_INSN_CMPIU32:
			case VC4_INSN_CMPI48:
				op->type |= R_ANAL_OP_TYPE_CMP;
				break;

			case VC4_INSN_CMN32:
			case VC4_INSN_CMNI32:
				op->type = R_ANAL_OP_TYPE_COND;
			case VC4_INSN_CMN16:
			case VC4_INSN_CMNIU32:
			case VC4_INSN_CMNI48:
				op->type |= R_ANAL_OP_TYPE_CMP;
				break;

			case VC4_INSN_BTST32:
			case VC4_INSN_BTSTI32:
				op->type = R_ANAL_OP_TYPE_COND;
			case VC4_INSN_BTST16:
			case VC4_INSN_BTSTI16:
			case VC4_INSN_BTSTIU32:
				op->type |= R_ANAL_OP_TYPE_CMP;
				break;

			case VC4_INSN_ADDSP:
				op->stackop = R_ANAL_STACK_INC;
				op->stackptr = i2;
			case VC4_INSN_FADDI:
			case VC4_INSN_FADDR:
				// Avoid ADDSP fallthrough
				if (op->stackptr == 0) {
					op->family = R_ANAL_OP_FAMILY_FPU;
				}
			case VC4_INSN_ADD32:
			case VC4_INSN_ADDS232:
			case VC4_INSN_ADDS432:
			case VC4_INSN_ADDS832:
			case VC4_INSN_ADDS1632:
			case VC4_INSN_ADDI32:
			case VC4_INSN_ADDS2I32:
			case VC4_INSN_ADDS4I32:
			case VC4_INSN_ADDS8I32:
			case VC4_INSN_ADDS16I32:
			case VC4_INSN_ADDSATR:
			case VC4_INSN_ADDS5R:
			case VC4_INSN_ADDS6R:
			case VC4_INSN_ADDS7R:
			case VC4_INSN_ADDS8R:
			case VC4_INSN_ADDSATI:
			case VC4_INSN_ADDS5I:
			case VC4_INSN_ADDS6I:
			case VC4_INSN_ADDS7I:
			case VC4_INSN_ADDS8I:
				op->type = R_ANAL_OP_TYPE_COND;
			case VC4_INSN_ADD16:
			case VC4_INSN_ADDS216:
			case VC4_INSN_ADDS416:
			case VC4_INSN_ADDS816:
			case VC4_INSN_ADDS1616:
			case VC4_INSN_ADDI16:
			case VC4_INSN_ADDS8I16:
			case VC4_INSN_ADDIU32:
			case VC4_INSN_ADDS2IU32_SHL1:
			case VC4_INSN_ADDS4IU32_SHL2:
			case VC4_INSN_ADDS8IU32_SHL3:
			case VC4_INSN_ADDS16IU32_SHL4:
			case VC4_INSN_ADD48I:
			case VC4_INSN_ADDI48:
				op->type |= R_ANAL_OP_TYPE_ADD;
				op->reg = strdup (reg1);
				break;

			case VC4_INSN_FSUBI:
			case VC4_INSN_FSUBR:
				op->family = R_ANAL_OP_FAMILY_FPU;
			case VC4_INSN_SUB32:
			case VC4_INSN_SUBI32:
			case VC4_INSN_SUBSATR:
			case VC4_INSN_SUBSATI:
			case VC4_INSN_SUBS1R:
			case VC4_INSN_SUBS2R:
			case VC4_INSN_SUBS3R:
			case VC4_INSN_SUBS4R:
			case VC4_INSN_SUBS5R:
			case VC4_INSN_SUBS6R:
			case VC4_INSN_SUBS7R:
			case VC4_INSN_SUBS8R:
			case VC4_INSN_SUBS1I:
			case VC4_INSN_SUBS2I:
			case VC4_INSN_SUBS3I:
			case VC4_INSN_SUBS4I:
			case VC4_INSN_SUBS5I:
			case VC4_INSN_SUBS6I:
			case VC4_INSN_SUBS7I:
			case VC4_INSN_SUBS8I:
			case VC4_INSN_RSUB32:
			case VC4_INSN_RSUBI32:
				op->type = R_ANAL_OP_TYPE_COND;
			case VC4_INSN_SUB16:
			case VC4_INSN_SUBI16:
			case VC4_INSN_SUBIU32:
			case VC4_INSN_SUBI48:
			case VC4_INSN_RSUB16:
			case VC4_INSN_RSUBIU32:
			case VC4_INSN_RSUBI48:
				op->type |= R_ANAL_OP_TYPE_SUB;
				op->reg = strdup (reg1);
				break;

			case VC4_INSN_FMULI:
			case VC4_INSN_FMULR:
				op->family = R_ANAL_OP_FAMILY_FPU;
			case VC4_INSN_MUL32:
			case VC4_INSN_MULI32:
			case VC4_INSN_MULHDRSS:
			case VC4_INSN_MULHDRSU:
			case VC4_INSN_MULHDRUS:
			case VC4_INSN_MULHDRUU:
			case VC4_INSN_MULHDISS:
			case VC4_INSN_MULHDISU:
			case VC4_INSN_MULHDIUS:
			case VC4_INSN_MULHDIUU:
				op->type = R_ANAL_OP_TYPE_COND;
			case VC4_INSN_MUL16:
			case VC4_INSN_MULI16:
			case VC4_INSN_MULIU32:
			case VC4_INSN_MULI48:
				op->type |= R_ANAL_OP_TYPE_MUL;
				op->reg = strdup (reg1);
				break;

			case VC4_INSN_FDIVI:
			case VC4_INSN_FDIVR:
				op->family = R_ANAL_OP_FAMILY_FPU;
			case VC4_INSN_DIVRSS:
			case VC4_INSN_DIVRSU:
			case VC4_INSN_DIVRUS:
			case VC4_INSN_DIVRUU:
			case VC4_INSN_DIVISS:
			case VC4_INSN_DIVISU:
			case VC4_INSN_DIVIUS:
			case VC4_INSN_DIVIUU:
				op->type = R_ANAL_OP_TYPE_DIV | R_ANAL_OP_TYPE_COND;
				op->reg = strdup (reg1);
				break;

			case VC4_INSN_OR32:
			case VC4_INSN_ORI32:
				op->type = R_ANAL_OP_TYPE_COND;
			case VC4_INSN_OR16:
			case VC4_INSN_ORIU32:
			case VC4_INSN_ORI48:
				op->type |= R_ANAL_OP_TYPE_OR;
				op->reg = strdup (reg1);
				break;

			case VC4_INSN_AND32:
			case VC4_INSN_ANDI32:
				op->type = R_ANAL_OP_TYPE_COND;
			case VC4_INSN_AND16:
			case VC4_INSN_ANDIU32:
			case VC4_INSN_ANDI48:
				op->type |= R_ANAL_OP_TYPE_AND;
				op->reg = strdup (reg1);
				break;

			case VC4_INSN_EOR32:
			case VC4_INSN_EORI32:
				op->type = R_ANAL_OP_TYPE_COND;
			case VC4_INSN_EOR16:
			case VC4_INSN_EORIU32:
			case VC4_INSN_EORI48:
				op->type |= R_ANAL_OP_TYPE_XOR;
				op->reg = strdup (reg1);
				break;

			case VC4_INSN_NOT32:
			case VC4_INSN_NOTI32:
				op->type = R_ANAL_OP_TYPE_COND;
			case VC4_INSN_NOT16:
			case VC4_INSN_NOTI16:
			case VC4_INSN_NOTIU32:
				op->type |= R_ANAL_OP_TYPE_NOT;
				op->reg = strdup (reg1);
				break;

			case VC4_INSN_ROR32:
			case VC4_INSN_RORI32:
				op->type = R_ANAL_OP_TYPE_COND;
			case VC4_INSN_ROR16:
			case VC4_INSN_RORIU32:
				op->type |= R_ANAL_OP_TYPE_ROR;
				op->reg = strdup (reg1);
				break;

			case VC4_INSN_LSR32:
			case VC4_INSN_LSRI32:
				op->type = R_ANAL_OP_TYPE_COND;
			case VC4_INSN_LSR16:
			case VC4_INSN_LSRI16:
			case VC4_INSN_LSRIU32:
				op->type |= R_ANAL_OP_TYPE_SHR;
				op->reg = strdup (reg1);
				break;

			case VC4_INSN_SHL32:
			case VC4_INSN_SHLI32:
			case VC4_INSN_SHLSATR:
			case VC4_INSN_SHLSATI:
				op->type = R_ANAL_OP_TYPE_COND;
			case VC4_INSN_SHL16:
			case VC4_INSN_SHLI16:
			case VC4_INSN_SHLIU32:
				op->type |= R_ANAL_OP_TYPE_SHL;
				op->reg = strdup (reg1);
				break;

			case VC4_INSN_ASR32:
			case VC4_INSN_ASRI32:
				op->type = R_ANAL_OP_TYPE_COND;
			case VC4_INSN_ASR16:
			case VC4_INSN_ASRI16:
			case VC4_INSN_ASRIU32:
				op->type |= R_ANAL_OP_TYPE_SAR;
				op->reg = strdup (reg1);
				break;

			case VC4_INSN_FABSR:
			case VC4_INSN_FABSI:
				op->family = R_ANAL_OP_FAMILY_FPU;
			case VC4_INSN_ABS32:
			case VC4_INSN_ABSI32:
				op->type = R_ANAL_OP_TYPE_COND;
			case VC4_INSN_ABSIU32:
			case VC4_INSN_ABS16:
				op->type |= R_ANAL_OP_TYPE_ABS;
				op->reg = strdup (reg1);
				break;

			case VC4_INSN_LEA:
			case VC4_INSN_LEA32R:
			case VC4_INSN_LEA48:
			case VC4_INSN_LEA32PC:
				op->type = R_ANAL_OP_TYPE_LEA;
				op->direction = R_ANAL_OP_DIR_REF;

				access_list = r_list_newf ((RListFree)r_anal_value_free);
				if (!access_list) {
					break;
				}

				ADD_REG_TO_LIST_OR_BREAK (access_list, R_PERM_W, strdup (reg1));

				// "lea pc ..." is a jump
				if (!strcmp (reg1, "pc")) {
					if (reg2[0] != '\0') {
						op->type = R_ANAL_OP_TYPE_RJMP;
					} else {
						op->jump = i2;
					}
				}

				// "lea sp ..." resets the stack
				else if (!strcmp (reg1, "sp")) {
					op->stackop = R_ANAL_STACK_RESET;
					if (reg2[0] != '\0') {
						op->stackptr = i2;
					}
				}

				op->reg = reg1;
				if (reg2[0] != '\0') {
					// "lea .., XX(sp)" reads the stack
					if (!strcmp(reg2, "sp")) {
						op->stackop = R_ANAL_STACK_GET;
						op->stackptr = i2;
					}

					val = r_anal_value_new ();
					if (!val) {
						break;
					}
					val->type = R_ANAL_VAL_MEM;
					val->access = R_PERM_R;
					val->reg = strdup (reg1);
					val->delta = i2;
					r_list_append (access_list, val);
				} else {
					op->ptr = i2;
					op->refptr = 0;
				}
				op->access = access_list;
				break;

			case VC4_INSN_LDCNDDISP:   // ld${alu32cond}   $alu32dreg,$imm6($alu32areg)
			case VC4_INSN_LDCNDDISPH:  // ldh${alu32cond}  $alu32dreg,$imm6($alu32areg)
			case VC4_INSN_LDCNDDISPB:  // ldb${alu32cond}  $alu32dreg,$imm6($alu32areg)
			case VC4_INSN_LDCNDDISPSH: // ldsh${alu32cond} $alu32dreg,$imm6($alu32areg)
			case VC4_INSN_LDCNDIDX:    // ld${alu32cond}   $alu32dreg,($alu32areg,$alu32breg<<2)
			case VC4_INSN_LDCNDIDXH:   // ldh${alu32cond}  $alu32dreg,($alu32areg,$alu32breg<<1)
			case VC4_INSN_LDCNDIDXB:   // ldb${alu32cond}  $alu32dreg,($alu32areg,$alu32breg)
			case VC4_INSN_LDCNDIDXSH:  // ldsh${alu32cond} $alu32dreg,($alu32areg,$alu32breg<<1)
			case VC4_INSN_LDPREDEC:    // ld${alu32cond}   $alu32dreg,--($alu32areg)
			case VC4_INSN_LDPREDECH:   // ldh${alu32cond}  $alu32dreg,--($alu32areg)
			case VC4_INSN_LDPREDECB:   // ldb${alu32cond}  $alu32dreg,--($alu32areg)
			case VC4_INSN_LDPREDECSH:  // ldsh${alu32cond} $alu32dreg,--($alu32areg)
			case VC4_INSN_LDPOSTINC:   // ld${alu32cond}   $alu32dreg,($alu32areg)++
			case VC4_INSN_LDPOSTINCH:  // ldh${alu32cond}  $alu32dreg,($alu32areg)++
			case VC4_INSN_LDPOSTINCB:  // ldb${alu32cond}  $alu32dreg,($alu32areg)++
			case VC4_INSN_LDPOSTINCSH: // ldsh${alu32cond} $alu32dreg,($alu32areg)++
			case VC4_INSN_STCNDDISP:   // st${alu32cond}   $alu32dreg,$imm6($alu32areg)
			case VC4_INSN_STCNDDISPH:  // sth${alu32cond}  $alu32dreg,$imm6($alu32areg)
			case VC4_INSN_STCNDDISPB:  // stb${alu32cond}  $alu32dreg,$imm6($alu32areg)
			case VC4_INSN_STCNDDISPSH: // stsh${alu32cond} $alu32dreg,$imm6($alu32areg)
			case VC4_INSN_STCNDIDX:    // st${alu32cond}   $alu32dreg,($alu32areg,$alu32breg<<2)
			case VC4_INSN_STCNDIDXH:   // sth${alu32cond}  $alu32dreg,($alu32areg,$alu32breg<<1)
			case VC4_INSN_STCNDIDXB:   // stb${alu32cond}  $alu32dreg,($alu32areg,$alu32breg)
			case VC4_INSN_STCNDIDXSH:  // stsh${alu32cond} $alu32dreg,($alu32areg,$alu32breg<<1)
			case VC4_INSN_STPREDEC:    // st${alu32cond}   $alu32dreg,--($alu32areg)
			case VC4_INSN_STPREDECH:   // sth${alu32cond}  $alu32dreg,--($alu32areg)
			case VC4_INSN_STPREDECB:   // stb${alu32cond}  $alu32dreg,--($alu32areg)
			case VC4_INSN_STPREDECSH:  // stsh${alu32cond} $alu32dreg,--($alu32areg)
			case VC4_INSN_STPOSTINC:   // st${alu32cond}   $alu32dreg,($alu32areg)++
			case VC4_INSN_STPOSTINCH:  // sth${alu32cond}  $alu32dreg,($alu32areg)++
			case VC4_INSN_STPOSTINCB:  // stb${alu32cond}  $alu32dreg,($alu32areg)++
			case VC4_INSN_STPOSTINCSH: // stsh${alu32cond} $alu32dreg,($alu32areg)++
				op->type = R_ANAL_OP_TYPE_COND;
			case VC4_INSN_LDSP:        // ld $alu16dreg,$spoffset(sp)
			case VC4_INSN_LDOFF:       // ld $alu16dreg,$ldstoff($alu16sreg)
			case VC4_INSN_LDIND:       // ld$accsz $alu16dreg,($alu16sreg)
			case VC4_INSN_LDOFF12:     // ld$accsz32 $alu32dreg,$offset12($alu32areg)
			case VC4_INSN_LDOFF16:     // ld$accsz32 $alu32dreg,$offset16($off16basereg)
			case VC4_INSN_LDPCREL27:   // ld$accsz32 $alu48idreg,$mem48pcrel27
			case VC4_INSN_LDOFF27:     // ld$accsz32 $alu48idreg,$mem48offset27($mem48sreg)
			case VC4_INSN_STSP:        // st $alu16dreg,$spoffset(sp)
			case VC4_INSN_STOFF:       // st $alu16dreg,$ldstoff($alu16sreg)
			case VC4_INSN_STIND:       // st$accsz $alu16dreg,($alu16sreg)
			case VC4_INSN_STOFF12:     // st$accsz32 $alu32dreg,$offset12($alu32areg)
			case VC4_INSN_STOFF16:     // st$accsz32 $alu32dreg,$offset16($off16basereg)
			case VC4_INSN_STPCREL27:   // st$accsz32 $alu48idreg,$mem48pcrel27
			case VC4_INSN_STOFF27: {    // st$accsz32 $alu48idreg,$mem48offset27($mem48sreg)
				bool is_load;
				RAnalValue *memory_access;
				st8 delta = 0;

				memory_access = r_anal_value_new ();
				if (!memory_access) {
					break;
				}
				memory_access->type = R_ANAL_VAL_MEM;

				if (instr[0] == 'l') {
					is_load = true;
					memory_access->access = R_PERM_R;

					op->type |= R_ANAL_OP_TYPE_LOAD;
					op->direction = R_ANAL_OP_DIR_READ;
				} else {
					is_load = false;
					memory_access->access = R_PERM_W;

					op->type |= R_ANAL_OP_TYPE_STORE;
					op->direction = R_ANAL_OP_DIR_WRITE;
				}

				// "stsb ", "ldsb ", "stb " or "ldb "
				if ((instr[2] == 's' && instr[3] == 'b') || instr[2] == 'b') {
					// 8 bits access
					memory_access->memref = 1;
					op->refptr = 1;
				}
				// "stsh ", "ldsh ", "sth " or "ldh "
				else if ((instr[2] == 's' && instr[3] == 'h') || instr[2] == 'h') {
					// Check that the access size isn't a condition ("hi" or "hs")
					if (instr[3] != 'i' && instr[3] != 's') {
						// 16 bits access
						memory_access->memref = 2;
						op->refptr = 2;
					}
				}
				else {
					// 32 bits access
					memory_access->memref = 4;
					op->refptr = 4;
				}

				access_list = r_list_newf ((RListFree)r_anal_value_free);
				if (!access_list) {
					break;
				}

				// Treat first register
				ADD_REG_TO_LIST_OR_BREAK (access_list, R_PERM_R, strdup (reg1));
				if (is_load) {
					// "ld pc ..." is a jump
					if (!strcmp (reg1, "pc")) {
						op->direction = R_ANAL_OP_DIR_EXEC;
						if (op->type & R_ANAL_OP_TYPE_COND) {
							op->type = R_ANAL_OP_TYPE_RCJMP;
							op->fail = op->addr + op->size;
						} else {
							op->type = R_ANAL_OP_TYPE_RJMP;
						}
					}

					// "ld sp ..." changes the stack pointer
					else if (!strcmp (reg1, "sp")) {
						op->stackop = R_ANAL_STACK_RESET;
					}
				}
				// "st pc ..." is the only case the writen value is
				// known (op->addr)
				else {
					if (!strcmp (reg1, "pc")) {
						op->val = op->addr;
					}
				}

				// Treat second register
				if (reg2[0] != '\0') {
					// In case of predec or postinc, the register 2 is
					// also written
					if (strstr (instr, "++")) {
						ADD_REG_TO_LIST_OR_BREAK (access_list, R_PERM_R|R_PERM_W, strdup (reg2));
					} else if (strstr (instr, "--")) {
						delta = -1;
						ADD_REG_TO_LIST_OR_BREAK (access_list, R_PERM_R|R_PERM_W, strdup (reg2));
					} else {
						ADD_REG_TO_LIST_OR_BREAK (access_list, R_PERM_R, strdup (reg2));
					}

					if (reg3[0] == '\0') {
						// When the instruction is "[ld|st] rX, imm(pc)"
						// the target adress is known (pc + imm)
						if (!strcmp (reg2, "pc")) {
							memory_access->imm = op->addr + i2 + delta;

							if (op->type & (R_ANAL_OP_TYPE_JMP | R_ANAL_OP_TYPE_UJMP)) {
								op->jump = op->addr + i2 + delta;
							} else {
								if (op->stackop == R_ANAL_STACK_RESET) {
									op->stackptr = op->addr + i2 + delta;
								}
								op->ptr = op->addr + i2 + delta;
							}
						}
						// Instruction "[ld|st] rX, imm(sp)" is a stack
						// operation at offset imm
						else {
							if (!strcmp (reg2, "sp")) {
								op->stackop = is_load ? R_ANAL_STACK_GET : R_ANAL_STACK_SET;
								op->stackptr = i2;
							}
							memory_access->reg = strdup (reg2);
							memory_access->delta = i2 + delta;
						}
					}
				}

				// If there isn't any second register, then the target
				// adress is known (immediate)
				else {
					memory_access->imm = i2;
					if (op->type & (R_ANAL_OP_TYPE_JMP | R_ANAL_OP_TYPE_UJMP)) {
						op->jump = i2;
					} else {
						if (op->stackop == R_ANAL_STACK_RESET) {
							op->stackptr = i2;
						}
						op->ptr = i2;
						op->refptr = 0;
					}
				}

				// Treat third regsiter
				if (reg3[0] != '\0') {
					ADD_REG_TO_LIST_OR_BREAK (access_list, R_PERM_R, strdup (reg3));

					memory_access->reg = strdup (reg2);
					memory_access->regdelta = strdup (reg3);
					memory_access->mul = shift>0 ? shift : 1;
					memory_access->delta = i2;
				}

				r_list_append (access_list, memory_access);
				op->access = access_list;
				break;
			}

			case VC4_INSN_BCC32I:
				op->type = R_ANAL_OP_TYPE_CJMP;
				op->direction = R_ANAL_OP_DIR_EXEC;
				op->jump = i3;
				op->fail = op->addr + op->size;
				break;

			case VC4_INSN_BCC32:
				op->type = R_ANAL_OP_TYPE_JMP;
				op->direction = R_ANAL_OP_DIR_EXEC;
				op->jump = i1;
				break;

			case VC4_INSN_BCC32R:
				op->type = R_ANAL_OP_TYPE_CJMP;
				op->direction = R_ANAL_OP_DIR_EXEC;
				op->jump = i3;
				op->fail = op->addr + op->size;
				break;

			case VC4_INSN_BCC:
				op->type = R_ANAL_OP_TYPE_CJMP;
				op->direction = R_ANAL_OP_DIR_EXEC;
				op->jump = i1;
				op->fail = op->addr + op->size;
				break;

			case VC4_INSN_ADDCMPBII:
			case VC4_INSN_ADDCMPBRI:
			case VC4_INSN_ADDCMPBIR:
			case VC4_INSN_ADDCMPBRR:
				op->type = R_ANAL_OP_TYPE_CJMP;
				op->direction = R_ANAL_OP_DIR_EXEC;
				op->jump = i4;
				op->fail = op->addr + op->size;
				break;

			case VC4_INSN_BREG:
				op->direction = R_ANAL_OP_DIR_EXEC;
				if (!strcmp (reg1, "lr")) {
					op->type = R_ANAL_OP_TYPE_RET;
				} else {
					op->type = R_ANAL_OP_TYPE_RJMP;
					op->direction = R_ANAL_OP_DIR_EXEC;
				}
				break;

			case VC4_INSN_BLREG:
				op->direction = R_ANAL_OP_DIR_EXEC;
				if (!strcmp (reg1, "lr")) {
					op->type = R_ANAL_OP_TYPE_RET;
				} else {
					op->type = R_ANAL_OP_TYPE_RCALL;
					op->fail = op->addr + op->size;
				}
				break;

			case VC4_INSN_BL32:
				op->direction = R_ANAL_OP_DIR_EXEC;
				op->type = R_ANAL_OP_TYPE_CALL;
				op->jump = i1;
				op->fail = op->addr + op->size;
				break;

			case VC4_INSN_POPRN:
			case VC4_INSN_POPRNPC:
			case VC4_INSN_POPRNRM0:
			case VC4_INSN_POPRNRM0_PC:
			case VC4_INSN_POPRNRM6:
			case VC4_INSN_POPRNRM6_PC:
			case VC4_INSN_POPRNRM16:
			case VC4_INSN_POPRNRM16_PC:
			case VC4_INSN_POPRNRM24:
			case VC4_INSN_POPRNRM24_PC:
				is_pop = true;
			case VC4_INSN_PUSHRN:
			case VC4_INSN_PUSHRNLR:
			case VC4_INSN_PUSHRNRM0:
			case VC4_INSN_PUSHRNRM0_LR:
			case VC4_INSN_PUSHRNRM6:
			case VC4_INSN_PUSHRNRM6_LR:
			case VC4_INSN_PUSHRNRM16:
			case VC4_INSN_PUSHRNRM16_LR:
			case VC4_INSN_PUSHRNRM24:
			case VC4_INSN_PUSHRNRM24_LR:
				access_list = r_list_newf ((RListFree)r_anal_value_free);
				if (!access_list) {
					break;
				}

				// reg2 is filled only for
				// "push XXX, lr" or "pop XXX, pc"
				if (reg2[0] != '\0') {
					ADD_REG_TO_LIST_OR_BREAK (access_list,
						is_pop ? R_PERM_W : R_PERM_R,
						is_pop ? "pc" : "lr");
				}

				// push/pop rX case
				if (regEndRange[0] == '\0') {
					ADD_REG_TO_LIST_OR_BREAK (access_list,
						is_pop ? R_PERM_W : R_PERM_R,
						strdup (reg1));
				}

				// push/pop rX-rY case
				else {
					ut64 i, j, tmp;
					char reg[4] = {0};

					i = r_num_get (NULL, &reg1[1]);
					j = r_num_get (NULL, &regEndRange[1]);

					// The order isn't fixed betwen rX and rY
					if (i > j) {
						tmp = j;
						j = i;
						i = tmp;
					}

					for (; i <= j; i++) {
						snprintf (reg, 4, "r%li", i);

						ADD_REG_TO_LIST_OR_BREAK (access_list,
							is_pop ? R_PERM_W : R_PERM_R,
							strdup (reg));
					}
				}

				for (nb_stack_op = r_list_length (access_list); nb_stack_op > 0; nb_stack_op--) {
						val = r_anal_value_new ();
						if (!val) {
							break;
						}

						val->type = R_ANAL_VAL_MEM;
						val->access = is_pop ? R_PERM_R : R_PERM_W;
						val->memref = 4;
						val->reg = "sp";
						val->base = 0;
						val->delta = 4*(nb_stack_op-1);
						r_list_append (access_list, val);
				}

				op->type = R_ANAL_OP_TYPE_RPUSH;
				op->stackop = R_ANAL_STACK_INC;
				op->stackptr = is_pop ? -4*nb_stack_op : 4*nb_stack_op;
				op->access = access_list;
				break;
			}
		} else if (!strcmp (instr, "*unknown*")) {
			op->type = R_ANAL_OP_TYPE_UNK;
		} else {
			fprintf (stderr, "Error: private data for '%s' empty\n", instr);
		}
	}

	if (mask & R_ARCH_OP_MASK_DISASM) {
		if (op->size > 0) {
			op->mnemonic = instr? instr: strdup ("");
			r_str_replace_char (op->mnemonic, '\t', ' ');
		} else {
			free (instr);
			op->mnemonic = strdup ("(data)");
		}
	} else {
		free (instr);
	}
	return true;
}

static int info(RArchSession *s, ut32 q) {
	switch (q) {
	case R_ARCH_INFO_MIN_OP_SIZE:
		return 2;
	case R_ARCH_INFO_MAX_OP_SIZE:
		return 6;
	}
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
	.decode = &decode
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ARCH,
	.data = &r_arch_plugin_vc4,
	.version = R2_VERSION
};
#endif
