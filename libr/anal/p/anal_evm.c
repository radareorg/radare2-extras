#include <string.h>
#include <errno.h>

#include <jansson.h>

#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>
#include <r_anal.h>
#include <r_util.h>
#include <sdb.h>

#include "evm.h"

struct evm_anal_info {
	Sdb *pushs_db;
};

static struct evm_anal_info *evm_ai = NULL;

static unsigned opcodes_types[] = {
	[EVM_OP_STOP] = R_ANAL_OP_TYPE_RET,
	[EVM_OP_ADD] = R_ANAL_OP_TYPE_ADD,
	[EVM_OP_MUL] = R_ANAL_OP_TYPE_MUL,
	[EVM_OP_SUB] = R_ANAL_OP_TYPE_SUB,
	[EVM_OP_DIV] = R_ANAL_OP_TYPE_DIV,
	[EVM_OP_SDIV] = R_ANAL_OP_TYPE_DIV,
	[EVM_OP_MOD] = R_ANAL_OP_TYPE_MOD,
	[EVM_OP_SMOD] = R_ANAL_OP_TYPE_MOD,
	[EVM_OP_ADDMOD] = R_ANAL_OP_TYPE_ADD,
	[EVM_OP_MULMOD] = R_ANAL_OP_TYPE_MUL,
	[EVM_OP_EXP] = R_ANAL_OP_TYPE_MUL,
	[EVM_OP_SIGNEXTEND] = R_ANAL_OP_TYPE_CAST,
	[EVM_OP_LT] = R_ANAL_OP_TYPE_COND,
	[EVM_OP_GT] = R_ANAL_OP_TYPE_COND,
	[EVM_OP_SLT] = R_ANAL_OP_TYPE_COND,
	[EVM_OP_SGT] = R_ANAL_OP_TYPE_COND,

	[EVM_OP_EQ] = R_ANAL_OP_TYPE_CMP,
	[EVM_OP_ISZERO] = R_ANAL_OP_TYPE_CMP,
	[EVM_OP_AND] = R_ANAL_OP_TYPE_AND,
	[EVM_OP_OR] = R_ANAL_OP_TYPE_OR,
	[EVM_OP_XOR] = R_ANAL_OP_TYPE_XOR,
	[EVM_OP_NOT] = R_ANAL_OP_TYPE_NOT,
	[EVM_OP_BYTE] = R_ANAL_OP_TYPE_MOV,
	[EVM_OP_SHA3] = R_ANAL_OP_TYPE_CRYPTO,

	[EVM_OP_ADDRESS] = R_ANAL_OP_TYPE_CRYPTO,
	[EVM_OP_BALANCE] = R_ANAL_OP_TYPE_CRYPTO,
	[EVM_OP_ORIGIN] = R_ANAL_OP_TYPE_CRYPTO,
	[EVM_OP_CALLER] = R_ANAL_OP_TYPE_CRYPTO,
	[EVM_OP_CALLVALUE] = R_ANAL_OP_TYPE_CRYPTO,
	[EVM_OP_CALLDATALOAD] = R_ANAL_OP_TYPE_CRYPTO,
	[EVM_OP_CALLDATASIZE] = R_ANAL_OP_TYPE_CRYPTO,
	[EVM_OP_CALLDATACOPY] = R_ANAL_OP_TYPE_CRYPTO,
	[EVM_OP_CODESIZE] = R_ANAL_OP_TYPE_CRYPTO,
	[EVM_OP_CODECOPY] = R_ANAL_OP_TYPE_CRYPTO,
	[EVM_OP_GASPRICE] = R_ANAL_OP_TYPE_CRYPTO,
	[EVM_OP_EXTCODESIZE] = R_ANAL_OP_TYPE_CRYPTO,
	[EVM_OP_EXTCODECOPY] = R_ANAL_OP_TYPE_CRYPTO,
	[EVM_OP_RETURNDATASIZE] = R_ANAL_OP_TYPE_PUSH,
	[EVM_OP_RETURNDATACOPY] = R_ANAL_OP_TYPE_STORE,

	[EVM_OP_BLOCKHASH] = R_ANAL_OP_TYPE_CRYPTO,
	[EVM_OP_COINBASE] = R_ANAL_OP_TYPE_CRYPTO,
	[EVM_OP_TIMESTAMP] = R_ANAL_OP_TYPE_CRYPTO,
	[EVM_OP_NUMBER] = R_ANAL_OP_TYPE_CRYPTO,
	[EVM_OP_DIFFICULTY] = R_ANAL_OP_TYPE_CRYPTO,
	[EVM_OP_GASLIMIT] = R_ANAL_OP_TYPE_CRYPTO,

	[EVM_OP_POP] = R_ANAL_OP_TYPE_POP,
	[EVM_OP_MLOAD] = R_ANAL_OP_TYPE_LOAD,
	[EVM_OP_MSTORE] = R_ANAL_OP_TYPE_STORE,
	[EVM_OP_MSTORE8] = R_ANAL_OP_TYPE_STORE,
	[EVM_OP_SLOAD] = R_ANAL_OP_TYPE_LOAD,
	[EVM_OP_SSTORE] = R_ANAL_OP_TYPE_STORE,
	[EVM_OP_JUMP] = R_ANAL_OP_TYPE_JMP,
	[EVM_OP_JUMPI] = R_ANAL_OP_TYPE_JMP,
	[EVM_OP_PC] = R_ANAL_OP_TYPE_MOV,
	[EVM_OP_MSIZE] = R_ANAL_OP_TYPE_MOV,
	[EVM_OP_GAS] = R_ANAL_OP_TYPE_MOV,
	[EVM_OP_JUMPDEST] = R_ANAL_OP_TYPE_NOP,

	[EVM_OP_PUSH1] = R_ANAL_OP_TYPE_PUSH,
	[EVM_OP_PUSH2] = R_ANAL_OP_TYPE_PUSH,
	[EVM_OP_PUSH3] = R_ANAL_OP_TYPE_PUSH,
	[EVM_OP_PUSH4] = R_ANAL_OP_TYPE_PUSH,
	[EVM_OP_PUSH5] = R_ANAL_OP_TYPE_PUSH,
	[EVM_OP_PUSH6] = R_ANAL_OP_TYPE_PUSH,
	[EVM_OP_PUSH7] = R_ANAL_OP_TYPE_PUSH,
	[EVM_OP_PUSH8] = R_ANAL_OP_TYPE_PUSH,
	[EVM_OP_PUSH9] = R_ANAL_OP_TYPE_PUSH,
	[EVM_OP_PUSH10] = R_ANAL_OP_TYPE_PUSH,
	[EVM_OP_PUSH11] = R_ANAL_OP_TYPE_PUSH,
	[EVM_OP_PUSH12] = R_ANAL_OP_TYPE_PUSH,
	[EVM_OP_PUSH13] = R_ANAL_OP_TYPE_PUSH,
	[EVM_OP_PUSH14] = R_ANAL_OP_TYPE_PUSH,
	[EVM_OP_PUSH15] = R_ANAL_OP_TYPE_PUSH,
	[EVM_OP_PUSH16] = R_ANAL_OP_TYPE_PUSH,
	[EVM_OP_PUSH17] = R_ANAL_OP_TYPE_PUSH,
	[EVM_OP_PUSH18] = R_ANAL_OP_TYPE_PUSH,
	[EVM_OP_PUSH19] = R_ANAL_OP_TYPE_PUSH,
	[EVM_OP_PUSH20] = R_ANAL_OP_TYPE_PUSH,
	[EVM_OP_PUSH21] = R_ANAL_OP_TYPE_PUSH,
	[EVM_OP_PUSH22] = R_ANAL_OP_TYPE_PUSH,
	[EVM_OP_PUSH23] = R_ANAL_OP_TYPE_PUSH,
	[EVM_OP_PUSH24] = R_ANAL_OP_TYPE_PUSH,
	[EVM_OP_PUSH25] = R_ANAL_OP_TYPE_PUSH,
	[EVM_OP_PUSH26] = R_ANAL_OP_TYPE_PUSH,
	[EVM_OP_PUSH27] = R_ANAL_OP_TYPE_PUSH,
	[EVM_OP_PUSH28] = R_ANAL_OP_TYPE_PUSH,
	[EVM_OP_PUSH29] = R_ANAL_OP_TYPE_PUSH,
	[EVM_OP_PUSH30] = R_ANAL_OP_TYPE_PUSH,
	[EVM_OP_PUSH31] = R_ANAL_OP_TYPE_PUSH,
	[EVM_OP_PUSH32] = R_ANAL_OP_TYPE_PUSH,
	[EVM_OP_DUP1] = R_ANAL_OP_TYPE_MOV,
	[EVM_OP_DUP2] = R_ANAL_OP_TYPE_MOV,
	[EVM_OP_DUP3] = R_ANAL_OP_TYPE_MOV,
	[EVM_OP_DUP4] = R_ANAL_OP_TYPE_MOV,
	[EVM_OP_DUP5] = R_ANAL_OP_TYPE_MOV,
	[EVM_OP_DUP6] = R_ANAL_OP_TYPE_MOV,
	[EVM_OP_DUP7] = R_ANAL_OP_TYPE_MOV,
	[EVM_OP_DUP8] = R_ANAL_OP_TYPE_MOV,
	[EVM_OP_DUP9] = R_ANAL_OP_TYPE_MOV,
	[EVM_OP_DUP10] = R_ANAL_OP_TYPE_MOV,
	[EVM_OP_DUP11] = R_ANAL_OP_TYPE_MOV,
	[EVM_OP_DUP12] = R_ANAL_OP_TYPE_MOV,
	[EVM_OP_DUP13] = R_ANAL_OP_TYPE_MOV,
	[EVM_OP_DUP14] = R_ANAL_OP_TYPE_MOV,
	[EVM_OP_DUP15] = R_ANAL_OP_TYPE_MOV,
	[EVM_OP_DUP16] = R_ANAL_OP_TYPE_MOV,
	[EVM_OP_SWAP1] = R_ANAL_OP_TYPE_MOV,
	[EVM_OP_SWAP2] = R_ANAL_OP_TYPE_MOV,
	[EVM_OP_SWAP3] = R_ANAL_OP_TYPE_MOV,
	[EVM_OP_SWAP4] = R_ANAL_OP_TYPE_MOV,
	[EVM_OP_SWAP5] = R_ANAL_OP_TYPE_MOV,
	[EVM_OP_SWAP6] = R_ANAL_OP_TYPE_MOV,
	[EVM_OP_SWAP7] = R_ANAL_OP_TYPE_MOV,
	[EVM_OP_SWAP8] = R_ANAL_OP_TYPE_MOV,
	[EVM_OP_SWAP9] = R_ANAL_OP_TYPE_MOV,
	[EVM_OP_SWAP10] = R_ANAL_OP_TYPE_MOV,
	[EVM_OP_SWAP11] = R_ANAL_OP_TYPE_MOV,
	[EVM_OP_SWAP12] = R_ANAL_OP_TYPE_MOV,
	[EVM_OP_SWAP13] = R_ANAL_OP_TYPE_MOV,
	[EVM_OP_SWAP14] = R_ANAL_OP_TYPE_MOV,
	[EVM_OP_SWAP15] = R_ANAL_OP_TYPE_MOV,
	[EVM_OP_SWAP16] = R_ANAL_OP_TYPE_MOV,

	[EVM_OP_LOG0] = R_ANAL_OP_TYPE_TRAP,
	[EVM_OP_LOG1] = R_ANAL_OP_TYPE_TRAP,
	[EVM_OP_LOG2] = R_ANAL_OP_TYPE_TRAP,
	[EVM_OP_LOG3] = R_ANAL_OP_TYPE_TRAP,
	[EVM_OP_LOG4] = R_ANAL_OP_TYPE_TRAP,

	[EVM_OP_CREATE] = R_ANAL_OP_TYPE_CRYPTO,
	[EVM_OP_CALL] = R_ANAL_OP_TYPE_CRYPTO,
	[EVM_OP_CALLCODE] = R_ANAL_OP_TYPE_CRYPTO,
	[EVM_OP_RETURN] = R_ANAL_OP_TYPE_RET,
	[EVM_OP_DELEGATECALL] = R_ANAL_OP_TYPE_CRYPTO,
	[EVM_OP_REVERT] = R_ANAL_OP_TYPE_RET,
	[EVM_OP_SELFDESTRUCT] = R_ANAL_OP_TYPE_CRYPTO,
};

struct evm_sigs_info {
	RIO *rio;
	RIODesc *riodesc;
	ut8 *contents;
	size_t contents_len;
	json_t *root;

	Sdb	*sigs_db;
	Sdb *found_sigs_db;
};

static struct evm_sigs_info *sigs_info = 0;

static int evm_oplen(ut8 opcode) {
	int ret;
	const EvmOpDef *opdef = &opcodes[opcode];

	if (opdef->txt) {
		return opdef->len;
	}
	switch (opcode) {
	case EVM_OP_PUSH1:
	case EVM_OP_PUSH2:
	case EVM_OP_PUSH3:
	case EVM_OP_PUSH4:
	case EVM_OP_PUSH5:
	case EVM_OP_PUSH6:
	case EVM_OP_PUSH7:
	case EVM_OP_PUSH8:
	case EVM_OP_PUSH9:
	case EVM_OP_PUSH10:
	case EVM_OP_PUSH11:
	case EVM_OP_PUSH12:
	case EVM_OP_PUSH13:
	case EVM_OP_PUSH14:
	case EVM_OP_PUSH15:
	case EVM_OP_PUSH16:
	case EVM_OP_PUSH17:
	case EVM_OP_PUSH18:
	case EVM_OP_PUSH19:
	case EVM_OP_PUSH20:
	case EVM_OP_PUSH21:
	case EVM_OP_PUSH22:
	case EVM_OP_PUSH23:
	case EVM_OP_PUSH24:
	case EVM_OP_PUSH25:
	case EVM_OP_PUSH26:
	case EVM_OP_PUSH27:
	case EVM_OP_PUSH28:
	case EVM_OP_PUSH29:
	case EVM_OP_PUSH30:
	case EVM_OP_PUSH31:
	case EVM_OP_PUSH32:
	{
		int pushSize = opcode - EVM_OP_PUSH1;
		/*
		            op->imm = 0;
		            for (i = 0; i < pushSize + 1; i++) {
		                    op->imm <<= 8;
		                    op->imm |= buf[i + 1];
		            }
		            settxtf (op, "push%d 0x%x", pushSize + 1, op->imm);
		*/
		ret = 2 + pushSize;
	}
	break;
	case EVM_OP_DUP1:
	case EVM_OP_DUP2:
	case EVM_OP_DUP3:
	case EVM_OP_DUP4:
	case EVM_OP_DUP5:
	case EVM_OP_DUP6:
	case EVM_OP_DUP7:
	case EVM_OP_DUP8:
	case EVM_OP_DUP9:
	case EVM_OP_DUP10:
	case EVM_OP_DUP11:
	case EVM_OP_DUP12:
	case EVM_OP_DUP13:
	case EVM_OP_DUP14:
	case EVM_OP_DUP15:
	case EVM_OP_DUP16:
	{
		// settxtf (op, "dup%d", dupSize);
		ret = 1;
	}
	break;
	case EVM_OP_SWAP1:
	case EVM_OP_SWAP2:
	case EVM_OP_SWAP3:
	case EVM_OP_SWAP4:
	case EVM_OP_SWAP5:
	case EVM_OP_SWAP6:
	case EVM_OP_SWAP7:
	case EVM_OP_SWAP8:
	case EVM_OP_SWAP9:
	case EVM_OP_SWAP10:
	case EVM_OP_SWAP11:
	case EVM_OP_SWAP12:
	case EVM_OP_SWAP13:
	case EVM_OP_SWAP14:
	case EVM_OP_SWAP15:
	case EVM_OP_SWAP16:
	{
		// settxtf (op, "swap%d", swapSize);
		ret = 1;
	}
	break;
	case EVM_OP_LOG0:
	case EVM_OP_LOG1:
	case EVM_OP_LOG2:
	case EVM_OP_LOG3:
	case EVM_OP_LOG4:
	{
		// settxtf (op, "log%d", logSize);
		ret = 1;
	}
	break;
	default:
		// settxtf (op, "invalid");
		ret = 1;
		break;
	}

	return ret;
}

/* Jumps/calls in EVM are done via first pushing dst value
 * on the stack, and then calling a jump/jumpi instruction, for example:
 *   0x0000000d push 0x42
 *   0x0000000f jumpi
 *
 * we are storing the value in push instruction to db, but not at the
 * addr of the push instruction, but at the addr of next jumpi instruction.
 * So in our example we are inserting (0xf, 0x42)
 */
static int evm_add_push_to_db(ut64 addr, const ut8 *buf, int len) {
	ut8 opcode = buf[0];
	ut64 next_cmd_addr = addr + evm_oplen (opcode);
	ut64 dst_addr = 0;
	size_t i, push_size;
	char key[16] = {0}, value[16] = {0};

	push_size = opcode - EVM_OP_PUSH1;

	for (i = 0; i < push_size + 1; i++) {
		dst_addr <<= 8;
		dst_addr |= buf[i + 1];
	}

	if (evm_ai) {
		snprintf (key, sizeof(key) - 1, "%08x", (unsigned) next_cmd_addr);
		snprintf (value, sizeof(value) - 1, "%08x", (unsigned) dst_addr);
		sdb_set (evm_ai->pushs_db, key, value, 0);
	}

	return 0;
}

static st64 evm_get_jmp_addr(ut64 addr) {
	char key[16] = {0};
	const char *value;
	unsigned ret;

	snprintf (key, sizeof(key) - 1, "%08x", (unsigned) addr);

	value = sdb_const_get (evm_ai->pushs_db, key, 0);

	if (value) {
		sscanf(value, "%08x", &ret);

		return ret;
	} else {
		return -1;
	}
}

static int evm_op(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *buf, int len) {
	ut32 *push4op;
	st64 ret;
	ut8 opcode;
	char sig[64] = {0};

	opcode = buf[0];

	memset (op, 0, sizeof(RAnalOp));

	op->type = opcodes_types[opcode];
	if (!op->type) {
		op->type = R_ANAL_OP_TYPE_UNK;
	}
	op->addr = addr;
	op->jump = op->fail = -1;
	op->ptr = op->val = -1;

	r_strbuf_init (&op->esil);

	switch (opcode) {
	case EVM_OP_JUMP:
	case EVM_OP_JUMPI:
		op->fail = addr + 1;

		if (opcode == EVM_OP_JUMP) {
			op->type = R_ANAL_OP_TYPE_JMP;
		} else {
			op->type = R_ANAL_OP_TYPE_CJMP;
		}

		ret = evm_get_jmp_addr(addr);

		if (ret >= 0) {
			op->jump = ret;
		} else {
			op->type = R_ANAL_OP_TYPE_UJMP;
		}

		op->eob = true;
		break;
	case EVM_OP_PC:
		break;
	case EVM_OP_MSIZE:
		break;
	case EVM_OP_GAS:
		break;
	case EVM_OP_JUMPDEST:
		break;
	case EVM_OP_PUSH1:
	case EVM_OP_PUSH2:
	case EVM_OP_PUSH3:
	case EVM_OP_PUSH4:
		evm_add_push_to_db (addr, buf, len);

		if (opcode == EVM_OP_PUSH4 && sigs_info && sigs_info->sigs_db) {
			push4op = (ut32 *)(buf + 1);

			snprintf(sig, sizeof(sig) - 1, "0x%08x", ntohl((unsigned)(*push4op)));

			const char *data = sdb_const_get (sigs_info->sigs_db, sig, 0);

			if (data) {
				char addr_str[16];
				char value[1024];

				snprintf(addr_str, sizeof(addr_str) - 1, "0x%08x", (unsigned int)addr);

				addr_str[16 - 1] = '\0';

				snprintf(value, sizeof(value) - 1, "calls a function %s with signature %s",
						data, sig);

				value[1023] = '\0';

				sdb_set(sigs_info->found_sigs_db, addr_str, value, 0);
				r_meta_set_string(anal, 'C', addr, data);
			}
		}

		break;
	default:
		break;
	}

	op->size = evm_oplen (opcode);
	return evm_oplen (opcode);
}


static int evm_load_symbol_map (RAnal *anal, const char *file) {
	size_t i;
	int ret = 0;
	bool rc;

	if (sigs_info) {
		r_io_close (sigs_info->rio);
		r_io_free (sigs_info->rio);
		sdb_free (sigs_info->sigs_db);
		sdb_free (sigs_info->found_sigs_db);

		free (sigs_info->contents);
		free (sigs_info);
	}

	sigs_info = malloc(sizeof(*sigs_info));
	memset(sigs_info, 0, sizeof(*sigs_info));

	if (!sigs_info) {
		ret = -1;
		goto out;
	}

	if (sigs_info) {
		sigs_info->rio = r_io_new ();
		sigs_info->riodesc = r_io_open (sigs_info->rio, file, R_PERM_R, 0644);

		if (!sigs_info->riodesc) {
			printf ("Failed to open %s: %s\n", file, strerror (errno));
			ret = -1;

			goto out_free;
		} else {
			json_error_t error;
			sigs_info->contents_len = r_io_size (sigs_info->rio);
			sigs_info->contents = malloc(sigs_info->contents_len + 1);

			rc = r_io_read (sigs_info->rio, sigs_info->contents, sigs_info->contents_len);

			if (rc == false) {
				printf ("Failed to read file\n");
				ret = -1;

				goto out_close;
			}

			sigs_info->contents[sigs_info->contents_len] = '\0';

			sigs_info->root = json_loads ((const char*)sigs_info->contents, 0, &error);

			if (!sigs_info->root) {
				printf ("Failed to parse json document on line %d: %s\n",
						error.line, error.text);
			} else {
				printf ("Parsed successfully\n");
				sigs_info->sigs_db = sdb_new0 ();
				sigs_info->found_sigs_db = sdb_new0 ();

				for (i = 0; i < json_array_size (sigs_info->root); i++) {
					json_t *elem, *sig, *args, *name;
					char *name_str, *sig_str, *args_str, *value;
					size_t value_size;

					elem = json_array_get (sigs_info->root, i);

					if (!elem) {
						continue;
					}

					sig = json_object_get (elem, "sig");
					name = json_object_get (elem, "name");
					args = json_object_get (elem, "args");

					if (!sig || !name || !args) {
						continue;
					}

					sig_str = strdup (json_string_value (sig));
					name_str = strdup (json_string_value (name));
					args_str = strdup (json_string_value (args));

					value_size = strlen(name_str) + strlen(args_str) + 8;

					value = malloc(sizeof(char) * value_size);

					snprintf(value, value_size - 1, "%s(%s)", name_str, args_str);

					sdb_set (sigs_info->sigs_db, sig_str, value, 0);

					free (value);

					free (args_str);
					free (name_str);
					free (sig_str);
				}

				json_decref (sigs_info->root);
				free (sigs_info->contents);

				sigs_info->root = 0;
				sigs_info->contents = 0;
			}
		}
	}

	goto out;

out_close:
	r_io_close (sigs_info->rio);

out_free:
	r_io_free (sigs_info->rio);
	sigs_info->rio = NULL;
	free (sigs_info);
	sigs_info = NULL;

out:
	return ret;
}

static int evm_list_found_symbols_cb (void *user, const char *k, const char *v) {
	printf ("%s | %s\n", k, v);

	return 1;
}

static int evm_list_found_symbols (RAnal *anal) {
	if (sigs_info && sigs_info->found_sigs_db) {
		sdb_foreach (sigs_info->found_sigs_db, evm_list_found_symbols_cb, NULL);
	}

	return 0;
}

static void evm_cmd_ext_help () {
	printf ("a!l <file path> 	- Read a JSON file with function signatures\n"
			"a!f				- List found function signatures\n"
			"a!h				- Show this help message\n");
}

static int evm_cmd_ext (RAnal *anal, const char *input) {
	const char *arg = input;
	arg++;

	while (*arg == ' ') {
		arg++;
	}

	switch (input[0]) {
	case 'l':
		printf("here %s\n", arg);
		evm_load_symbol_map (anal, arg);
		break;
	case 'f':
		evm_list_found_symbols (anal);
		break;
	case 'h':
	default:
		evm_cmd_ext_help ();
		return -1;
	}

	return 0;
}

static int evm_anal_init (void *user) {
	if (!evm_ai) {
		evm_ai = (struct evm_anal_info*)malloc (sizeof(*evm_ai));

		evm_ai->pushs_db = sdb_new0 ();
	}

	return 0;
}

static int evm_anal_fini (void *user) {
	if (evm_ai) {
		if (evm_ai->pushs_db) {
			sdb_free (evm_ai->pushs_db);
		}

		free(evm_ai);
		evm_ai = NULL;
	}

	return 0;
}

RAnalPlugin r_anal_plugin_evm = {
	.name = "evm",
	.desc = "ETHEREUM VM code analysis plugin",
	.license = "LGPL3",
	.arch = "evm",
	.bits = 8,
	.op = evm_op,
	.init = evm_anal_init,
	.fini = evm_anal_fini,
	.esil = false,
	.cmd_ext = evm_cmd_ext,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_evm,
	.version = R2_VERSION
};
#endif
