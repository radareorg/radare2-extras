#include <r_anal.h>
#include <r_cmd.h>
#include <r_cons.h>
#include <r_core.h>
#include <r_lib.h>
#include <r_types.h>

#include <fuzzy.h>
#include <string.h>

#include "char_str.h"

#undef R_API
#define R_API static
#undef R_IPI
#define R_IPI static

// from docs: "You MUST allocate result to hold FUZZY_MAX_RESULT"
static char hash_result[FUZZY_MAX_RESULT];

static int r_cmd_ssdeep_call(void *user, const char *cmd);
static bool ssdeep_print_hash(RCore *core, const char *ptr, char hash_mode);
static char *ssdeep_get_func_disasm(RCore *core, ut64 addr, ut8 *buf,
									int nb_bytes, int nb_opcodes, bool esil);
static void ssdeep_check_size(ut32 len);

static int r_cmd_ssdeep_call(void *user, const char *cmd) {
	RCore *core = (RCore *)user;
	if (!core)
	return false;

	int cmd_len = strlen (cmd);
	if (!strstr (cmd, "ssdeep"))
	return R_FALSE;

	if (cmd_len == 6) {
		ssdeep_print_hash (core, " ", 0);
	} else {
		char hash_mode = 0;
		if (cmd[6] == 'e')
			hash_mode = 1;
		else if (cmd[6] == 'd')
			hash_mode = 2;
	
		if (cmd_len > 7)
			++cmd;
	
		ssdeep_print_hash (core, &cmd[6], hash_mode);
	}

	return true;
}

static void ssdeep_check_size(ut32 len) {
	if (len < 4096) {
		r_cons_printf ("Warning! Current buffer is too small - %d bytes. "
				"A default minimum buffer size is 4096 bytes\n",
				len);
	}
}

// hash_mode - //0 -raw; 1 - esil; 2 - disasm
static bool ssdeep_print_hash(RCore *core, const char *ptr, char hash_mode) {
	ut32 osize = 0, len = core->blocksize;
	int pos = 0, handled_cmd = false;

	if (!*ptr || *ptr == '?') {
		r_cons_printf ( "ssdeep? - show help\n"
				"ssdeep[e|d] - calculate fuzzy hash for a block (esil/disasm)\n"
				"ssdeep custom_len\n"
				"ssdeep custom_len @addr\n");
		return true;
	}

	ptr = r_str_chop_ro(ptr);
	if (ptr && *ptr && r_num_is_valid_input (core->num, ptr)) {
		int nlen = r_num_math (core->num, ptr);
		if (nlen > 0) len = nlen;
		osize = core->blocksize;
		if (nlen > core->blocksize) {
			r_core_block_size (core, nlen);
			if (nlen != core->blocksize) {
				eprintf ("Invalid block size\n");
				r_core_block_size (core, osize);
				return false;
			}
		}
	} else if (!ptr || !*(ptr + 1)) {
		osize = len;
	}

	if (hash_mode > 0) {
		char *disasm_buff = ssdeep_get_func_disasm (core, core->offset, core->block, len, 0,
							    (hash_mode == 1)? true: false);

		len = strlen (disasm_buff);
		ssdeep_check_size (len);

		fuzzy_hash_buf (disasm_buff, osize, hash_result);
		r_cons_printf ("%s\n", hash_result);
		free (disasm_buff);
	} else {
		ssdeep_check_size (len);

		memset (hash_result, '\0', FUZZY_MAX_RESULT);
		fuzzy_hash_buf (core->block, len, hash_result);
		r_cons_printf ("%s\n", hash_result);
	}

	if (osize) {
		r_core_block_size (core, osize);
	}
	return handled_cmd;
}

static char *ssdeep_get_func_disasm(RCore *core, ut64 addr, ut8 *buf, int nb_bytes, int nb_opcodes, bool esil) {
	RAsmOp asmop;
	RAnalOp analop = { 0 };
	RAnalFunction *f;
	int i, j, k, oplen, ret, line;
	ut64 old_offset = core->offset;
	ut64 at;
	int dis_opcodes = 0;
	int limit_by = 'b';

	char_str disasm_buf;
	char_str_init (&disasm_buf);

	if (nb_opcodes != 0) {
		limit_by = 'o';
	}
	if (nb_opcodes) { // Disassemble `nb_opcodes` opcodes.
		if (nb_opcodes < 0) {
			int count, nbytes = 0;

			/* Backward disassembly of `nb_opcodes` opcodes:
			 * - We compute the new starting offset
			 * - Read at the new offset */
			nb_opcodes = -nb_opcodes;

			if (nb_opcodes > 0xffff) {
				eprintf ("Too many backward instructions\n");
				return 0;
			}

			if (r_core_prevop_addr (core, core->offset, nb_opcodes, &addr)) {
				nbytes = core->offset - addr;
			} else if (!r_core_asm_bwdis_len (core, &nbytes, &addr, nb_opcodes)) {
				return false;
			}
			count = R_MIN (nb_bytes, nbytes);
			if (count > 0) {
				r_core_read_at (core, addr, buf, count);
				r_core_read_at (core, addr + count, buf + count, nb_bytes - count);
			} else if (nb_bytes > 0) {
				memset (buf, 0xff, nb_bytes);
			}
		} else {
			dis_opcodes = 1;
			r_core_read_at (core, addr, buf, nb_bytes);
		}
	} else if (nb_bytes < 0) {
		nb_bytes = -nb_bytes;
		addr -= nb_bytes;
		r_core_read_at (core, addr, buf, nb_bytes);
	}
	core->offset = addr;

	if (core->anal && core->anal->cur && core->anal->cur->reset_counter) {
		core->anal->cur->reset_counter (core->anal, addr);
	}

	i = k = j = line = 0;
	// i = number of bytes
	// j = number of instructions
	// k = delta from addr
	for (;;) {
		bool end_nbopcodes, end_nbbytes;
	
		at = addr + k;
		r_asm_set_pc(core->assembler, at);
		// 32 is the biggest opcode length in intel
		if (dis_opcodes == 1 && i >= nb_bytes - 32) {
			// Read another nb_bytes bytes into buf from current offset
			r_core_read_at (core, at, buf, nb_bytes);
			i = 0;
		}
	
		if (limit_by == 'o') {
			if (j >= nb_opcodes) {
				break;
			}
		} else if (i >= nb_bytes) {
			break;
		}
		ret = r_asm_disassemble (core->assembler, &asmop, buf + i, nb_bytes - i);
		if (ret < 1) {
			char_str_append_len (&disasm_buf, "invalid\n", 8);
			i++;
			k++;
			j++;
			continue;
		}
		r_anal_op_fini (&analop);
	
		r_anal_op (core->anal, &analop, at, buf + i, nb_bytes - i);
		if (r_config_get_i (core->config, "asm.pseudo")) {
			r_parse_parse (core->parser, asmop.buf_asm, asmop.buf_asm);
		}
		f = r_anal_get_fcn_in (core->anal, at, R_ANAL_FCN_TYPE_FCN | R_ANAL_FCN_TYPE_SYM);
		if (r_config_get_i (core->config, "asm.varsub") && f) {
			core->parser->varlist = r_anal_var_list;
			r_parse_varsub (core->parser, f, at, analop.size, asmop.buf_asm,
					asmop.buf_asm, sizeof(asmop.buf_asm));
		}
		oplen = r_asm_op_get_size (&asmop);
	
		if (esil) {
			const char *esil = R_STRBUF_SAFEGET (&analop.esil);
			char_str_append (&disasm_buf, esil);
			char_str_append_len (&disasm_buf, "\n", 1);
		} else {
			char *escaped_str = r_str_escape (asmop.buf_asm);
			char_str_append (&disasm_buf, escaped_str);
			char_str_append_len (&disasm_buf, "\n", 1);
	
			free (escaped_str);
		}
	
		i += oplen; // bytes
		k += oplen; // delta from addr
		j++;		// instructions
		line++;
	
		end_nbopcodes = dis_opcodes == 1 && nb_opcodes > 0 && line >= nb_opcodes;
		end_nbbytes = dis_opcodes == 0 && nb_bytes > 0 && i >= nb_bytes;
		if (end_nbopcodes || end_nbbytes) break;
	}

	core->offset = old_offset;
	r_anal_op_fini (&analop);

	return disasm_buf.array;
}

RCorePlugin r_core_plugin_ssdeep = {
	.name = "ssdeep",
	.desc = "fuzzy hashing for r2",
	.license = "gpl",
	.call = r_cmd_ssdeep_call,
};

#ifndef CORELIB
RLibStruct radare_plugin = { 
	.type = R_LIB_TYPE_CORE,
	.data = &r_core_plugin_ssdeep,
	.version = R2_VERSION
};
#endif
