/* radare - LGPL-3.0-only - Copyright 2026 - pancake */
#include <r_asm.h>
#include "qjs.h"

static char *parse(RAsmPluginSession *s, const char *data) {
	static const char *rules[] = {
		"add/0/stack[sp-2] = stack[sp-2] + stack[sp-1]; sp--",
		"sub/0/stack[sp-2] = stack[sp-2] - stack[sp-1]; sp--",
		"mul/0/stack[sp-2] = stack[sp-2] * stack[sp-1]; sp--",
		"div/0/stack[sp-2] = stack[sp-2] / stack[sp-1]; sp--",
		"mod/0/stack[sp-2] = stack[sp-2] % stack[sp-1]; sp--",
		"neg/0/stack[sp-1] = -stack[sp-1]",
		"lnot/0/stack[sp-1] = !stack[sp-1]",
		"not/0/stack[sp-1] = ~stack[sp-1]",
		"drop/0/sp--", "dup/0/stack[sp] = stack[sp-1]; sp++",
		"push_i8/1/push($1)", "push_i16/1/push($1)", "push_i32/1/push($1)",
		"push_const/1/push(constants[$1])", "push_const8/1/push(constants[$1])",
		"push_atom_value/1/push(atoms[$1])", "push_this/0/push(this)",
		"push_true/0/push(true)", "push_false/0/push(false)",
		"undefined/0/push(undefined)", "null/0/push(null)",
		"get_loc/1/push(locals[$1])", "get_loc8/1/push(locals[$1])",
		"get_arg/1/push(args[$1])", "get_var_ref/1/push(closure[$1])",
		"get_var/1/push(atoms[$1])", "put_var/1/atoms[$1] = pop()",
		"put_loc/1/locals[$1] = pop()", "put_loc8/1/locals[$1] = pop()",
		"put_arg/1/args[$1] = pop()", "put_var_ref/1/closure[$1] = pop()",
		"set_loc/1/locals[$1] = stack[sp-1]", "set_loc8/1/locals[$1] = stack[sp-1]",
		"set_arg/1/args[$1] = stack[sp-1]", "set_var_ref/1/closure[$1] = stack[sp-1]",
		"goto/1/goto $1", "goto8/1/goto $1", "goto16/1/goto $1",
		"if_true/1/if (pop()) goto $1", "if_true8/1/if (pop()) goto $1",
		"if_false/1/if (!pop()) goto $1", "if_false8/1/if (!pop()) goto $1",
		"return/0/return pop()", "return_undef/0/return undefined",
		"return_async/0/return pop()", "throw/0/throw pop()",
		NULL
	};
	// Only apply semantics for instructions present in the selected VM.
	size_t i;
	for (i = 1; i < R_ARRAY_SIZE (qjs_opcodes); i++) {
		const QjsOpcode *o = &qjs_opcodes[i];
		size_t len = strlen (o->name);
		if (strncmp (data, o->name, len) || (data[len] && data[len] != ' ')) {
			continue;
		}
		if (!strcmp (o->fmt, "none_int")) {
			return r_str_newf ("push(%s)", !strcmp (o->name, "push_minus1")? "-1": o->name + 5);
		}
		if (!strcmp (o->name, "get_loc0_loc1")) {
			return strdup ("push(locals[0]); push(locals[1])");
		}
		const char *bank = !strcmp (o->fmt, "none_loc")? "locals": !strcmp (o->fmt, "none_arg")? "args": !strcmp (o->fmt, "none_var_ref")? "closure": NULL;
		if (bank && len && isdigit ((ut8)o->name[len - 1])) {
			char index = o->name[len - 1];
			if (!strncmp (o->name, "get_", 4)) {
				return r_str_newf ("push(%s[%c])", bank, index);
			}
			return r_str_newf ("%s[%c] = %s", bank, index, !strncmp (o->name, "put_", 4)? "pop()": "stack[sp-1]");
		}
		return r_str_pseudo_transform (rules, data);
	}
	return strdup (data);
}

RAsmPlugin r_asm_plugin_qjs = {
	.meta = { .name = "qjs", .author = "pancake", .desc = "QuickJS stack pseudo syntax", .license = "LGPL-3.0-only" },
	.parse = parse,
};

R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_qjs,
	.version = R2_VERSION,
};
