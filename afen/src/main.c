/* radare - Copyright 2024 - satk0 */

#define R_LOG_ORIGIN "core.afen"

#include <r_core.h>

typedef struct RAfenRepl {
	char *old_name;
	char *new_name;
} RAfenRepl;

static R_TH_LOCAL HtUP *ht; // hash table

#if R2_VERSION_NUMBER >= 50909
static void fini(RAsmPluginSession *aps) {
	RParse *p = aps->rasm->parse;
	R_FREE (p->retleave_asm);
}
#endif

static char *parse(RCore *core, const char *data) {
	char *out = strdup (data);

#if R2_VERSION_NUMBER >= 50909
	RAnalFunction *fcn = r_anal_get_function_at (core->anal, core->addr);
#else
	RAnalFunction *fcn = r_anal_get_function_at (core->anal, core->offset);
#endif

	if (fcn) {
		RVector *vec = ht_up_find (ht, fcn->addr, NULL);
		if (vec) {
			RAfenRepl *repl;
			r_vector_foreach (vec, repl) {
				out = r_str_replace_all (out, repl->old_name, repl->new_name);
			}
		}
	}
	return out;
}
// afen parser
#if R2_VERSION_NUMBER >= 50909
static char *r_parse_afen(RAsmPluginSession *aps, const char *data) {
	char* out = parse ((RCore *) aps->rasm->user, data);
	return out;
}
#else
static int r_parse_afen(RParse *p, const char *data, char *str) {
	char* out = parse ((RCore *) p->analb.anal->user, data);

	strcpy (str, out);
	return true;
}
#endif

// RParse plugin Definition Info
#if R2_VERSION_NUMBER >= 50909
RAsmPlugin r_parse_plugin_afen = {
	.meta = {
		.name = "afen",
		.desc = "Afen parse plugin",
	},
	.parse = r_parse_afen,
	.fini = fini,
	// .subvar = subvar,
};
#else
RParsePlugin r_parse_plugin_afen = {
	.name = "afen",
	.desc = "Afen parse plugin",
	.parse = r_parse_afen,
};
#endif

static inline void repl_free_afen(void *e, void *user ) {
	RAfenRepl *repl = (RAfenRepl *) e;
	if (repl) {
		R_FREE (repl->old_name);
		R_FREE (repl->new_name);
	}
}

static inline void vector_value_free_afen(HtUPKv *kv) {
	RVector *vec = (RVector *) kv->value;
	if (vec) {
		r_vector_free (vec);
	}
}

// setup afen parser
#if R2_VERSION_NUMBER >= 50909
static bool r_core_init_afen(RCorePluginSession *cps) {
	RCore *core = (RCore *) cps->core;

	r_asm_plugin_add (core->rasm, &r_parse_plugin_afen);

	/*<ut64, RVector<RAfenRepl*>>*/ ht = ht_up_new (NULL, vector_value_free_afen, NULL);
	if (!ht) {
		R_LOG_ERROR ("Fail to initialize hashtable");
		ht_up_free (ht);
		return false;
	}

	return true;
}
#else
static bool r_core_init_afen(void *user, const char *input) {
	RCmd *rcmd = (RCmd *) user;
	RCore *core = (RCore *) rcmd->data;

	r_parse_plugin_add (core->parser, &r_parse_plugin_afen);

	/*<ut64, RVector<RAfenRepl*>>*/ ht = ht_up_new (NULL, vector_value_free_afen, NULL);
	if (!ht) {
		R_LOG_ERROR ("Fail to initialize hashtable");
		ht_up_free (ht);
		return false;
	}

	return true;
}
#endif


#if R2_VERSION_NUMBER >= 50909
static bool r_core_fini_afen(RCorePluginSession *cps) {
	ht_up_free (ht);
	ht = NULL;

	return true;
}
#else
static bool r_core_fini_afen(void *user, const char *input) {
	ht_up_free (ht);
	ht = NULL;

	return true;
}
#endif

static bool check_for_afen_command(RCore *core, const char *input) {
	if (r_str_startswith (input, "afen")) {
		int argc;
		char **argv = r_str_argv (input, &argc);

		if (argc != 3) {
			R_LOG_INFO ("Usage: afen new_name old_name");
			return true;
		}

		if (!argv) {
			R_LOG_ERROR ("Can't get args");
			return false;
		}

#if R2_VERSION_NUMBER >= 50909
		RAnalFunction *fcn = r_anal_get_function_at (core->anal, core->addr);
#else
		RAnalFunction *fcn = r_anal_get_function_at (core->anal, core->offset);
#endif

		if (!fcn) {
#if R2_VERSION_NUMBER >= 50909
			R_LOG_ERROR ("No Function at 0x%08" PFMT64x, core->addr);
#else
			R_LOG_ERROR ("No Function at 0x%08" PFMT64x, core->offset);
#endif
			R_LOG_INFO ("Use afen inside a function!");
			return false;
		}

		RVector *vec = ht_up_find (ht, fcn->addr, NULL);

		if (!vec) {
			vec = r_vector_new (sizeof (RAfenRepl), repl_free_afen, NULL);
			ht_up_insert (ht, fcn->addr, vec);
		}

		bool updated = false;
		RAfenRepl *repl;
		r_vector_foreach (vec, repl) {
			if (!strcmp (repl->old_name, argv[2])) {
				repl->new_name = argv[1];
				updated = true;
				break;
			}
		}

		if (updated) return true;

		repl = R_NEW (RAfenRepl);
		repl->new_name = argv[1];
		repl->old_name = argv[2];

		r_vector_push (vec, repl);

		return true;
	}
	return false;
}

#if R2_VERSION_NUMBER >= 50909
static bool r_core_call_afen(RCorePluginSession *cps, const char *input) {
	return check_for_afen_command(cps->core, input);
}
#else
static bool r_core_call_afen(void *user, const char *input) {
	return check_for_afen_command((RCore *) user, input);
}
#endif

// RCore plugin Definition Info
RCorePlugin r_core_plugin_afen = {
	.meta = {
		.name = "core-afen",
		.desc = "Rename expressions",
		.author = "satk0",
		.license = "GPLv3",
	},
	.call = r_core_call_afen,
	.init = r_core_init_afen,
	.fini = r_core_fini_afen
};


#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_CORE,
	.data = &r_core_plugin_afen,
	.version = R2_VERSION,
#if R2_VERSION_NUMBER >= 50909
	.abiversion = R2_ABIVERSION,
#endif
};
#endif
