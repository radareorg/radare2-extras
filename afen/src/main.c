/* radare - Copyright 2024 - satk0 */

#define R_LOG_ORIGIN "core.afen"

#include <r_core.h>

typedef struct RAfenRepl {
	char *old_name;
	char *new_name;
} RAfenRepl;

static R_TH_LOCAL HtUP *ht; // hash table

// afen parser
static int r_parse_afen(RParse *p, const char *data, char *str) {
	char *input = strdup (data);

	RCore *core = (RCore *) p->analb.anal->user;

	RAnalFunction *fcn = r_anal_get_function_at (core->anal, core->offset);

	if (fcn) {
		RVector *vec = ht_up_find (ht, fcn->addr, NULL);
		if (vec) {
			RAfenRepl *repl;
			r_vector_foreach (vec, repl) {
				input = r_str_replace_all (input, repl->old_name, repl->new_name);
			}
		}
	}

	strcpy (str, input);
	return true;
}

// RParse plugin Definition Info
RParsePlugin r_parse_plugin_afen = {
	.name = "afen",
	.desc = "Afen parse plugin",
	.parse = r_parse_afen,
};

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

// sets afen parser
static int r_core_init_afen(void *user, const char *input) {
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

static int r_core_fini_afen(void *user, const char *input) {
	ht_up_free (ht);
	ht = NULL;

	return true;
}

static int r_core_call_afen(void *user, const char *input) {
	RCore *core = (RCore *) user;

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

		RAnalFunction *fcn = r_anal_get_function_at (core->anal, core->offset);

		if (!fcn) {
			R_LOG_ERROR ("No Function at 0x%08" PFMT64x, core->offset);
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
	.version = R2_VERSION
};
#endif
