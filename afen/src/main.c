/* radare - Copyright 2024 - satk0 */

#define R_LOG_ORIGIN "core.afen"

#include <r_core.h>

static RList *old_names;
static RList *new_names;

// afen parser
static int r_afen_parse(RParse *p, const char *data, char *str) {
	int res = true;
	char *input = strdup (data);

	int n = r_list_length(old_names);

	if (n){
		RListIter *s_iter_old = NULL;
		RListIter *s_iter_new = NULL;

		s_iter_old = old_names->head;
		s_iter_new = new_names->head;

		for (int i = 0; i < n; ++i) {
			input = r_str_replace_all (input, s_iter_old->data, s_iter_new->data);

			s_iter_old = r_list_iter_get_next(s_iter_old);
			s_iter_new = r_list_iter_get_next(s_iter_new);
		}

	}

	strcpy (str, input);
	return res;
}

// sets afen parser
static int r_cmd_init(void *user, const char *input) {
	RCmd *rcmd = (RCmd *) user;
	RCore *core = (RCore *) rcmd->data;
	old_names = r_list_new ();
	new_names = r_list_new ();

	core->parser->cur->parse = r_afen_parse;
	
	return true;
}

static int r_cmd_fini(void *user, const char *input) {
	r_list_free(old_names);
	r_list_free(new_names);

	return true;
}

static int r_cmd_afen_client(void *user, const char *input) {
	if (r_str_startswith (input, "afen")) {
		int *argc = (int*) malloc(sizeof(int));
		char **argv = r_str_argv(input, argc);

		if (*argc != 3) {
			r_cons_printf("Usage: afen new_name old_name\n");
			return true;
		}

		r_list_append(new_names, argv[1]);
		r_list_append(old_names, argv[2]);

		return true;
	}
	return false;
}

// PLUGIN Definition Info
RCorePlugin r_core_plugin_afen = {
	.meta = {
		.name = "core-afen",
		.desc = "Rename expressions",
		.author = "satk0",
		.license = "GPLv3",
	},
	.call = r_cmd_afen_client,
	.init = r_cmd_init,
	.fini = r_cmd_fini
};


#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_CORE,
	.data = &r_core_plugin_afen,
	.version = R2_VERSION
};
#endif
