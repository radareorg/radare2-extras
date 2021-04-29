/* radare - LGPLv3 - Copyright 2014-2015 - pancake, jvoisin, jfrankowski */

#include <dirent.h>
#include <r_core.h>
#include <r_lib.h>
#include <yara.h>

#undef R_API
#define R_API static
#undef R_IPI
#define R_IPI static

// true if the plugin has been initialized.
static int initialized = false;

static bool print_strings = 0;
static unsigned int flagidx = 0;
static bool io_va = true;

#if YR_MAJOR_VERSION < 4
static int callback(int message, void* rule, void* data);
#else
static int callback(YR_SCAN_CONTEXT* context, int message, void* rule, void* data);
#endif
static int r_cmd_yara_add (const RCore* core, const char* input);
static int r_cmd_yara_add_file (const char* rules_path);
static int r_cmd_yara_call(void *user, const char *input);
static int r_cmd_yara_clear();
static int r_cmd_yara_init(void *user, const char *cmd);
static int r_cmd_yara_help(const RCore* core);
static int r_cmd_yara_process(const RCore* core, const char* input);
static int r_cmd_yara_scan(const RCore* core, const char* option);
static int r_cmd_yara_load_default_rules (const RCore* core);

static const char* yara_rule_template = "rule RULE_NAME {\n\tstrings:\n\n\tcondition:\n}";

/* Because of how the rules are compiled, we are not allowed to add more
 * rules to a compiler once it has compiled. That's why we keep a list
 * of those compiled rules.
 */
static RList* rules_list;

#if YR_MAJOR_VERSION < 4
static int callback (int message, void *msg_data, void *user_data) {
	RCore *core = (RCore *) user_data;
	RPrint *print = core->print;
	unsigned int ruleidx;
	st64 offset = 0;
	ut64 n = 0;

	YR_RULE* rule = msg_data;

	if (message == CALLBACK_MSG_RULE_MATCHING)
	{
		YR_STRING* string;
		r_cons_printf("%s\n", rule->identifier);
		ruleidx = 0;
		yr_rule_strings_foreach(rule, string)
		{
			YR_MATCH* match;

			yr_string_matches_foreach(string, match)
			{
				n = match->base + match->offset;
				// Find virtual address if needed
				if (io_va) {
					RIOMap *map = r_io_map_get_paddr (core->io, n);
					if (map) {
						offset = r_io_map_begin (map) - map->delta;
					}
				}

				const char *flag = sdb_fmt ("%s%d_%s_%d", "yara", flagidx, rule->identifier, ruleidx);
				if (print_strings) {
					r_cons_printf("0x%08" PFMT64x ": %s : ", n + offset, flag);
					r_print_bytes(print, match->data, match->data_length, "%02x");
				}
				r_flag_set (core->flags, flag, n + offset, match->data_length);
				ruleidx++;
			}
		}
		flagidx++;
	}
	return CALLBACK_CONTINUE;
}

static void compiler_callback(int error_level, const char* file_name,
		int line_number, const char* message, void* user_data) {
	eprintf ("file: %s line_number: %d.\n%s", file_name, line_number, message);
	return;
}
#else
static int callback (YR_SCAN_CONTEXT* context, int message, void *msg_data, void *user_data) {
	RCore *core = (RCore *) user_data;
	RPrint *print = core->print;
	unsigned int ruleidx;
	st64 offset = 0;
	ut64 n = 0;

	YR_RULE* rule = msg_data;

	if (message == CALLBACK_MSG_RULE_MATCHING)
	{
		YR_STRING* string;
		r_cons_printf("%s\n", rule->identifier);
		ruleidx = 0;
		yr_rule_strings_foreach(rule, string)
		{
			YR_MATCH* match;
			yr_string_matches_foreach(context, string, match)
			{
				n = match->base + match->offset;
				// Find virtual address if needed
				if (io_va) {
					RIOMap *map = r_io_map_get_paddr (core->io, n);
					if (map) {
						offset = r_io_map_begin (map) - map->delta;
					}
				}

				const char *flag = sdb_fmt ("%s%d_%s_%d", "yara", flagidx, rule->identifier, ruleidx);
				if (print_strings) {
					r_cons_printf("0x%08" PFMT64x ": %s : ", n + offset, flag);
					r_print_bytes(print, match->data, match->data_length, "%02x");
				}
				r_flag_set (core->flags, flag, n + offset, match->data_length);
				ruleidx++;
			}
		}
		flagidx++;

	}
	return CALLBACK_CONTINUE;
}

static void compiler_callback(int error_level, const char* file_name,
		int line_number, const struct YR_RULE *rule, const char* message, void* user_data) {
	eprintf ("file: %s line_number: %d.\n%s", file_name, line_number, message);
	return;
}
#endif

static int r_cmd_yara_scan(const RCore* core, const char* option) {
	RListIter* rules_it;
	YR_RULES* rules;
	void* to_scan;
	int result;

	r_flag_space_push (core->flags, "yara");
	const unsigned int to_scan_size = r_io_size (core->io);
	io_va = r_config_get_b (core->config, "io.va");

	if (to_scan_size < 1) {
		eprintf ("Invalid file size\n");
		return false;
	}

	if( *option == '\0') {
		print_strings = 0;
	}
	else if (*option == 'S') {
		print_strings = 1;
	}
	else {
		print_strings = 0;
		eprintf ("Invalid option\n");
		return false;
	}

	to_scan = malloc (to_scan_size);
	if (!to_scan) {
		eprintf ("Something went wrong during memory allocation\n");
		return false;
	}

	result = r_io_pread_at (core->io, 0L, to_scan, to_scan_size);
	if (!result) {
		eprintf ("Something went wrong during r_io_read_at\n");
		free (to_scan);
		return false;
	}

	r_list_foreach (rules_list, rules_it, rules) {
		yr_rules_scan_mem (rules, to_scan, to_scan_size, 0, callback, (void *)core, 0);
	}
	free (to_scan);

	return true;
}

static int r_cmd_yara_show(const char * name) {
	/* List loaded rules containing name */
	RListIter* rules_it;
	YR_RULES* rules;
	YR_RULE* rule;

	r_list_foreach (rules_list, rules_it, rules) {
		yr_rules_foreach (rules, rule) {
			if (r_str_casestr (rule->identifier, name)) {
				r_cons_printf ("%s\n", rule->identifier);
			}
		}
	}

	return true;
}

static int r_cmd_yara_tags() {
	/* List tags from all the different loaded rules */
	RListIter* rules_it;
	RListIter *tags_it;
	YR_RULES* rules;
	YR_RULE* rule;
	const char* tag_name;
	RList *tag_list = r_list_new();
	tag_list->free = free;

	r_list_foreach (rules_list, rules_it, rules) {
		yr_rules_foreach(rules, rule) {
			yr_rule_tags_foreach(rule, tag_name) {
				if (! r_list_find (tag_list, tag_name, (RListComparator)strcmp)) {
					r_list_add_sorted (tag_list,
							strdup (tag_name), (RListComparator)strcmp);
				}
			}
		}
	}

	r_cons_printf ("[YARA tags]\n");
	r_list_foreach (tag_list, tags_it, tag_name) {
		r_cons_printf ("%s\n", tag_name);
	}

	r_list_free (tag_list);

	return true;
}

static int r_cmd_yara_tag (const char * search_tag) {
	/* List rules with tag search_tag */
	RListIter* rules_it;
	YR_RULES* rules;
	YR_RULE* rule;
	const char* tag_name;

	r_list_foreach (rules_list, rules_it, rules) {
		yr_rules_foreach (rules, rule) {
			yr_rule_tags_foreach(rule, tag_name) {eprintf ("Invalid option\n");
				if (r_str_casestr (tag_name, search_tag)) {
					r_cons_printf("%s\n", rule->identifier);
					break;
				}
			}
		}
	}

	return true;
}

static int r_cmd_yara_list () {
	/* List all loaded rules */
	RListIter* rules_it;
	YR_RULES* rules;
	YR_RULE* rule;

	r_list_foreach (rules_list, rules_it, rules) {
		yr_rules_foreach (rules, rule) {
			r_cons_printf("%s\n", rule->identifier);
		}
	}

	return true;
}

static int r_cmd_yara_clear () {
	/* Clears all loaded rules */
	r_list_free (rules_list);
	rules_list = r_list_newf((RListFree) yr_rules_destroy);
	eprintf ("Rules cleared.\n");

	return true;
}

static int r_cmd_yara_add(const RCore* core, const char* input) {
	/* Add a rule with user input */
	YR_COMPILER* compiler = NULL;
	char* modified_template = NULL;
	char* old_template = NULL;
	int result, i, continue_edit;

	for( i = 0; input[i] != '\0'; i++) {
		if (input[i] != ' ') {
			return r_cmd_yara_add_file (input + i);
		}
	}

	if (yr_compiler_create (&compiler) != ERROR_SUCCESS) {
		char buf[64];
		eprintf ("Error: %s\n",
		yr_compiler_get_error_message (compiler, buf, sizeof (buf)));

		return false;
	}

	old_template = strdup(yara_rule_template);
	do {
		modified_template = r_core_editor (core, NULL, old_template);
		free(old_template);
		old_template = NULL;
		if (!modified_template) {
			eprintf("Something happened with the temp file");

			goto err_exit;
		}

		result = yr_compiler_add_string (compiler, modified_template, NULL);
		if( result > 0 ) {
			char buf[64];
			eprintf ("Error: %s\n",
			yr_compiler_get_error_message (compiler, buf, sizeof (buf)));

			continue_edit = r_cons_yesno('y', "Do you want to continue editing the rule? [y]/n\n");
			if (!continue_edit) {
				goto err_exit;
			}

			old_template = modified_template;
			modified_template = NULL;
		}
	} while (result > 0);

	free(modified_template);
	yr_compiler_destroy (compiler);
	r_cons_printf ("Rule successfully added.\n");

	return true;

err_exit:
	if (compiler) yr_compiler_destroy (compiler);
	if (modified_template) free (modified_template);
	if (old_template) free (old_template);
	return false;
}

static int r_cmd_yara_add_file(const char* rules_path) {
	YR_COMPILER* compiler = NULL;
	YR_RULES* rules;
	FILE* rules_file = NULL;
	int result;

	if (!rules_path) {
		eprintf ("Please tell me what am I supposed to load\n");
		return false;
	}

	rules_file = r_sandbox_fopen (rules_path, "r");
	if (!rules_file) {
		eprintf ("Unable to open %s\n", rules_path);
		return false;
	}

	if (yr_compiler_create (&compiler) != ERROR_SUCCESS) {
		char buf[64];
		eprintf ("Error: %s\n",
		yr_compiler_get_error_message (compiler, buf, sizeof (buf)));

		goto err_exit;
	}

	result = yr_compiler_add_file (compiler, rules_file, NULL, rules_path);
	fclose (rules_file);
	rules_file = NULL;
	if (result > 0) {
		char buf[64];
		eprintf ("Error: %s : %s\n",
		yr_compiler_get_error_message (compiler, buf, sizeof (buf)),
			rules_path);

		goto err_exit;
	}

	if (yr_compiler_get_rules (compiler, &rules) != ERROR_SUCCESS) {
		char buf[64];
		eprintf ("Error: %s\n",
		yr_compiler_get_error_message (compiler, buf, sizeof (buf)));

		goto err_exit;
	}

	r_list_append(rules_list, rules);

	yr_compiler_destroy (compiler);
	return true;

err_exit:
	if (compiler) yr_compiler_destroy (compiler);
	if (rules_file) fclose (rules_file);
	return false;
}

static int r_cmd_yara_help(const RCore* core) {
	const char * help_message[] = {
		"Usage: yara", "", " Yara plugin",
		"add", " [file]", "Add yara rules from file, or open $EDITOR with yara rule template",
		"clear", "", "Clear all rules",
		"help", "", "Show this help",
		"list", "", "List all rules",
		"scan", "[S]", "Scan the current file, if S option is given it prints matching strings.",
		"show", " name", "Show rules containing name",
		"tag", " name", "List rules with tag 'name'",
		"tags", "", "List tags from the loaded rules",
		NULL
	};

	r_core_cmd_help (core, help_message);

    return true;
}

static int r_cmd_yara_process(const RCore* core, const char* input) {
    if (!strncmp (input, "add", 3))
        return r_cmd_yara_add (core, input + 3);
    else if (!strncmp (input, "clear", 4))
        return r_cmd_yara_clear ();
    else if (!strncmp (input, "list", 4))
        return r_cmd_yara_list ();
    else if (!strncmp (input, "scan", 4))
        return r_cmd_yara_scan (core, input + 4);
    else if (!strncmp (input, "show", 4))
        return r_cmd_yara_show (input + 5);
    else if (!strncmp (input, "tags", 4))
        return r_cmd_yara_tags ();
    else if (!strncmp (input, "tag ", 4))
        return r_cmd_yara_tag (input + 4);
    else
        return r_cmd_yara_help (core);
}

static int r_cmd_yara_call(void *user, const char *input) {
	const char *args;
	RCore* core = (RCore*) user;
	if (strncmp (input, "yara", 4)) {
		return false;
	}
	if (strncmp (input, "yara ", 5)) {
		return r_cmd_yara_help (core);
	}
	args = input + 4;
	if (! initialized && !r_cmd_yara_init (core, NULL)) {
		return false;
	}
	if (*args) {
		args++;
	}
	r_cmd_yara_process (core, args);
	return true;
}

static int r_cmd_yara_load_default_rules (const RCore* core) {
	RListIter* iter = NULL;
	YR_COMPILER* compiler = NULL;
	YR_RULES* yr_rules;
	char* filename, *complete_path;
	char* rules = NULL;
	char* y3_rule_dir = r_str_newf ("%s%s%s", r_str_home(R2_HOME_PLUGINS), R_SYS_DIR, "rules-yara3");
	RList* list = r_sys_dir (y3_rule_dir);

	if (yr_compiler_create (&compiler) != ERROR_SUCCESS) {
		char buf[64];
		eprintf ("Error: %s\n",
		yr_compiler_get_error_message (compiler, buf, sizeof (buf)));

		goto err_exit;
	}

	yr_compiler_set_callback(compiler, compiler_callback, NULL);

	r_list_foreach (list, iter, filename) {
		if (filename[0] != '.') { // skip '.', '..' and hidden files
			complete_path = r_str_newf ("%s%s%s", y3_rule_dir, R_SYS_DIR, filename);
			rules = (char*)r_file_gzslurp (complete_path, NULL, true);

			free (complete_path);
			complete_path = NULL;

			if (yr_compiler_add_string (compiler, rules, NULL) > 0) {
				char buf[64];
				eprintf ("Error: %s\n",
				yr_compiler_get_error_message (compiler, buf, sizeof (buf)));
			}

			free (rules);
			rules = NULL;
		}
	}
	r_list_free (list);

	if (yr_compiler_get_rules (compiler, &yr_rules) != ERROR_SUCCESS) {
		char buf[64];
		eprintf ("Error: %s\n",
		yr_compiler_get_error_message (compiler, buf, sizeof (buf)));

		goto err_exit;
	}

	r_list_append(rules_list, yr_rules);

	yr_compiler_destroy (compiler);
	return true;

err_exit:
	if (y3_rule_dir) free (y3_rule_dir);
	if (compiler) yr_compiler_destroy (compiler);
	if (list) r_list_free (list);
	if (rules) free (rules);
	return false;
}

static int r_cmd_yara_init(void *user, const char *cmd) {
	RCore* core = (RCore *)user;
	rules_list = r_list_newf((RListFree) yr_rules_destroy);
	yr_initialize ();
	r_cmd_yara_load_default_rules (core);
	initialized = true;
	flagidx = 0;
	return true;
}

static int r_cmd_yara_fini(){
	if (initialized) {
		r_list_free (rules_list);
		yr_finalize();
		initialized = false;
	}
	return true;
}

RCorePlugin r_core_plugin_yara = {
	.name = "yara",
	.desc = "YARA integration",
	.license = "LGPL",
	.call = r_cmd_yara_call,
	.init = r_cmd_yara_init,
	.fini = r_cmd_yara_fini
};

#ifndef CORELIB
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_CORE,
	.data = &r_core_plugin_yara,
        .version = R2_VERSION
};
#endif
