/* radare - LGPLv3 - Copyright 2014-2023 - pancake, jvoisin, jfrankowski */

#include <r_core.h>
#include <yara.h>

// true if the plugin has been initialized.
static R_TH_LOCAL bool initialized = false;

// TODO: remove globals!
static R_TH_LOCAL bool print_strings = false;
static R_TH_LOCAL unsigned int flagidx = 0;
static R_TH_LOCAL bool io_va = true;

#if YR_MAJOR_VERSION < 4
static int callback(int message, void* rule, void* data);
#else
static int callback(YR_SCAN_CONTEXT* context, int message, void* rule, void* data);
#endif
static int cmd_yara_add(const RCore* core, const char* input);
static int cmd_yara_add_file (const char* rules_path);
static int cmd_yara_call(void *user, const char *input);
static int cmd_yara_clear();
static int cmd_yara_init(void *user, const char *cmd);
static int cmd_yara_help(const RCore* core);
static int cmd_yara_process(const RCore* core, const char* input);
static int cmd_yara_scan(const RCore* core, const char* option);
static int cmd_yara_load_default_rules(const RCore* core);

static const char yara_rule_template[] = "rule RULE_NAME {\n\tstrings:\n\n\tcondition:\n}";

/* Because of how the rules are compiled, we are not allowed to add more
 * rules to a compiler once it has compiled. That's why we keep a list
 * of those compiled rules.
 */
static R_TH_LOCAL RList* rules_list = NULL;

#if YR_MAJOR_VERSION < 4
static int callback (int message, void *msg_data, void *user_data) {
	RCore *core = (RCore *) user_data;
	RPrint *print = core->print;
	unsigned int ruleidx;
	st64 offset = 0;
	ut64 n = 0;

	YR_RULE* rule = msg_data;

	if (message == CALLBACK_MSG_RULE_MATCHING) {
		YR_STRING* string;
		r_cons_printf ("%s\n", rule->identifier);
		ruleidx = 0;
		yr_rule_strings_foreach (rule, string) {
			YR_MATCH* match;

			yr_string_matches_foreach (string, match) {
				n = match->base + match->offset;
				// Find virtual address if needed
				if (io_va) {
					RIOMap *map = r_io_map_get_paddr (core->io, n);
					if (map) {
						offset = r_io_map_begin (map) - map->delta;
					}
				}

				r_strf_var (flag, 256, "%s%d_%s_%d", "yara", flagidx, rule->identifier, ruleidx);
				if (print_strings) {
					r_cons_printf ("0x%08" PFMT64x ": %s : ", n + offset, flag);
					r_print_bytes (print, match->data, match->data_length, "%02x");
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
	// TODO depending on error_level. use R_LOG_WARN, ERROR or INFO
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

	if (message == CALLBACK_MSG_RULE_MATCHING) {
		YR_STRING* string;
		r_cons_printf ("%s\n", rule->identifier);
		ruleidx = 0;
		yr_rule_strings_foreach (rule, string) {
			YR_MATCH* match;
			yr_string_matches_foreach (context, string, match) {
				n = match->base + match->offset;
				// Find virtual address if needed
				if (io_va) {
					RIOMap *map = r_io_map_get_paddr (core->io, n);
					if (map) {
						offset = r_io_map_begin (map) - map->delta;
					}
				}

				r_strf_var (flag, 256, "%s%d_%s_%d", "yara", flagidx, rule->identifier, ruleidx);
				if (print_strings) {
					r_cons_printf ("0x%08" PFMT64x ": %s : ", n + offset, flag);
					r_print_bytes (print, match->data, match->data_length, "%02x");
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
	// TODO depending on error_level. use R_LOG_WARN, ERROR or INFO
	eprintf ("file: %s line_number: %d.\n%s", file_name, line_number, message);
	return;
}
#endif

static int cmd_yara_scan(const RCore* core, R_NULLABLE const char* option) {
	RListIter* rules_it;
	YR_RULES* rules;
	void* to_scan;

	r_flag_space_push (core->flags, "yara");
	const unsigned int to_scan_size = r_io_size (core->io);
	io_va = r_config_get_b (core->config, "io.va");

	if (to_scan_size < 1) {
		R_LOG_ERROR ("Invalid file size");
		return false;
	}

	if (*option) {
		if (*option == '\0') {
			print_strings = false;
		} else if (*option == 'S') {
			print_strings = true;
		} else {
			print_strings = false;
			R_LOG_ERROR ("Invalid option");
			return false;
		}
	}

	to_scan = malloc (to_scan_size);
	if (!to_scan) {
		R_LOG_ERROR ("Something went wrong during memory allocation");
		return false;
	}

	int result = r_io_pread_at (core->io, 0L, to_scan, to_scan_size);
	if (!result) {
		R_LOG_ERROR ("Something went wrong during r_io_read_at");
		free (to_scan);
		return false;
	}
	r_list_foreach (rules_list, rules_it, rules) {
		yr_rules_scan_mem (rules, to_scan, to_scan_size, 0, callback, (void *)core, 0);
	}
	free (to_scan);

	return true;
}

static int cmd_yara_show(const char * name) {
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

static int cmd_yara_tags() {
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

static int cmd_yara_tag(const char * search_tag) {
	/* List rules with tag search_tag */
	RListIter* rules_it;
	YR_RULES* rules;
	YR_RULE* rule;
	const char* tag_name;

	r_list_foreach (rules_list, rules_it, rules) {
		yr_rules_foreach (rules, rule) {
			yr_rule_tags_foreach(rule, tag_name) {
				R_LOG_WARN ("Invalid option");
				if (r_str_casestr (tag_name, search_tag)) {
					r_cons_printf ("%s\n", rule->identifier);
					break;
				}
			}
		}
	}

	return true;
}

static int cmd_yara_list() {
	/* List all loaded rules */
	RListIter* rules_it;
	YR_RULES* rules;
	YR_RULE* rule;

	r_list_foreach (rules_list, rules_it, rules) {
		yr_rules_foreach (rules, rule) {
			r_cons_printf ("%s\n", rule->identifier);
		}
	}

	return true;
}

static int cmd_yara_clear() {
	/* Clears all loaded rules */
	r_list_free (rules_list);
	rules_list = r_list_newf ((RListFree) yr_rules_destroy);
	R_LOG_INFO ("Rules cleared");
	return true;
}

static void logerr(YR_COMPILER* compiler, R_NULLABLE const char *arg) {
	char buf[64];
	const char *errmsg = yr_compiler_get_error_message (compiler, buf, sizeof (buf));
	if (arg) {
		R_LOG_ERROR ("%s %s", errmsg, arg);
	} else {
		R_LOG_ERROR ("%s", errmsg);
	}
}

static int cmd_yara_add(const RCore* core, const char* input) {
	if (!input) {
		R_LOG_ERROR ("Missing argument");
		return false;
	}
	/* Add a rule with user input */
	YR_COMPILER* compiler = NULL;
	int result, i, continue_edit;

	for (i = 0; input[i]; i++) {
		if (input[i] != ' ') {
			return cmd_yara_add_file (input + i);
		}
	}

	if (yr_compiler_create (&compiler) != ERROR_SUCCESS) {
		logerr (compiler, NULL);
		return false;
	}

	char *old_template = strdup (yara_rule_template);
	char *modified_template = NULL;
	do {
		char *modified_template = r_core_editor (core, NULL, old_template);
		R_FREE (old_template);
		if (!modified_template) {
			R_LOG_ERROR ("Something bad happened with the temp file");
			goto err_exit;
		}

		result = yr_compiler_add_string (compiler, modified_template, NULL);
		if (result > 0) {
			logerr (compiler, NULL);
			continue_edit = r_cons_yesno ('y', "Do you want to continue editing the rule? [y]/n\n");
			if (!continue_edit) {
				goto err_exit;
			}
			old_template = modified_template;
			modified_template = NULL;
		}
	} while (result > 0);

	free (modified_template);
	if (compiler != NULL) {
		yr_compiler_destroy (compiler);
	}
	R_LOG_INFO ("Rule successfully added");
	return true;

err_exit:
	if (compiler != NULL) {
		yr_compiler_destroy (compiler);
	}
	free (modified_template);
	free (old_template);
	return false;
}

static int cmd_yara_add_file(const char* rules_path) {
	YR_COMPILER* compiler = NULL;
	YR_RULES* rules;

	if (!rules_path) {
		R_LOG_INFO ("Please tell me what am I supposed to load");
		return false;
	}

	FILE* rules_file = r_sandbox_fopen (rules_path, "r");
	if (!rules_file) {
		R_LOG_ERROR ("Unable to open %s", rules_path);
		return false;
	}

	if (yr_compiler_create (&compiler) != ERROR_SUCCESS) {
		logerr (compiler, NULL);
		goto err_exit;
	}

	int result = yr_compiler_add_file (compiler, rules_file, NULL, rules_path);
	fclose (rules_file);
	rules_file = NULL;
	if (result > 0) {
		logerr (compiler, rules_path);
		goto err_exit;
	}

	if (yr_compiler_get_rules (compiler, &rules) != ERROR_SUCCESS) {
		logerr (compiler, NULL);
		goto err_exit;
	}

	r_list_append (rules_list, rules);

	yr_compiler_destroy (compiler);
	return true;

err_exit:
	if (compiler) {
		yr_compiler_destroy (compiler);
	}
	if (rules_file) {
		fclose (rules_file);
	}
	return false;
}

static int cmd_yara_help(const RCore* core) {
	const char *help_message[] = {
		"Usage: yara", " [action] [args..]", " load and run yara rules inside r2",
		"yara", " add [file]", "Add yara rules from file, or open $EDITOR with yara rule template",
		"yara", " clear", "Clear all rules",
		"yara", " help", "Show this help (same as 'yara?')",
		"yara", " list", "List all rules",
		"yara", " scan[S]", "Scan the current file, if S option is given it prints matching strings",
		"yara", " show [name]", "Show rules containing name",
		"yara", " tag [name]", "List rules with tag 'name'",
		"yara", " tags", "List tags from the loaded rules",
		"yara", " version", "Show version information about r2yara and yara",
		NULL
	};
	r_core_cmd_help (core, help_message);
	return true;
}

static int cmd_yara_process(const RCore* core, const char* input) {
	char *inp = strdup (input);
	char *arg = r_str_after (inp, ' ');
	if (arg) {
		arg = (char *)r_str_trim_head_ro (arg);
	}
	int res = -1;
	if (r_str_startswith (input, "add")) {
		res = cmd_yara_add (core, arg);
	} else if (r_str_startswith (inp, "clear")) {
		res = cmd_yara_clear ();
	} else if (r_str_startswith (inp, "list")) {
		res = cmd_yara_list ();
	} else if (r_str_startswith (inp, "scan")) {
		res = cmd_yara_scan (core, arg);
	} else if (r_str_startswith (inp, "show")) {
		res = cmd_yara_show (arg);
	} else if (r_str_startswith (inp, "tags")) {
		res = cmd_yara_tags ();
	} else if (r_str_startswith (input, "tag ")) {
        	res = cmd_yara_tag (arg);
	} else if (r_str_startswith (input, "ver")) {
		r_cons_printf ("r2 %s\n", R2_VERSION);
		r_cons_printf ("yara %s\n", YR_VERSION);
		r_cons_printf ("r2yara %s\n", R2Y_VERSION);
		res = 0;
	} else {
		cmd_yara_help (core);
	}
	free (inp);
	return res;
}

static int cmd_yara_call(void *user, const char *input) {
	RCore* core = (RCore*) user;
	if (!r_str_startswith (input, "yara")) {
		return false;
	}
	if (!initialized && !cmd_yara_init (core, NULL)) {
		return false;
	}
	const char *args = input[4]? input + 5: input + 4;
	cmd_yara_process (core, args);
	return true;
}

static int cmd_yara_load_default_rules(const RCore* core) {
	RListIter* iter = NULL;
	YR_COMPILER* compiler = NULL;
	YR_RULES* yr_rules;
	char* filename, *complete_path;
	char* rules = NULL;
#if R2_VERSION_NUMBER < 50709
	char* y3_rule_dir = r_str_newf ("%s%s%s", r_str_home (R2_HOME_PLUGINS), R_SYS_DIR, "rules-yara3");
#else
	char* y3_rule_dir = r_xdg_datadir ("plugins/rules-yara3");
#endif
	RList* list = r_sys_dir (y3_rule_dir);

	if (yr_compiler_create (&compiler) != ERROR_SUCCESS) {
		logerr (compiler, NULL);
		goto err_exit;
	}

	yr_compiler_set_callback (compiler, compiler_callback, NULL);

	r_list_foreach (list, iter, filename) {
		if (filename[0] != '.') { // skip '.', '..' and hidden files
			complete_path = r_str_newf ("%s%s%s", y3_rule_dir, R_SYS_DIR, filename);
			rules = (char*)r_file_gzslurp (complete_path, NULL, true);
			R_FREE (complete_path);
			if (yr_compiler_add_string (compiler, rules, NULL) > 0) {
				logerr (compiler, NULL);
			}
			R_FREE (rules);
		}
	}
	r_list_free (list);

	if (yr_compiler_get_rules (compiler, &yr_rules) != ERROR_SUCCESS) {
		logerr (compiler, NULL);
		goto err_exit;
	}

	r_list_append (rules_list, yr_rules);

	if (compiler) {
		yr_compiler_destroy (compiler);
	}
	return true;

err_exit:
	free (y3_rule_dir);
	if (compiler) {
		yr_compiler_destroy (compiler);
	}
	r_list_free (list);
	free (rules);
	return false;
}

static int cmd_yara_init(void *user, const char *cmd) {
	RCore* core = (RCore *)user;
	rules_list = r_list_newf ((RListFree) yr_rules_destroy);
	yr_initialize ();
	cmd_yara_load_default_rules (core);
	initialized = true;
	flagidx = 0;
	return true;
}

static int cmd_yara_fini() {
	if (initialized) {
		r_list_free (rules_list);
		yr_finalize ();
		initialized = false;
	}
	return true;
}

RCorePlugin r_core_plugin_yara = {
	.meta = {
		.name = "yara",
		.desc = "YARA integration",
		.license = "LGPL",
		.version = "0.1.2",
	},
	.call = cmd_yara_call,
	.init = cmd_yara_init,
	.fini = cmd_yara_fini
};

#ifndef CORELIB
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_CORE,
	.data = &r_core_plugin_yara,
        .version = R2_VERSION
};
#endif
