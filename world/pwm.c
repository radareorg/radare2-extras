/* radare - LGPL - Copyright 2022 - pancake */

#include <r_lib.h>
#include <r_cmd.h>
#include <r_core.h>

const char *worldmap = "" \
"               ,_   .__._. _.  .                                     \n" \
"           , _-.','' .~      ~/      ;-'_   _-'     ,;_;_,    ~~-    \n" \
"  .-~^|_/-'~'--' .  | ',    ,'      /  / ~|-_]_/~/~      ~~--~~~~'--_\n" \
"  /              ,/'-/~ '  ,' _  , '|,'|~                   ._/-, /~ \n" \
"  |.^-'|_,       '-,| '|. '   ~  ,  /'~                /    /_  /~   \n" \
"o        '|        '',=~|        _|~     ,_  ,               /|      \n" \
"          '.        /'~          |_/)_.,-,~  ) :         ,_,/ |      \n" \
"           |       /            ._--'-_ _~|              [ ) /       \n" \
"           '|   __-|           '/      ~ |(  :_          /  ~        \n" \
"  .          '_ |  .~-_      = |          ||_' ~|  /|  .~ ,          \n" \
"               `-`/  /;       '|           '-,   |,' /|/  |          \n" \
"                 '__,~'-_       [_ _,       /'    '  |, /|'          \n" \
"                   /     '_       ' |      /         |  ~'; -,_.     \n" \
"                   |       '.        |    |  ,        '-_, ,; ~ ~.   \n" \
"                    |,      /        |_   / /|            ,-, ,   -, \n" \
"                     |    ,/          |  |' |/          ,-   ~ |   '.\n" \
"                    ,|   ,/           | ,/              |       |    \n" \
"                    /    |             =                 -~~-, /   _ \n" \
"                    |  ,-'                                    ~    / \n" \
"                    / ,'                                      ~      \n" \
"                    ',|  ~                                           \n" \
"                      ~'                                             \n";

typedef struct {
	int pos;
	const char *msg;
} RPrintMap;

static int cmpmap(RPrintMap *a, RPrintMap *b) {
	return b->pos - a->pos;
}


static int pwm(void *user, const char *input) {
	RList *foo = r_list_newf (free);
	if (r_str_startswith (input, "pwm")) {
		const char *nl = strchr (worldmap, '\n');
		int cols = nl - worldmap + 1;
		char *map = strdup (worldmap);
		char *inp = strdup (input);
		RList *args = r_str_split_list (inp, " ", 0);
		const char *arg;
		RListIter *iter;
		r_list_foreach (args, iter, arg) {
			int x = 0, y = 0;
			char s[32] = {0};
			sscanf (arg, "%d:%d:%s", &x, &y, s);
			// sscanf (arg, "%d:%d", &x, &y);
			if (x == 0 && y == 0) {
				continue;
			}
			int pos = x + (cols * y);
			if (pos < strlen (map)) {
				RPrintMap *pm = R_NEW0 (RPrintMap);
				pm->pos = pos;
				pm->msg = strdup (s);
				r_list_append (foo, pm);
			}
		}
		r_list_sort (foo, (RListComparator)cmpmap);
		RPrintMap *mi;
		r_list_foreach (foo, iter, mi) {
			char *ns = r_str_newf (Color_GREEN"%s"Color_RESET, mi->msg);
			map = r_str_insert (map, mi->pos, ns);
			free (ns);
		}
		r_cons_printf ("%s\n", map);
		r_list_free (args);
		r_list_free (foo);
		free (map);
		free (inp);
		return 1;
	}
	return 0;
}

RCorePlugin r_core_plugin_test = {
	.name = "pwm",
	.desc = "print world map",
	.license = "BSD",
	.call = pwm,
};

#ifndef CORELIB
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_CORE,
	.data = &r_core_plugin_test,
	.version = R2_VERSION
};
#endif
