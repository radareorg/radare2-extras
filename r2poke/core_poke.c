/* radare - LGPLv3 - Copyright 2023 - pancake */

#include <r_core.h>
#include <libpoke.h>

// XXX dont polute the global space
static R_TH_LOCAL RCore *Gcore = NULL;
static R_TH_LOCAL pk_compiler pc = NULL;

#include "term.c"
#include "iod.c"

static const char *exception_handler="\
fun r2_exception_handler = (Exception exception) void:\
{\
  if (exception.code != EC_exit && exception.code != EC_signal)\
  {\
    print (\"unhandled \"\
           + (exception.name == \"\" ? \"unknown\" : exception.name)\
           + \" exception\n\");\
\
    if (exception.location != \"\" || exception.msg != \"\")\
    {\
      if (exception.location != \"\")\
        print (exception.location + \" \");\
      print (exception.msg + \"\n\");\
    }\
  }\
}";

static void
poke_handle_exception (pk_val exception)
{
  pk_val handler = pk_decl_val (pc, "r2_exception_handler");

  if (handler == PK_NULL)
    R_LOG_ERROR ("Couldn't get a handler for poke gdb_exception_handler");
  if (pk_call (pc, handler, NULL, NULL, 1, exception)
      == PK_ERROR)
    R_LOG_ERROR ("Couldn't call gdb_exception_handler in poke");
}


static int r_cmd_poke_call(void *user, const char *input) {
	Gcore = (RCore*)user;
	if (r_str_startswith (input, "poke")) {
		pk_val exception, exit_exception;
		if (!input[4] || r_str_startswith (input + 4, " -h")) {
			eprintf ("Usage: poke [-h]|[-f file] [expr]\n");
			return true;
		}
		if (r_str_startswith (input + 4, " -q")) {
			return true;
		}
		if (r_str_startswith (input + 4, " -f ")) {
			const char *filename = r_str_trim_head_ro (input + 8);
			pk_compile_file (pc, filename, &exit_exception);
			return true;
		}
		if (r_str_startswith (input + 4, " -")) {
			R_LOG_ERROR ("Unknown flag");
			return true;
		}
		const char *expr = r_str_trim_head_ro (input + 4);
		if (pk_compile_buffer (pc, expr, NULL, &exit_exception) != PK_OK) {
			R_LOG_ERROR ("Buffer compile fails");
		}
		if (exit_exception != PK_NULL) {
			poke_handle_exception (exit_exception);
			R_LOG_ERROR ("Syntax error");
		}
#if 0
		// LOAD
		R_LOG_INFO ("Loading UUID pickle");
		pk_compile_file (pc, "poke/pickles/uuid.pk", &exit_exception);
		pk_compile_buffer (pc, "var a = UUID @ 0#B;", NULL, &exit_exception);
		if (pk_compile_buffer (pc, "printf(\"fHELLO %i60d\\n\", (UUID@0#b).get_time());", NULL, &exit_exception)) {
			R_LOG_ERROR("fhLLOE ");
		}
		pk_compile_buffer (pc, "print(\"HELLO\\n\");", NULL, &exit_exception);
		if (pk_compile_buffer (pc, "var u=UUID @ 0#b;print(\"jeje\\n\");printf(\"time:%i60d\\n\", u.get_time());", NULL, &exit_exception) != PK_OK) {
			R_LOG_ERROR ("Buffer compile fails");
		}
#endif
		r_cons_newline ();
		r_cons_flush ();
#if 0
 4363      (poke) var elf = Elf64_File @ 0#B
 4364      (poke) elf.get_sections_by_name (".text")
#endif
#if 0
		// int pk_load (pk_compiler pkc, const char *module) LIBPOKE_API;
		r_cons_flush ();
		R_LOG_INFO ("Disassembling \"pop\" expression");
		pk_disassemble_expression (pc, "\"pop\"", 0);
		r_cons_flush ();
		R_LOG_INFO ("Printing profile");
		pk_print_profile (pc);
#endif
		r_cons_flush ();
		return true;
	}
	return false;
}

static struct pk_alien_token * alientoken(const char *id, char **errmsg) {
	eprintf ("Resolve alien with id (%s)\n", id);
	return NULL;
}

// init's user is RLibPlugin not RCore!
static int r_cmd_poke_init(void *user, const char *cmd) {
	pk_val exit_exception;
	pc = pk_compiler_new_with_flags (&poke_term_if, PK_F_NOSTDTYPES);
	if (pc == NULL) {
		R_LOG_ERROR ("Cannot initialize the poke compiler");
		return true;
	}
#if 0
	Gcore = (RCore*)user;
#endif
	pk_set_obase (pc, 16);
	pk_set_omode (pc, PK_PRINT_TREE);
	if (pk_compile_buffer (pc, exception_handler, NULL, &exit_exception) != PK_OK) {
		R_LOG_ERROR ("Buffer compile fails");
	}
	pk_set_alien_token_fn (pc, alientoken);
	if (pk_register_iod (pc, &iod_if) != PK_OK) {
		R_LOG_ERROR ("Could not register the foreign IO device interface in poke");
	}
#if 0
	if (pk_compile_buffer (pc, &exception, NULL, &exit_exception) != PK_OK) {
		R_LOG_ERROR ("Buffer compile fails");
	}
#endif
	/* load std types */
	if (pk_compile_buffer (pc, "load \"std-types.pk\";", NULL, &exit_exception) != PK_OK) {
		R_LOG_ERROR ("Buffer compile fails");
	}
	if (pk_compile_buffer (pc, "open(\"<r2>\");", NULL, &exit_exception) != PK_OK) {
		R_LOG_ERROR ("Cannot open the R2 IO device");
	}


	return true;
}

static int r_cmd_poke_fini(void *user, const char *cmd) {
	RCore *core = (RCore *)user;
	if (!pc) {
		return 0;
	}
	pk_val val, exit_exception;
	if (pk_compile_statement (pc,
				"try close (get_ios); catch if E_no_ios {}",
				NULL, &val, &exit_exception) != PK_OK
			|| exit_exception != PK_NULL) {
		R_LOG_ERROR ("while closing an IOS on exit");
	}
	pk_compiler_free (pc);
	Gcore = NULL;
	pc = NULL;

	return 0;
}

RCorePlugin r_core_plugin_poke = {
	.name = "poke",
	.desc = "GNU/POKE for radare2",
	.license = "GPL3",
	.call = r_cmd_poke_call,
	.init = r_cmd_poke_init,
	.fini = r_cmd_poke_fini
};

#ifndef CORELIB
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_CORE,
	.data = &r_core_plugin_poke,
        .version = R2_VERSION
};
#endif
