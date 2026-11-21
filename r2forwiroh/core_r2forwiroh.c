/* radare - LGPL - Copyright 2026 */
#include <r_core.h>
#include <ctype.h>
#include "r2forwiroh.h"
#include "sync.inc.c"

typedef struct {
	R2FwHandle *transport;
	bool dispatching;
} R2Fw;

static const char *help =
	"r2fw start [state-dir] [local] Start networking; local disables Internet discovery/relays\n"
	"r2fw stop                    Cancel networking and join workers\n"
	"r2fw status[j]               JSON transport, invitation, jobs and pending core requests\n"
	"r2fw invite                  Rotate invitation and HTTP URL (expires in five minutes)\n"
	"r2fw qr                      Show current invitation QR\n"
	"r2fw cancel                  Invalidate invitation and HTTP URL\n"
	"r2fw pending                 List incoming pairing requests\n"
	"r2fw accept|reject <id>      Accept or reject a pending request\n"
	"r2fw connect <uri>           Pair with a server; it must accept the request\n"
	"r2fw open <peer> [token]     Forward an ephemeral local port to the peer's r2 service\n"
	"r2fw close                   Close the selected forwarding tunnel\n"
	"r2fw abort                   Cancel outgoing pairing\n"
	"r2fw disconnect <peer>       Disconnect without forgetting the peer\n"
	"r2fw network                 Notify forwiroh that local connectivity changed\n"
	"r2fw revoke <peer>           Revoke a trusted peer and disconnect it\n"
	"r2fw ping                    Check the selected peer's HTTP service\n"
	"r2fw cmd <quoted-command>    Run a command remotely\n"
	"r2fw sync push|pull          Merge comments and function entrypoints/names\n"
	"r2fw sync export             Export metadata JSON for inspection\n"
	"r2fw poll                    Execute up to 16 queued requests on this core thread\n"
	"r2fw serve                   Poll until Ctrl-C (networking stays in background)\n"
	"r2fw result [job-id]         Get asynchronous job output\n"
	"r2fw events                  Drain connection and pairing events\n";

static void fw_poll(RCorePluginSession *session) {
	R2Fw *fw = session->data;
	RCore *core = session->core;
	int i;
	fw->dispatching = true;
	for (i = 0; i < 16; i++) {
		char *raw = r2fw_call (fw->transport, "{\"op\":\"next\"}");
		RJson *json = r_json_parsedup (raw);
		r2fw_string_free (raw);
		const RJson *next = r_json_get (json, "data");
		const RJson *request = r_json_get (next, "request");
		const char *op = r_json_get_str (request, "op");
		if (!op) {
			r_json_free (json);
			break;
		}
		char *reply = NULL;
		if (!strcmp (op, "export")) {
			reply = fw_export (core);
		} else if (!strcmp (op, "import")) {
			reply = fw_import (core, r_json_get (request, "metadata"));
		} else if (!strcmp (op, "cmd")) {
			const char *command = r_json_get_str (request, "command");
			char *output = command? r_core_cmd_str (core, command): NULL;
			reply = output? fw_json ("data", output): NULL;
			free (output);
		}
		if (!reply) {
			reply = fw_error ("Cannot dispatch request");
		}
		char *message = r_str_newf ("{\"op\":\"reply\",\"id\":%" PFMT64u ",\"reply\":%s}", (ut64)r_json_get_num (next, "id"), reply);
		r2fw_string_free (r2fw_call (fw->transport, message));
		free (message);
		free (reply);
		r_json_free (json);
	}
	fw->dispatching = false;
}

static bool fw_remote(RCmdContext *ctx) {
	RCorePluginSession *session = ctx->handler_user;
	R2Fw *fw = session->data;
	const char *args[3];
	r_cmdctx_args (ctx, args, R_ARRAY_SIZE (args));
	char job[32];
	if (!strcmp (args[0], "result") && args[1]) {
		ut64 id = 0;
		if (!r_cmdctx_num (ctx, 1, session->core->num, &id)) {
			return false;
		}
		snprintf (job, sizeof (job), "%" PFMT64u, id);
		args[1] = job;
	}
	char *reply = r2fw_command (fw->transport, args, r_cmdctx_argc (ctx));
	RJson *json = r_json_parsedup (reply);
	const char *qr = r_json_get_str (r_json_get (json, "data"), "qr");
	r_cons_println (ctx->cons, qr? qr: reply);
	bool ok = json && !r_json_get (json, "error");
	r_json_free (json);
	r2fw_string_free (reply);
	return ok;
}

static bool fw_start(RCmdContext *ctx) {
	RCorePluginSession *session = ctx->handler_user;
	R2Fw *fw = session->data;
	const char *path = r_cmdctx_arg (ctx, 1).a;
	const char *mode = r_cmdctx_arg (ctx, 2).a;
	if (fw->transport || r_sandbox_enable (false) || (mode && strcmp (mode, "local"))) {
		R_LOG_ERROR ("Already started, sandboxed, or invalid mode");
		return false;
	}
	char *directory = path? strdup (path): r_xdg_datadir ("r2forwiroh");
	fw->transport = directory? r2fw_new (directory, mode != NULL): NULL;
	free (directory);
	if (!fw->transport) {
		return false;
	}
	r_cons_println (ctx->cons, "{\"state\":\"starting\"}");
	return true;
}

static bool fw_stop(RCmdContext *ctx) {
	RCorePluginSession *session = ctx->handler_user;
	R2Fw *fw = session->data;
	r2fw_free (fw->transport);
	fw->transport = NULL;
	return true;
}

static bool fw_run(RCmdContext *ctx) {
	RCorePluginSession *session = ctx->handler_user;
	R2Fw *fw = session->data;
	if (!fw->transport) {
		R_LOG_ERROR ("Run r2fw start first");
		return false;
	}
	if (!strcmp (r_cmdctx_arg (ctx, 0).a, "poll")) {
		fw_poll (session);
	} else {
		r_cons_break_push (ctx->cons, NULL, NULL);
		while (!r_cons_is_breaked (ctx->cons)) {
			fw_poll (session);
			r_sys_usleep (10000);
		}
		r_cons_break_pop (ctx->cons);
	}
	return true;
}

static bool fw_sync(RCmdContext *ctx) {
	if (strcmp (r_cmdctx_arg (ctx, 1).a, "export")) {
		return fw_remote (ctx);
	}
	RCorePluginSession *session = ctx->handler_user;
	char *reply = fw_export (session->core);
	r_cons_println (ctx->cons, reply);
	free (reply);
	return true;
}

static const struct {
	const char *name;
	size_t min, max;
	bool (*run)(RCmdContext *ctx);
} local_commands[] = {
	{ "start", 1, 3, fw_start },
	{ "stop", 1, 1, fw_stop },
	{ "poll", 1, 1, fw_run },
	{ "serve", 1, 1, fw_run },
	{ "sync", 2, 2, fw_sync }
};

static RCmdResult fw_command(RCmdContext *ctx) {
	RCorePluginSession *session = ctx->handler_user;
	R2Fw *fw = session->data;
	const char *name = r_cmdctx_arg (ctx, 0).a;
	size_t argc = r_cmdctx_argc (ctx);
	if (fw->dispatching) {
		R_LOG_ERROR ("Remote commands cannot manage their own transport");
		return (RCmdResult) { .status = 1 };
	}
	if (!name || r_cmdctx_help (ctx)) {
		r_cons_print (ctx->cons, help);
		return (RCmdResult) { 0 };
	}
	if (argc > 3 || r_strs_len (ctx->subcmd)) {
		goto invalid;
	}
	for (size_t i = 0; i < argc; i++) {
		RStrs arg = r_cmdctx_arg (ctx, i);
		if (strlen (arg.a) != r_strs_len (arg)) {
			goto invalid;
		}
	}
	for (size_t i = 0; i < R_ARRAY_SIZE (local_commands); i++) {
		if (!strcmp (name, local_commands[i].name)) {
			if (argc < local_commands[i].min || argc > local_commands[i].max) {
				goto invalid;
			}
			return (RCmdResult) { .status = local_commands[i].run (ctx)? 0: 1 };
		}
	}
	return (RCmdResult) { .status = fw_remote (ctx)? 0: 1 };
invalid:
	R_LOG_ERROR ("Invalid arguments. Use r2fw?");
	return (RCmdResult) { .status = 1 };
}

static bool fw_init(RCorePluginSession *session) {
	session->data = R_NEW0 (R2Fw);
	return session->data != NULL;
}

static bool fw_fini(RCorePluginSession *session) {
	R2Fw *fw = session->data;
	if (fw) {
		r2fw_free (fw->transport);
		free (fw);
	}
	session->data = NULL;
	return true;
}

RCorePlugin r_core_plugin_r2forwiroh = {
	.meta = {
		.name = "r2forwiroh",
		.desc = "Share an r2 session over forwiroh",
		.author = "pancake",
		.license = "LGPL-3.0-only"
	},
	.init = fw_init,
	.fini = fw_fini,
	.command = "r2fw",
	.call_ctx = fw_command
};

#ifndef R2_PLUGIN_INCORE
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_CORE,
	.data = &r_core_plugin_r2forwiroh,
	.version = R2_VERSION
};
#endif
