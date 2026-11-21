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

static char *fw_call(R2Fw *fw, const char *request) {
	char *owned = r2fw_call (fw->transport, request);
	char *copy = owned? strdup (owned): fw_error ("Transport returned no reply");
	r2fw_string_free (owned);
	return copy;
}

static void fw_poll(RCorePluginSession *session) {
	R2Fw *fw = session->data;
	RCore *core = session->core;
	int i;
	fw->dispatching = true;
	for (i = 0; i < 16; i++) {
		char *raw = fw_call (fw, "{\"op\":\"next\"}");
		RJson *json = r_json_parse (raw);
		const RJson *next = r_json_get (json, "data");
		const RJson *request = r_json_get (next, "request");
		const char *op = r_json_get_str (request, "op");
		if (!op) {
			r_json_free (json);
			free (raw);
			break;
		}
		char *reply = NULL;
		if (!strcmp (op, "export")) {
			reply = fw_export (core);
		} else if (!strcmp (op, "import")) {
			reply = fw_import (core, r_json_get (request, "metadata"));
		} else if (!strcmp (op, "cmd")) {
			const char *command = r_json_get_str (request, "command");
			RCoreTask *task = command? r_core_task_new (core, R_CORE_TASK_MODE_COOP, true, command, NULL, NULL): NULL;
			if (task) {
				r_core_task_run_sync (&core->tasks, task);
				PJ *pj = pj_new ();
				pj_o (pj);
				pj_ks (pj, "data", r_str_get (task->res));
				pj_end (pj);
				reply = pj_drain (pj);
				r_core_task_free (task);
			}
		}
		if (!reply) {
			reply = fw_error ("Cannot dispatch request");
		}
		PJ *pj = pj_new ();
		pj_o (pj);
		pj_ks (pj, "op", "reply");
		pj_kn (pj, "id", r_json_get_num (next, "id"));
		pj_k (pj, "reply");
		pj_raw (pj, reply);
		pj_end (pj);
		char *ack = fw_call (fw, pj_string (pj));
		free (ack);
		pj_free (pj);
		free (reply);
		r_json_free (json);
		free (raw);
	}
	fw->dispatching = false;
}

static RCmdResult fw_command(RCmdContext *ctx) {
	RCorePluginSession *session = ctx->handler_user;
	R2Fw *fw = session->data;
	const char *args[3];
	r_cmdctx_args (ctx, args, R_ARRAY_SIZE (args));
	const char *op = args[0];
	RCmdResult result = { .status = 1 };
	if (fw->dispatching) {
		R_LOG_ERROR ("Remote commands cannot manage their own transport");
		return result;
	}
	for (size_t i = 0; i < r_cmdctx_argc (ctx); i++) {
		RStrs arg = r_cmdctx_arg (ctx, i);
		if (strlen (arg.a) != r_strs_len (arg)) {
			R_LOG_ERROR ("NUL in argument");
			return result;
		}
	}
	if (r_strs_len (ctx->subcmd) && !r_cmdctx_help (ctx)) {
		R_LOG_ERROR ("Unknown command suffix. Use r2fw?");
		return result;
	}
	if (!op || r_cmdctx_help (ctx)) {
		r_cons_print (ctx->cons, help);
		return (RCmdResult) { 0 };
	}
	if (!strcmp (op, "start")) {
		if (fw->transport || r_cmdctx_argc (ctx) > 3 || (args[2] && strcmp (args[2], "local"))) {
			R_LOG_ERROR ("Already started, or too many arguments");
			return result;
		}
		if (r_sandbox_enable (false)) {
			R_LOG_ERROR ("Forwiroh cannot be started in sandbox mode");
			return result;
		}
		char *path = args[1]? strdup (args[1]): r_xdg_datadir ("r2forwiroh");
		fw->transport = path? r2fw_new (path, args[2] != NULL): NULL;
		free (path);
		if (!fw->transport) {
			return result;
		}
		r_cons_println (ctx->cons, "{\"state\":\"starting\"}");
		return (RCmdResult) { 0 };
	}
	if (!strcmp (op, "stop")) {
		if (r_cmdctx_argc (ctx) != 1) {
			return result;
		}
		r2fw_free (fw->transport);
		fw->transport = NULL;
		return (RCmdResult) { 0 };
	}
	if (!fw->transport) {
		if (!strcmp (op, "status") || !strcmp (op, "statusj")) {
			r_cons_println (ctx->cons, "{\"data\":{\"transport\":{\"state\":\"stopped\"},\"invite\":null,\"pending_commands\":0,\"remote_port\":0,\"results\":[]}}");
			return (RCmdResult) { 0 };
		}
		R_LOG_ERROR ("Run r2fw start first");
		return result;
	}
	if (!strcmp (op, "poll") || !strcmp (op, "serve")) {
		if (r_cmdctx_argc (ctx) != 1) {
			return result;
		}
		bool serve = !strcmp (op, "serve");
		if (serve) {
			r_cons_break_push (ctx->cons, NULL, NULL);
		}
		do {
			fw_poll (session);
			if (serve) {
				r_sys_usleep (10000);
			}
		} while (serve && !r_cons_is_breaked (ctx->cons));
		if (serve) {
			r_cons_break_pop (ctx->cons);
		}
		return (RCmdResult) { 0 };
	}
	if (!strcmp (op, "sync") && args[1] && !strcmp (args[1], "export") && r_cmdctx_argc (ctx) == 2) {
		char *reply = fw_export (session->core);
		r_cons_println (ctx->cons, reply);
		free (reply);
		return (RCmdResult) { 0 };
	}
	PJ *pj = pj_new ();
	pj_o (pj);
	const char *key = NULL;
	const char *value = args[1];
	size_t argc = r_cmdctx_argc (ctx);
	if ((!strcmp (op, "status") || !strcmp (op, "statusj") || !strcmp (op, "invite")
			|| !strcmp (op, "cancel") || !strcmp (op, "qr") || !strcmp (op, "ping")
			|| !strcmp (op, "events") || !strcmp (op, "pending") || !strcmp (op, "close")
			|| !strcmp (op, "abort") || !strcmp (op, "network")) && argc == 1) {
		pj_ks (pj, "op", !strcmp (op, "statusj")? "status": !strcmp (op, "pending")? "peer_pending":
			!strcmp (op, "abort")? "pair_cancel": !strcmp (op, "network")? "network_change": op);
	} else if (!strcmp (op, "result") && argc <= 2) {
		pj_ks (pj, "op", op);
		if (value) {
			ut64 id = 0;
			if (!r_cmdctx_num (ctx, 1, session->core->num, &id)) {
				goto invalid;
			}
			pj_kn (pj, "id", id);
		}
	} else if ((!strcmp (op, "accept") || !strcmp (op, "reject")) && argc == 2) {
		pj_ks (pj, "op", "peer_approve");
		pj_kb (pj, "accept", !strcmp (op, "accept"));
		key = "id";
	} else if ((!strcmp (op, "revoke") || !strcmp (op, "disconnect")) && argc == 2) {
		pj_ks (pj, "op", !strcmp (op, "revoke")? "peer_revoke": "peer_disconnect");
		key = "peer";
	} else if (!strcmp (op, "connect") && argc == 2) {
		pj_ks (pj, "op", op);
		key = "uri";
	} else if (!strcmp (op, "open") && argc >= 2 && argc <= 3) {
		pj_ks (pj, "op", op);
		key = "peer";
		if (args[2]) {
			pj_ks (pj, "token", args[2]);
		}
	} else if (!strcmp (op, "cmd") && argc == 2) {
		pj_ks (pj, "op", op);
		key = "command";
	} else if (!strcmp (op, "sync") && argc == 2 && (!strcmp (value, "push") || !strcmp (value, "pull"))) {
		pj_ks (pj, "op", value);
	} else {
		goto invalid;
	}
	if (key) {
		pj_ks (pj, key, value);
	}
	pj_end (pj);
	char *reply = fw_call (fw, pj_string (pj));
	if (!strcmp (op, "qr")) {
		RJson *json = r_json_parse (reply);
		const RJson *data = r_json_get (json, "data");
		const char *qr = r_json_get_str (data, "qr");
		r_cons_println (ctx->cons, qr? qr: reply);
		r_json_free (json);
	} else {
		r_cons_println (ctx->cons, reply);
	}
	free (reply);
	pj_free (pj);
	return (RCmdResult) { 0 };
invalid:
	pj_free (pj);
	R_LOG_ERROR ("Invalid arguments. Use r2fw?");
	return result;
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
