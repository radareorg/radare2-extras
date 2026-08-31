/* radare - LGPL - Copyright 2026 - pancake */

// Core plugin exposing the current radare2 session to the Chrome DevTools
// Protocol (CDP), so a Chromium/Edge "inspect" frontend (chrome://inspect)
// can discover this r2 instance as a remote target and drive a JavaScript
// REPL over the r2 QuickJS (r2js) engine from the DevTools Console.
//
//   webdev [port]     start the DevTools server (blocking, ^C to stop)
//   webdev            same, default port 9229
//   webdev?           show help
//
// Discovery (spoken by chrome://inspect over plain HTTP):
//   GET /json/version   -> browser identity + protocol version
//   GET /json[/list]    -> array with this r2 session as a single target
//   GET /               -> a human readable landing page
// then DevTools upgrades to a WebSocket and speaks CDP. We implement enough of
// Runtime.* to make the Console usable: every expression typed in the console
// is evaluated through `js base64:...` and its output is returned.
//
// NOTE: Apple's Safari "Develop" menu uses the WebKit Remote Web Inspector
// protocol (registered with webinspectord), which is NOT CDP, so Safari can't
// discover this. Any Chromium-based DevTools frontend can.

#include <r_core.h>
#include <r_cons.h>
#include <r_socket.h>
#include <r_hash.h>
#include <r_util.h>
#include <unistd.h>

#define WD_DEFAULT_PORT "9229"
#define WS_GUID "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
#define WS_MAX_FRAME (64 * 1024 * 1024)

// ---------------------------------------------------------------------------
// small helpers
// ---------------------------------------------------------------------------

static char *json_escape(const char *s) {
	if (!s) {
		return strdup ("");
	}
	RStrBuf *sb = r_strbuf_new ("");
	const unsigned char *p = (const unsigned char *)s;
	for (; *p; p++) {
		unsigned char c = *p;
		switch (c) {
		case '"': r_strbuf_append (sb, "\\\""); break;
		case '\\': r_strbuf_append (sb, "\\\\"); break;
		case '\n': r_strbuf_append (sb, "\\n"); break;
		case '\r': r_strbuf_append (sb, "\\r"); break;
		case '\t': r_strbuf_append (sb, "\\t"); break;
		default:
			if (c < 0x20) {
				r_strbuf_appendf (sb, "\\u%04x", c);
			} else {
				r_strbuf_appendf (sb, "%c", c);
			}
		}
	}
	return r_strbuf_drain (sb);
}

static const char *session_file(RCore *core) {
	if (core->io && core->io->desc && core->io->desc->name) {
		return core->io->desc->name;
	}
	return "(no file)";
}

static char *session_cwd(void) {
	char buf[4096];
	if (getcwd (buf, sizeof (buf))) {
		return strdup (buf);
	}
	return strdup ("");
}

// ---------------------------------------------------------------------------
// r2js evaluation: run an expression through QuickJS and capture its output
// ---------------------------------------------------------------------------

static char *eval_js(RCore *core, const char *expr) {
	// Wrap the expression so its value is printed to the r2 console (which
	// r_core_cmd_str captures). r2.log writes to the cons buffer. The whole
	// wrapper is base64-encoded and handed to `js base64:` so that r2's own
	// command parsing never sees the raw characters (;, @, |, quotes...).
	RStrBuf *sb = r_strbuf_new ("");
	r_strbuf_append (sb, "(function(){var __v;try{__v=(");
	r_strbuf_append (sb, expr && *expr ? expr : "undefined");
	r_strbuf_append (sb, "\n);}catch(e){r2.log('Uncaught '+(e&&e.stack?e.stack:e));return;}"
		"if(typeof __v!=='undefined'){r2.log(typeof __v==='object'?"
		"JSON.stringify(__v):(''+__v));}})()");
	char *wrapper = r_strbuf_drain (sb);
	char *b64 = r_base64_encode_dyn ((const ut8 *)wrapper, strlen (wrapper));
	free (wrapper);
	if (!b64) {
		return strdup ("");
	}
	char *cmd = r_str_newf ("js base64:%s", b64);
	free (b64);
	char *out = r_core_cmd_str (core, cmd);
	free (cmd);
	if (!out) {
		return strdup ("");
	}
	r_str_trim (out); // drop trailing newline noise
	return out;
}

// ---------------------------------------------------------------------------
// WebSocket framing (server side: we read masked frames, write unmasked)
// ---------------------------------------------------------------------------

static char *ws_accept_key(const char *key) {
	char buf[512];
	snprintf (buf, sizeof (buf), "%s%s", key, WS_GUID);
	RHash *h = r_hash_new (true, R_HASH_SHA1);
	r_hash_do_sha1 (h, (const ut8 *)buf, strlen (buf));
	char *out = r_base64_encode_dyn (h->digest, 20);
	r_hash_free (h);
	return out;
}

// read one frame; returns malloc'd payload (NUL terminated), sets *opcode/*len
static char *ws_recv(RSocket *s, int *opcode, ut64 *outlen) {
	ut8 hdr[2];
	if (r_socket_read_block (s, hdr, 2) != 2) {
		return NULL;
	}
	*opcode = hdr[0] & 0x0f;
	bool masked = (hdr[1] & 0x80) != 0;
	ut64 len = hdr[1] & 0x7f;
	if (len == 126) {
		ut8 e[2];
		if (r_socket_read_block (s, e, 2) != 2) {
			return NULL;
		}
		len = ((ut64)e[0] << 8) | e[1];
	} else if (len == 127) {
		ut8 e[8];
		if (r_socket_read_block (s, e, 8) != 8) {
			return NULL;
		}
		len = 0;
		int i;
		for (i = 0; i < 8; i++) {
			len = (len << 8) | e[i];
		}
	}
	if (len > WS_MAX_FRAME) {
		return NULL;
	}
	ut8 mask[4] = {0};
	if (masked && r_socket_read_block (s, mask, 4) != 4) {
		return NULL;
	}
	char *payload = malloc (len + 1);
	if (!payload) {
		return NULL;
	}
	if (len && r_socket_read_block (s, (ut8 *)payload, (int)len) != (int)len) {
		free (payload);
		return NULL;
	}
	if (masked) {
		ut64 i;
		for (i = 0; i < len; i++) {
			payload[i] ^= mask[i & 3];
		}
	}
	payload[len] = 0;
	if (outlen) {
		*outlen = len;
	}
	return payload;
}

static void ws_send_frame(RSocket *s, ut8 opcode_byte, const char *data, ut64 len) {
	ut8 hdr[10];
	int hl;
	hdr[0] = opcode_byte;
	if (len < 126) {
		hdr[1] = (ut8)len;
		hl = 2;
	} else if (len <= 0xffff) {
		hdr[1] = 126;
		hdr[2] = (len >> 8) & 0xff;
		hdr[3] = len & 0xff;
		hl = 4;
	} else {
		hdr[1] = 127;
		int i;
		for (i = 0; i < 8; i++) {
			hdr[2 + i] = (len >> ((7 - i) * 8)) & 0xff;
		}
		hl = 10;
	}
	r_socket_write (s, hdr, hl);
	if (len) {
		r_socket_write (s, (void *)data, (int)len);
	}
}

static void ws_send_text(RSocket *s, const char *msg) {
	ws_send_frame (s, 0x81, msg, strlen (msg));
}

// ---------------------------------------------------------------------------
// Chrome DevTools Protocol dispatch
// ---------------------------------------------------------------------------

static void cdp_reply(RSocket *s, int id, const char *inner_result) {
	char *msg = r_str_newf ("{\"id\":%d,\"result\":%s}", id,
		inner_result ? inner_result : "{}");
	ws_send_text (s, msg);
	free (msg);
}

static void cdp_event(RSocket *s, const char *method, const char *params) {
	char *msg = r_str_newf ("{\"method\":\"%s\",\"params\":%s}", method,
		params ? params : "{}");
	ws_send_text (s, msg);
	free (msg);
}

static void cdp_dispatch(RCore *core, RSocket *s, char *msg) {
	RJson *root = r_json_parse (msg);
	if (!root) {
		return;
	}
	const RJson *jid = r_json_get (root, "id");
	const RJson *jm = r_json_get (root, "method");
	int id = (jid && jid->type == R_JSON_INTEGER) ? (int)jid->num.s_value : 0;
	const char *method = (jm && jm->type == R_JSON_STRING) ? jm->str_value : "";

	if (!strcmp (method, "Runtime.enable")) {
		cdp_event (s, "Runtime.executionContextCreated",
			"{\"context\":{\"id\":1,\"origin\":\"\",\"name\":\"radare2\","
			"\"uniqueId\":\"1\",\"auxData\":{\"isDefault\":true}}}");
		cdp_reply (s, id, "{}");
	} else if (!strcmp (method, "Runtime.evaluate")
			|| !strcmp (method, "Runtime.callFunctionOn")) {
		const RJson *p = r_json_get (root, "params");
		const RJson *e = p ? r_json_get (p, "expression") : NULL;
		const char *expr = (e && e->type == R_JSON_STRING) ? e->str_value : "";
		char *out = eval_js (core, expr);
		if (out && *out) {
			char *esc = json_escape (out);
			char *inner = r_str_newf (
				"{\"result\":{\"type\":\"string\",\"value\":\"%s\"}}", esc);
			cdp_reply (s, id, inner);
			free (inner);
			free (esc);
		} else {
			cdp_reply (s, id, "{\"result\":{\"type\":\"undefined\"}}");
		}
		free (out);
	} else if (!strcmp (method, "Debugger.enable")) {
		cdp_reply (s, id, "{\"debuggerId\":\"1\"}");
	} else if (!strcmp (method, "Runtime.getHeapUsage")) {
		cdp_reply (s, id, "{\"usedSize\":0,\"totalSize\":0}");
	} else if (!strcmp (method, "Runtime.compileScript")) {
		cdp_reply (s, id, "{\"scriptId\":\"1\"}");
	} else {
		// Runtime.runIfWaitingForDebugger, Log.enable, Profiler.enable,
		// Network.enable, Page.enable, Runtime.discardConsoleEntries, ...
		cdp_reply (s, id, "{}");
	}
	r_json_free (root);
}

// ---------------------------------------------------------------------------
// HTTP + upgrade handling for a single accepted connection
// ---------------------------------------------------------------------------

static void http_respond(RSocket *s, int code, const char *status,
		const char *ctype, const char *body) {
	int blen = body ? (int)strlen (body) : 0;
	r_socket_printf (s, "HTTP/1.1 %d %s\r\nContent-Type: %s\r\n"
		"Content-Length: %d\r\nConnection: close\r\n"
		"Access-Control-Allow-Origin: *\r\n\r\n", code, status, ctype, blen);
	if (blen) {
		r_socket_write (s, (void *)body, blen);
	}
}

static char *discovery_target(RCore *core, const char *host) {
	int pid = r_sys_getpid ();
	char *cwd = session_cwd ();
	char *file_esc = json_escape (session_file (core));
	char *cwd_esc = json_escape (cwd);
	char *ver = r_str_newf ("radare2/%s", R2_VERSION);
	char *ver_esc = json_escape (ver);
	char *t = r_str_newf (
		"{\"description\":\"%s\","
		"\"id\":\"r2-%d\","
		"\"title\":\"%s\","
		"\"type\":\"node\","
		"\"url\":\"file://%s\","
		"\"faviconUrl\":\"\","
		"\"devtoolsFrontendUrl\":\"devtools://devtools/bundled/js_app.html?experiments=true&v8only=true&ws=%s/r2-%d\","
		"\"webSocketDebuggerUrl\":\"ws://%s/r2-%d\"}",
		ver_esc, pid, file_esc, cwd_esc, host, pid, host, pid);
	free (cwd);
	free (file_esc);
	free (cwd_esc);
	free (ver);
	free (ver_esc);
	return t;
}

static void serve_landing(RCore *core, RSocket *s, const char *host) {
	char *file_esc = json_escape (session_file (core));
	char *cwd = session_cwd ();
	char *html = r_str_newf (
		"<!doctype html><html><head><meta charset=utf-8>"
		"<title>r2 webdev</title><style>body{font-family:monospace;"
		"background:#111;color:#ddd;padding:2em}a{color:#6cf}"
		"code{color:#9f9}</style></head><body>"
		"<h1>radare2 webdev</h1>"
		"<p>file: <code>%s</code></p>"
		"<p>pid: <code>%d</code></p>"
		"<p>cwd: <code>%s</code></p>"
		"<p>This r2 session is exposed over the Chrome DevTools Protocol.</p>"
		"<ol><li>Open <code>chrome://inspect</code> in Chromium/Edge</li>"
		"<li>Click <b>Configure...</b> and add <code>%s</code></li>"
		"<li>This session appears under <b>Remote Target</b> &mdash; click "
		"<b>inspect</b></li>"
		"<li>In the DevTools <b>Console</b>, run JS one-liners against r2, e.g. "
		"<code>r2.cmd('ij')</code>, <code>r2.cmd('afl')</code>, "
		"<code>r2.cmd('ls')</code></li></ol>"
		"<p>Discovery: <a href=\"/json/list\">/json/list</a> &middot; "
		"<a href=\"/json/version\">/json/version</a></p>"
		"</body></html>",
		file_esc, r_sys_getpid (), cwd, host);
	http_respond (s, 200, "OK", "text/html", html);
	free (html);
	free (file_esc);
	free (cwd);
}

// returns true if a websocket session was served (connection consumed)
static void handle_client(RCore *core, RSocket *s, const char *portstr) {
	char method[16] = {0};
	char path[2048] = {0};
	char host[256] = {0};
	char wskey[256] = {0};
	bool upgrade = false;

	// the socket returned by accept_timeout is non-blocking; make it block so
	// the request read waits for the full header block
	r_socket_block_time (s, true, 0, 0);

	// slurp the request header block (up to the empty CRLF line) byte by byte.
	// r_socket_gets discards data past the first newline in a recv chunk, so we
	// read raw and split into lines ourselves.
	char req[16384];
	int total = 0;
	while (total < (int)sizeof (req) - 1) {
		ut8 c;
		if (r_socket_read_block (s, &c, 1) != 1) {
			break;
		}
		req[total++] = (char)c;
		if (total >= 4 && !memcmp (req + total - 4, "\r\n\r\n", 4)) {
			break;
		}
		if (total >= 2 && !memcmp (req + total - 2, "\n\n", 2)) {
			break;
		}
	}
	req[total] = 0;
	if (total == 0) {
		return;
	}
	// parse line by line
	char *save = NULL;
	char *line = r_str_tok_r (req, "\r\n", &save);
	if (line) {
		sscanf (line, "%15s %2047s", method, path);
	}
	while ((line = r_str_tok_r (NULL, "\r\n", &save))) {
		if (!r_str_ncasecmp (line, "Host:", 5)) {
			r_str_ncpy (host, r_str_trim_head_ro (line + 5), sizeof (host));
		} else if (!r_str_ncasecmp (line, "Upgrade:", 8)) {
			if (r_str_casestr (line + 8, "websocket")) {
				upgrade = true;
			}
		} else if (!r_str_ncasecmp (line, "Sec-WebSocket-Key:", 18)) {
			r_str_ncpy (wskey, r_str_trim_head_ro (line + 18), sizeof (wskey));
		}
	}
	if (!*host) {
		snprintf (host, sizeof (host), "127.0.0.1:%s", portstr);
	}

	if (upgrade && *wskey) {
		char *accept = ws_accept_key (wskey);
		r_socket_printf (s, "HTTP/1.1 101 Switching Protocols\r\n"
			"Upgrade: websocket\r\nConnection: Upgrade\r\n"
			"Sec-WebSocket-Accept: %s\r\n\r\n", accept);
		free (accept);
		eprintf ("[webdev] DevTools connected\n");
		// CDP message loop
		for (;;) {
			if (r_cons_is_breaked (core->cons)) {
				break;
			}
			int op = 0;
			ut64 len = 0;
			char *m = ws_recv (s, &op, &len);
			if (!m) {
				break;
			}
			if (op == 0x8) { // close
				free (m);
				break;
			}
			if (op == 0x9) { // ping -> pong
				ws_send_frame (s, 0x8a, m, len);
				free (m);
				continue;
			}
			if (op == 0x1 || op == 0x0) {
				cdp_dispatch (core, s, m);
			}
			free (m);
		}
		eprintf ("[webdev] DevTools disconnected\n");
		return;
	}

	// plain HTTP discovery
	if (!strcmp (path, "/json/version")) {
		char *body = r_str_newf (
			"{\"Browser\":\"radare2/%s\",\"Protocol-Version\":\"1.3\","
			"\"V8-Version\":\"quickjs\",\"WebKit-Version\":\"r2\","
			"\"webSocketDebuggerUrl\":\"ws://%s/r2-%d\"}",
			R2_VERSION, host, r_sys_getpid ());
		http_respond (s, 200, "OK", "application/json", body);
		free (body);
	} else if (!strcmp (path, "/json") || !strcmp (path, "/json/")
			|| !strcmp (path, "/json/list")) {
		char *t = discovery_target (core, host);
		char *body = r_str_newf ("[%s]", t);
		http_respond (s, 200, "OK", "application/json", body);
		free (body);
		free (t);
	} else if (!strcmp (path, "/json/protocol")) {
		http_respond (s, 200, "OK", "application/json", "{}");
	} else if (!strcmp (path, "/") || !strcmp (path, "/index.html")) {
		serve_landing (core, s, host);
	} else {
		http_respond (s, 404, "Not Found", "text/plain", "not found\n");
	}
}

// ---------------------------------------------------------------------------
// server loop (blocking, ^C to stop)
// ---------------------------------------------------------------------------

static void webdev_serve(RCore *core, const char *portstr) {
	RSocket *s = r_socket_new (false);
	if (!s) {
		R_LOG_ERROR ("webdev: cannot create socket");
		return;
	}
	if (!r_socket_listen (s, portstr, NULL)) {
		R_LOG_ERROR ("webdev: cannot listen on port %s", portstr);
		r_socket_free (s);
		return;
	}
	eprintf ("[webdev] serving r2 session on http://127.0.0.1:%s\n", portstr);
	eprintf ("[webdev] open chrome://inspect, add 127.0.0.1:%s as a target\n", portstr);
	eprintf ("[webdev] press ^C to stop\n");
	r_cons_break_push (core->cons, NULL, NULL);
	while (!r_cons_is_breaked (core->cons)) {
		RSocket *client = r_socket_accept_timeout (s, 1);
		if (!client) {
			continue;
		}
		handle_client (core, client, portstr);
		r_socket_free (client);
	}
	r_cons_break_pop (core->cons);
	eprintf ("[webdev] stopped\n");
	r_socket_free (s);
}

// ---------------------------------------------------------------------------
// command handler + plugin registration
// ---------------------------------------------------------------------------

static void webdev_help(RCore *core) {
	r_cons_printf (core->cons,
		"Usage: webdev [port]   expose this r2 session to Chrome DevTools\n"
		"| webdev            start the CDP server on port %s (blocking)\n"
		"| webdev [port]     start on a custom port\n"
		"| webdev?           this help\n"
		"\n"
		"Then open chrome://inspect, click Configure and add 127.0.0.1:PORT,\n"
		"and use the DevTools Console to run r2js one-liners (r2.cmd(...)).\n",
		WD_DEFAULT_PORT);
}

static bool webdev_call(RCorePluginSession *cps, const char *input) {
	if (!r_str_startswith (input, "webdev")) {
		return false;
	}
	RCore *core = cps->core;
	const char *arg = r_str_trim_head_ro (input + strlen ("webdev"));
	if (*arg == '?') {
		webdev_help (core);
		return true;
	}
	const char *port = (*arg) ? arg : WD_DEFAULT_PORT;
	webdev_serve (core, port);
	return true;
}

RCorePlugin r_core_plugin_webdev = {
	.meta = {
		.name = "webdev",
		.desc = "expose the r2 session to Chrome DevTools (webdev [port])",
		.author = "pancake",
		.license = "LGPL-3.0-only",
	},
	.call = webdev_call,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_CORE,
	.data = &r_core_plugin_webdev,
	.version = R2_VERSION
};
#endif
