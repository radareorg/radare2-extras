#include <r_core.h>
#include <ctype.h>
#include <assert.h>
#include "../sync.inc.c"

static RJson *exported(RCore *core) {
	char *text = fw_export (core);
	RJson *json = r_json_parsedup (text);
	free (text);
	assert (json && r_json_get (json, "data"));
	return json;
}

static void expect_error(RCore *core, const char *text) {
	RJson *json = r_json_parsedup (text);
	char *reply = fw_import (core, json);
	assert (strstr (reply, "error"));
	free (reply);
	r_json_free (json);
	assert (!r_meta_get_string (core->anal, R_META_TYPE_COMMENT, 123));
}

int main(void) {
	RCore *a = r_core_new ();
	RCore *b = r_core_new ();
	assert (a && b);
	assert (r_core_file_open (a, "malloc://256", R_PERM_RW, 0));
	assert (r_core_file_open (b, "malloc://256", R_PERM_RW, 0));
	const char *text = "quote \"; !touch /tmp/r2fw-injection; `?e nope`\nline two";
	assert (r_meta_set_string (a->anal, R_META_TYPE_COMMENT, 123, text));
	assert (r_anal_create_function (a->anal, "hello", 64, R_ANAL_FCN_TYPE_FCN, NULL));
	RJson *json = exported (a);
	char *reply = fw_import (b, r_json_get (json, "data"));
	assert (!strstr (reply, "error"));
	free (reply);
	assert (!strcmp (r_meta_get_string (b->anal, R_META_TYPE_COMMENT, 123), text));
	assert (!strcmp (r_anal_get_function_at (b->anal, 64)->name, "hello"));
	// Repeated merges are idempotent and preserve unrelated local annotations.
	assert (r_meta_set_string (b->anal, R_META_TYPE_COMMENT, 42, "local"));
	reply = fw_import (b, r_json_get (json, "data"));
	assert (!strstr (reply, "error"));
	free (reply);
	assert (!strcmp (r_meta_get_string (b->anal, R_META_TYPE_COMMENT, 42), "local"));
	ut8 byte = 1;
	assert (r_io_fd_write_at (b->io, r_io_fd_get_current (b->io), 0, &byte, 1) == 1);
	reply = fw_import (b, r_json_get (json, "data"));
	assert (strstr (reply, "Binary hash"));
	free (reply);
	r_json_free (json);
	r_meta_del (b->anal, R_META_TYPE_COMMENT, 123, 1);
	expect_error (b, "{}");
	expect_error (b, "{\"version\":2,\"base\":\"0x0\",\"sha256\":\"x\",\"comments\":[],\"functions\":[]}");
	expect_error (b, "{\"version\":1,\"base\":\"0x0x\",\"comments\":[],\"functions\":[]}");
	ut64 address;
	json = r_json_parsedup ("{\"address\":\"0x20000000000001\"}");
	assert (fw_address (json, "address", &address) && address == 0x20000000000001ULL);
	r_json_free (json);
	for (size_t i = 0; i < 4; i++) {
		const char *invalid[] = { "0x", "0xffffffffffffffff", "0x10000000000000000", "0x1;!touch" };
		PJ *pj = pj_new ();
		pj_o (pj);
		pj_ks (pj, "address", invalid[i]);
		pj_end (pj);
		json = r_json_parsedup (pj_string (pj));
		assert (!fw_address (json, "address", &address));
		r_json_free (json);
		pj_free (pj);
	}
	r_core_free (a);
	r_core_free (b);
	puts ("metadata sync tests passed");
	return 0;
}
