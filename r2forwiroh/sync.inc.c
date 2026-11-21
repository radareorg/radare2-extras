/* Addresses are hex strings: GUI JSON parsers must not round 64-bit addresses. */
#define FW_MAX_ITEMS 10000

static char *fw_error(const char *message) {
	PJ *pj = pj_new ();
	pj_o (pj);
	pj_ks (pj, "error", message);
	pj_end (pj);
	return pj_drain (pj);
}

static char *fw_digest(RCore *core) {
	int fd = r_io_fd_get_current (core->io);
	ut64 size = r_io_fd_size (core->io, fd);
	if (fd < 0 || size == UT64_MAX) {
		return NULL;
	}
	RMutaSession *ms = r_muta_use (core->muta, "sha256");
	if (!ms) {
		return NULL;
	}
	ut8 buffer[65536];
	ut64 at;
	bool ok = true;
	for (at = 0; at < size; at += sizeof (buffer)) {
		int n = R_MIN (size - at, sizeof (buffer));
		if (r_io_fd_read_at (core->io, fd, at, buffer, n) != n
				|| !r_muta_session_update (ms, buffer, n)) {
			ok = false;
			break;
		}
	}
	ok = ok && r_muta_session_end (ms, NULL, 0);
	int length = 0;
	ut8 *digest = ok? r_muta_session_get_output (ms, &length): NULL;
	char *hex = digest && length == 32? r_hex_bin2strdup (digest, length): NULL;
	free (digest);
	r_muta_session_free (ms);
	return hex;
}

static ut64 fw_base(RCore *core) {
	ut64 base = r_bin_get_baddr (core->bin);
	return base == UT64_MAX? 0: base;
}

static char *fw_export(RCore *core) {
	char *digest = fw_digest (core);
	if (!digest) {
		return fw_error ("Cannot hash the current IO descriptor");
	}
	PJ *pj = pj_new ();
	pj_o (pj);
	pj_ko (pj, "data");
	pj_ki (pj, "version", 1);
	pj_ks (pj, "sha256", digest);
	free (digest);
	char base[32];
	snprintf (base, sizeof (base), "0x%" PFMT64x, fw_base (core));
	pj_ks (pj, "base", base);
	pj_ka (pj, "comments");
	RIntervalTreeIter it;
	RAnalMetaItem *item;
	size_t count = 0;
	const RSpace *space = r_spaces_current (&core->anal->meta_spaces);
	r_interval_tree_foreach (&core->anal->meta, it, item) {
		if (item->type != R_META_TYPE_COMMENT || item->space != space || !item->str) {
			continue;
		}
		if (++count > FW_MAX_ITEMS) {
			pj_free (pj);
			return fw_error ("Too many comments");
		}
		RIntervalNode *node = r_interval_tree_iter_get (&it);
		char address[32];
		snprintf (address, sizeof (address), "0x%" PFMT64x, node->start);
		pj_o (pj);
		pj_ks (pj, "address", address);
		pj_ks (pj, "text", item->str);
		pj_end (pj);
	}
	pj_end (pj);
	pj_ka (pj, "functions");
	RListIter *iter;
	RAnalFunction *fcn;
	count = 0;
	r_list_foreach (core->anal->fcns, iter, fcn) {
		if (++count > FW_MAX_ITEMS) {
			pj_free (pj);
			return fw_error ("Too many functions");
		}
		char address[32];
		snprintf (address, sizeof (address), "0x%" PFMT64x, fcn->addr);
		pj_o (pj);
		pj_ks (pj, "address", address);
		pj_ks (pj, "name", r_str_get (fcn->name));
		pj_end (pj);
	}
	pj_end (pj);
	pj_end (pj);
	pj_end (pj);
	return pj_drain (pj);
}

static bool fw_address(const RJson *object, const char *key, ut64 *address) {
	const char *s = r_json_get_str (object, key);
	if (!s || strncmp (s, "0x", 2) || !s[2] || strlen (s) > 18) {
		return false;
	}
	const char *p;
	for (p = s + 2; *p; p++) {
		if (!isxdigit ((ut8)*p)) {
			return false;
		}
	}
	*address = strtoull (s + 2, NULL, 16);
	return *address != UT64_MAX;
}

static bool fw_entries_valid(const RJson *array, const char *field) {
	if (!array || array->type != R_JSON_ARRAY || array->children.count > FW_MAX_ITEMS) {
		return false;
	}
	const RJson *entry;
	for (entry = array->children.first; entry; entry = entry->next) {
		ut64 address;
		const char *value = r_json_get_str (entry, field);
		if (entry->type != R_JSON_OBJECT || !fw_address (entry, "address", &address)
				|| !value || strlen (value) > 65536 || (!strcmp (field, "name") && !*value)) {
			return false;
		}
	}
	return true;
}

static char *fw_import(RCore *core, const RJson *metadata) {
	const RJson *comments = r_json_get (metadata, "comments");
	const RJson *functions = r_json_get (metadata, "functions");
	const RJson *version = r_json_get (metadata, "version");
	const char *expected = r_json_get_str (metadata, "sha256");
	ut64 base;
	if (!version || version->type != R_JSON_INTEGER || version->num.u_value != 1
			|| !fw_address (metadata, "base", &base) || !expected || strlen (expected) != 64
			|| !fw_entries_valid (comments, "text") || !fw_entries_valid (functions, "name")) {
		return fw_error ("Invalid metadata schema");
	}
	char *digest = fw_digest (core);
	bool matches = digest && !strcmp (digest, expected) && base == fw_base (core);
	free (digest);
	if (!matches) {
		return fw_error ("Binary hash or load address differs");
	}
	const RJson *entry;
	for (entry = functions->children.first; entry; entry = entry->next) {
		ut64 address;
		fw_address (entry, "address", &address);
		const char *name = r_json_get_str (entry, "name");
		RAnalFunction *fcn = r_anal_get_function_at (core->anal, address);
		if (fcn? !r_anal_function_rename (fcn, name):
				!r_anal_create_function (core->anal, name, address, R_ANAL_FCN_TYPE_FCN, NULL)) {
			return fw_error ("Cannot import function (earlier entries may have been applied)");
		}
	}
	for (entry = comments->children.first; entry; entry = entry->next) {
		ut64 address;
		fw_address (entry, "address", &address);
		if (!r_meta_set_string (core->anal, R_META_TYPE_COMMENT, address, r_json_get_str (entry, "text"))) {
			return fw_error ("Cannot import comment (earlier entries may have been applied)");
		}
	}
	PJ *pj = pj_new ();
	pj_o (pj);
	pj_ko (pj, "data");
	pj_kn (pj, "comments", comments->children.count);
	pj_kn (pj, "functions", functions->children.count);
	pj_end (pj);
	pj_end (pj);
	return pj_drain (pj);
}
