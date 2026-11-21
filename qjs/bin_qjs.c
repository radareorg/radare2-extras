/* radare - LGPL-3.0-only - Copyright 2026 - pancake */
#include <r_bin.h>
#undef STRINGIFY
// Function bytecode is private to QuickJS; compile this adapter with the chosen VM.
#include <quickjs.c>
#undef malloc
#undef free
#undef realloc

#define QJS_BASE 0x10000000

typedef struct {
	JSRuntime *rt;
	JSContext *ctx;
	JSValue root;
	RBuffer *code;
	RList *functions;
	int fd;
} QjsBin;

static bool collect(QjsBin *bin, JSValueConst value, int depth) {
	if (depth > 128) {
		return false;
	}
	if (JS_VALUE_GET_TAG (value) == JS_TAG_MODULE) {
		JSModuleDef *m = JS_VALUE_GET_PTR (value);
		return collect (bin, m->func_obj, depth + 1);
	}
	if (JS_VALUE_GET_TAG (value) != JS_TAG_FUNCTION_BYTECODE) {
		return true;
	}
	JSFunctionBytecode *b = JS_VALUE_GET_PTR (value);
	r_list_append (bin->functions, b);
	if (!r_buf_append_bytes (bin->code, b->byte_code_buf, b->byte_code_len)) {
		return false;
	}
	int i;
	for (i = 0; i < b->cpool_count; i++) {
		if (!collect (bin, b->cpool[i], depth + 1)) {
			return false;
		}
	}
	return true;
}

static void destroy(RBinFile *bf) {
	QjsBin *bin = bf->bo->bin_obj;
	if (!bin) {
		return;
	}
	if (bin->fd >= 0) {
		bf->rbin->iob.fd_close (bf->rbin->iob.io, bin->fd);
	}
	r_list_free (bin->functions);
	r_unref (bin->code);
	if (bin->ctx) {
		JS_FreeValue (bin->ctx, bin->root);
		JS_FreeContext (bin->ctx);
	}
	if (bin->rt) {
		JS_FreeRuntime (bin->rt);
	}
	free (bin);
	bf->bo->bin_obj = NULL;
}

static bool check(RBinFile *bf, RBuffer *buf) {
	return r_buf_size (buf) > 1 && r_buf_read8_at (buf, 0) == BC_VERSION;
}

static bool load(RBinFile *bf, RBuffer *buf, ut64 loadaddr) {
	ut64 size = r_buf_size (buf);
	if (!check (bf, buf) || size > 64 * 1024 * 1024) {
		return false;
	}
	QjsBin *bin = R_NEW0 (QjsBin);
	bin->fd = -1;
	bin->root = JS_UNDEFINED;
	bin->code = r_buf_new ();
	bin->functions = r_list_new ();
	bf->bo->bin_obj = bin;
	bin->rt = JS_NewRuntime ();
	if (!bin->rt) {
		goto fail;
	}
	JS_SetMemoryLimit (bin->rt, 128 * 1024 * 1024);
	bin->ctx = JS_NewContext (bin->rt);
	if (!bin->ctx) {
		goto fail;
	}
	ut8 *data = malloc (size);
	if (!data) {
		goto fail;
	}
	if (r_buf_read_at (buf, 0, data, size) != (st64)size) {
		free (data);
		goto fail;
	}
	bin->root = JS_ReadObject (bin->ctx, data, size, JS_READ_OBJ_BYTECODE);
	free (data);
	if (JS_IsException (bin->root) || !collect (bin, bin->root, 0) || !r_buf_size (bin->code)) {
		goto fail;
	}
	return true;
fail:
	destroy (bf);
	return false;
}

static RBinInfo *info(RBinFile *bf) {
	RBinInfo *i = R_NEW0 (RBinInfo);
	i->file = strdup (bf->file);
	i->type = strdup ("QuickJS serialized bytecode");
	i->bclass = r_str_newf ("QuickJS bytecode v%d", BC_VERSION);
	i->rclass = strdup ("qjs");
	i->arch = strdup ("qjs");
	i->machine = strdup ("QuickJS VM");
	i->os = strdup ("any");
	i->bits = 32;
	i->has_va = true;
	i->big_endian = R_SYS_ENDIAN == R_SYS_ENDIAN_BIG;
	return i;
}

static RList *entries(RBinFile *bf) {
	RList *list = r_list_newf (free);
	RBinAddr *addr = R_NEW0 (RBinAddr);
	addr->paddr = 0;
	addr->vaddr = QJS_BASE;
	r_list_append (list, addr);
	return list;
}

static bool sections(RBinFile *bf) {
	QjsBin *bin = bf->bo->bin_obj;
	RIOBind *io = &bf->rbin->iob;
	ut64 size = r_buf_size (bin->code);
	if (bin->fd < 0) {
		char *uri = r_str_newf ("malloc://%"PFMT64u, size);
		RIODesc *desc = r_io_open_nomap (io->io, uri, R_PERM_RWX, 0);
		bin->fd = desc? desc->fd: -1;
		free (uri);
		if (bin->fd < 0) {
			return false;
		}
		ut64 len;
		const ut8 *bytes = r_buf_data (bin->code, &len);
		if (!bytes || io->fd_write_at (io->io, bin->fd, 0, bytes, len) != (st64)len) {
			return false;
		}
	}
	RBinSection *s = RVecRBinSection_emplace_back (&bf->bo->sections_vec);
	s->name = strdup ("bytecode");
	s->paddr = 0;
	s->vaddr = QJS_BASE;
	s->size = s->vsize = size;
	s->perm = R_PERM_RX;
	s->add = true;
	s->backing_fd = bin->fd;
	return true;
}

static bool symbols(RBinFile *bf) {
	QjsBin *bin = bf->bo->bin_obj;
	RListIter *it;
	JSFunctionBytecode *b;
	ut64 addr = QJS_BASE;
	r_list_foreach (bin->functions, it, b) {
		const char *name = JS_AtomToCString (bin->ctx, b->func_name);
		RBinSymbol *s = RVecRBinSymbol_emplace_back (&bf->bo->symbols_vec);
		s->name = r_bin_name_new (name && *name? name: "anonymous");
		s->vaddr = addr;
		s->paddr = addr - QJS_BASE;
		s->attr.size = b->byte_code_len;
		s->type = R_BIN_TYPE_FUNC_STR;
		s->bind = R_BIN_BIND_LOCAL_STR;
		JS_FreeCString (bin->ctx, name);
		addr += b->byte_code_len;
	}
	return true;
}

static const char *get_cc(RBinFile *bf, ut64 addr) {
	return "dyncc::r0+1";
}

RBinPlugin r_bin_plugin_qjs = {
	.meta = { .name = "qjs", .author = "pancake", .desc = "QuickJS objects via the selected runtime", .license = "LGPL-3.0-only" },
	.check = check, .load = load, .destroy = destroy, .info = info,
	.entries = entries, .sections_vec = sections, .symbols_vec = symbols, .get_cc = get_cc,
};

R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_qjs,
	.version = R2_VERSION,
};
