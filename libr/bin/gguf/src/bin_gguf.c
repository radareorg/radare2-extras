/* radare - LGPL - Copyright 2023 - pancake */

#include <r_bin.h>
enum {
    GGUF_TYPE_UINT8 = 0,
    GGUF_TYPE_INT8,
    GGUF_TYPE_UINT16,
    GGUF_TYPE_INT16,
    GGUF_TYPE_UINT32,
    GGUF_TYPE_INT32,
    GGUF_TYPE_FLOAT32,
    GGUF_TYPE_BOOL,
    GGUF_TYPE_STRING = 8,
    GGUF_TYPE_UINT64,
    GGUF_TYPE_INT64,
    GGUF_TYPE_FLOAT64,
    GGUF_TYPE_ARRAY
};

static bool load(RBinFile *hello, RBuffer *buf, ut64 loadaddr) {
	return true;
}

static void destroy(RBinFile *hello) {
	RBuffer *buf = R_UNWRAP3 (hello, bo, bin_obj);
	r_buf_free (buf);
}

static RList *strings(RBinFile *hello) {
	// no strings here
	return NULL;
}

static RBinInfo *info(RBinFile *bf) {
	RBinInfo *ret = R_NEW0 (RBinInfo);
	if (R_LIKELY (ret)) {
		ret->lang = NULL;
		ret->file = bf->file? strdup (bf->file): NULL;
		ret->type = strdup ("gguf");
		ret->bclass = strdup ("1.0"); // version
		ret->rclass = strdup ("program");
		ret->os = strdup ("any");
		ret->subsystem = strdup ("unknown");
		ret->machine = strdup ("llama2");
		ret->arch = strdup ("llama");
		ret->has_va = 1;
		ret->bits = 32; // 16?
		ret->big_endian = 0;
		ret->dbg_info = 0;
	}
	return ret;
}

static bool check(RBinFile *hello, RBuffer *buf) {
	r_return_val_if_fail (buf, false);

	ut8 tmp[64] = {0};
	int read_length = r_buf_read_at (buf, 0, tmp, sizeof (tmp));
	if (read_length < 64) {
		return false;
	}
	if (!memcmp (tmp, "GGUF", 4)) {
#define GGML_MAX_DIMS 4
		R_LOG_INFO ("Yeah its a GGUF file");
		ut32 version = r_read_le32 (tmp + 4);
		R_LOG_INFO ("Version %d", version);
		ut32 ntensors = r_read_le32 (tmp + 8);
		R_LOG_INFO ("Tensors %d", ntensors);
		ut32 nkv = r_read_le32 (tmp + 16);
		R_LOG_INFO ("KeyValues %d", nkv);
		ut64 pos = 16 + 8;
		ut8 data[512];
		int i, j;
		R_LOG_INFO ("f section.kv = 0x%08"PFMT64x, pos);
		for (i = 0 ; i < nkv; i++) {
			r_buf_read_at (buf, pos, data, sizeof (data));
			R_LOG_INFO ("KeyAddr: 0x%08"PFMT64x, pos);
			pos += 8;
			ut64 textlen = r_read_le64 (data);
			if (textlen > 200) {
				R_LOG_ERROR ("Invalid tensor name %"PFMT64d, textlen);
				break;
			}
			R_LOG_DEBUG ("KeyNameLen: %d", textlen);
			char *text = r_str_ndup (data + 8, textlen);
			R_LOG_INFO ("KeyName: %s", text);
			free (text);
			pos += textlen;
			pos += 4;
			ut32 type = r_read_le32 (data + 8  + textlen);
			switch (type) {
			case GGUF_TYPE_STRING: // 8
				{
					R_LOG_DEBUG ("KeyType: string (%d)", type);
					ut64 vlen = r_read_le64 (data + 8 + textlen + 4);
					R_LOG_DEBUG ("KeyValueSize: %d", vlen);
					vlen = R_MIN (vlen, sizeof (data) - 16 + textlen + 4);
					char *text = r_str_ndup (data + 8 + textlen + 4 + 8, vlen);
					R_LOG_INFO ("KeyValue: %s", text);
					free (text);
					pos += vlen + 8;
				}
				break;
			case GGUF_TYPE_UINT32:
				{
					R_LOG_DEBUG ("KeyType: uint32 (%d)", type);
					ut64 val = r_read_le32 (data + 8 + textlen + 4);
					R_LOG_INFO ("KeyValue: 0x%08x", val);
					pos += 4;
				}
				break;
			case GGUF_TYPE_FLOAT32:
				{
					R_LOG_DEBUG ("KeyType: float32 (%d)", type);
					ut32 val = r_read_le32 (data + 8 + textlen + 4);
					R_LOG_INFO ("KeyValue: 0x%08x", val);
					pos += 4;
				}
				break;
			case GGUF_TYPE_UINT64:
				{
					R_LOG_DEBUG ("KeyType: uint64 (%d)", type);
					ut64 val = r_read_le64 (data + 8 + textlen + 4);
					R_LOG_INFO ("KeyValue: 0x%08"PFMT64x, val);
					pos += 4;
				}
				break;
			default:
				R_LOG_ERROR ("KeyType: %d (unsupported)", type);
				break;
			}
		}
		R_LOG_INFO ("f section.tensors = 0x%08"PFMT64x, pos);
		ntensors *= 4000;
		for (i = 0 ; i < ntensors; i++) {
			r_buf_read_at (buf, pos, data, sizeof (data));
			pos += 8;
			ut64 textlen = r_read_le64 (data);
			if (textlen > 200) {
				R_LOG_ERROR ("Invalid tensor name");
				break;
			}
			char *text = r_str_ndup (data + 8, textlen);
			R_LOG_INFO ("Tensor[%d]: %s", i, text);
			free (text);
			pos += textlen;
		}
		R_LOG_INFO ("f section.float = 0x%08"PFMT64x, pos);
		return true;
	}
	return false;
}

static RList *entries(RBinFile *hello) {
	r_return_val_if_fail (hello, NULL);
	RList *ret = r_list_newf (free);
	if (ret) {
		RBinAddr *ptr = R_NEW0 (RBinAddr);
		if (ptr) {
			ptr->paddr = ptr->vaddr = 0;
			r_list_append (ret, ptr);
		}
	}
	return ret;
}

RBinPlugin r_bin_plugin_hello = {
	.meta = {
		.name = "hello",
		.desc = "hello world for rbin",
		.license = "LGPL3",
	},
	.load = &load,
	.destroy = &destroy,
	.check = &check,
	.entries = entries,
	.strings = &strings,
	.info = &info,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_hello,
	.version = R2_VERSION
};
#endif
