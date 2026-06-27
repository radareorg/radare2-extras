/* radare - LGPL - Copyright 2026 - memslicer */

// RBin plugin for Memory Slice (.msl) process memory dumps.
//
// Presents an .msl as a CORE-like object: architecture/bits/OS from the file
// header, the program counter of the Current thread as entry0, and one memory
// map per contiguous run of Captured pages (vaddr -> file offset of PageData).
// Failed/Unmapped pages are left unmapped so radare2 fills them with io.0xff,
// exactly like the ELF coredump loader.
//
// Open a slice with `r2 dump.msl` (default file IO). For a raw virtual-address
// view without bin metadata, the companion io plugin handles `msl://dump.msl`.
//
// MVP scope: uncompressed, unencrypted slices.

#include <r_bin.h>

#define MSL_FILE_MAGIC "MEMSLICE"
#define MSL_BLOCK_MAGIC "MSLC"
#define MSL_HDR_FLAG_ENCRYPTED 0x4
#define MSL_BLOCK_FLAG_COMPRESSED 0x1
#define MSL_BT_MEMORY_REGION 0x0001
#define MSL_BT_MODULE_ENTRY 0x0002
#define MSL_BT_THREAD_CONTEXT 0x0011
#define MSL_BT_END_OF_CAPTURE 0x0FFF
#define MSL_BLOCK_HEADER_SIZE 80
#define MSL_REG_FLAG_PC 0x1
#define MSL_THREAD_FLAG_CURRENT 0x1
#define MSL_MAX_PAGES (1ULL << 28)
#define MSL_MAX_EXPORTS 65536
#define MSL_MAX_NAME 256

typedef struct {
	ut64 base;
	ut64 size;
	char *path;
} MslModule;

typedef struct {
	RList *maps;       // RBinMap*
	RList *modules;    // MslModule*
	ut64 entry;        // PC of the Current thread
	bool has_entry;
	ut16 os_type;
	ut16 arch_type;
	int bits;
	int compressed_skipped; // compressed regions that can't be file-mapped
} RBinMslObj;

static void msl_module_free(void *p) {
	MslModule *m = p;
	if (m) {
		free (m->path);
		free (m);
	}
}

// Basename of a module path (handles both '\\' and '/').
static const char *msl_basename(const char *path) {
	if (!path) {
		return "module";
	}
	const char *b = path;
	const char *p;
	for (p = path; *p; p++) {
		if (*p == '/' || *p == '\\') {
			b = p + 1;
		}
	}
	return *b? b: path;
}

static inline ut64 msl_pad8(ut64 n) {
	return (n + 7) & ~(ut64)7;
}

static const char *msl_arch_str(ut16 arch, int *bits) {
	switch (arch) {
	case 0: *bits = 32; return "x86";   // x86
	case 1: *bits = 64; return "x86";   // x86_64
	case 2: *bits = 64; return "arm";   // ARM64
	case 3: *bits = 32; return "arm";   // ARM32
	case 4: *bits = 32; return "mips";  // MIPS32
	case 5: *bits = 64; return "mips";  // MIPS64
	case 6: *bits = 32; return "riscv"; // RV32
	case 7: *bits = 64; return "riscv"; // RV64
	case 8: *bits = 32; return "ppc";   // PPC32
	case 9: *bits = 64; return "ppc";   // PPC64
	default: *bits = 64; return "x86";
	}
}

static const char *msl_os_str(ut16 os) {
	switch (os) {
	case 0: return "windows";
	case 1: return "linux";
	case 2: return "macos";
	case 3: return "android";
	case 4: return "ios";
	default: return "unknown";
	}
}

static int msl_page_state(ut8 *psm, ut64 page) {
	ut8 byte = psm[page >> 2];
	int bitpos = 6 - (int)((page & 3) * 2);
	return (byte >> bitpos) & 3;
}

// Append one RBinMap per contiguous run of Captured pages in a region.
static void msl_region_maps(RBinMslObj *o, RBuffer *b, ut64 payload_off, ut16 bflags) {
	ut8 p[32];
	if (r_buf_read_at (b, payload_off, p, sizeof (p)) != sizeof (p)) {
		return;
	}
	if (bflags & MSL_BLOCK_FLAG_COMPRESSED) {
		// Compressed PageData cannot be expressed as a vaddr->file-offset
		// map. Open the slice with the `msl://` URI instead (the io plugin
		// decompresses lz4 in memory).
		o->compressed_skipped++;
		return;
	}
	ut64 base = r_read_le64 (p);
	ut64 size = r_read_le64 (p + 8);
	ut8 prot = p[16];
	ut8 psl = p[18];
	if (psl < 10 || psl > 40 || size == 0) {
		return;
	}
	ut64 page_size = 1ULL << psl;
	if (size & (page_size - 1)) {
		return;
	}
	ut64 npages = size >> psl;
	if (npages > MSL_MAX_PAGES) {
		return;
	}
	ut64 psm_bytes = msl_pad8 ((npages + 3) / 4);
	ut8 *psm = malloc (psm_bytes? (size_t)psm_bytes: 1);
	if (!psm) {
		return;
	}
	if (psm_bytes && r_buf_read_at (b, payload_off + 32, psm, psm_bytes) != (st64)psm_bytes) {
		free (psm);
		return;
	}
	ut64 data_off = payload_off + 32 + psm_bytes;
	int perm = ((prot & 1)? R_PERM_R: 0) | ((prot & 2)? R_PERM_W: 0) | ((prot & 4)? R_PERM_X: 0);

	ut64 cap_count = 0;    // captured pages seen so far (file offset cursor)
	ut64 run_start = 0;    // page index where current run began
	ut64 run_foff = 0;     // file offset of current run start
	bool in_run = false;
	ut64 i;
	for (i = 0; i < npages; i++) {
		bool captured = msl_page_state (psm, i) == 0;
		if (captured && !in_run) {
			in_run = true;
			run_start = i;
			run_foff = data_off + cap_count * page_size;
		} else if (!captured && in_run) {
			RBinMap *m = R_NEW0 (RBinMap);
			if (m) {
				m->addr = base + run_start * page_size;
				m->offset = run_foff;
				m->size = (int)((i - run_start) * page_size);
				m->perms = perm;
				m->file = strdup ("msl");
				r_list_append (o->maps, m);
			}
			in_run = false;
		}
		if (captured) {
			cap_count++;
		}
	}
	if (in_run) {
		RBinMap *m = R_NEW0 (RBinMap);
		if (m) {
			m->addr = base + run_start * page_size;
			m->offset = run_foff;
			m->size = (int)((npages - run_start) * page_size);
			m->perms = perm;
			m->file = strdup ("msl");
			r_list_append (o->maps, m);
		}
	}
	free (psm);
}

// Extract the program counter from a Thread Context block payload.
static bool msl_thread_pc(RBuffer *b, ut64 payload_off, ut64 payload_len, ut64 *pc, bool *is_current) {
	ut8 hdr[32];
	if (payload_len < sizeof (hdr) || r_buf_read_at (b, payload_off, hdr, sizeof (hdr)) != sizeof (hdr)) {
		return false;
	}
	ut16 tflags = r_read_le16 (hdr + 16);
	ut32 regcount = r_read_le32 (hdr + 20);
	ut16 namelen = r_read_le16 (hdr + 24);
	ut64 off = payload_off + 32 + msl_pad8 (namelen);
	ut64 end = payload_off + payload_len;
	ut32 r;
	for (r = 0; r < regcount; r++) {
		ut8 e[8];
		if (off + 8 > end || r_buf_read_at (b, off, e, sizeof (e)) != sizeof (e)) {
			return false;
		}
		ut8 rnamelen = e[0];
		ut8 width = e[1];
		ut16 rflags = r_read_le16 (e + 2);
		ut64 name_pad = msl_pad8 (rnamelen);
		ut64 val_off = off + 8 + name_pad;
		if (rflags & MSL_REG_FLAG_PC) {
			ut8 v[8] = {0};
			int n = (width > 8)? 8: width;
			if (r_buf_read_at (b, val_off, v, n) != n) {
				return false;
			}
			*pc = r_read_le64 (v);
			*is_current = (tflags & MSL_THREAD_FLAG_CURRENT) != 0;
			return true;
		}
		off = val_off + msl_pad8 (width);
	}
	return false;
}

// Translate a virtual address to a file offset using the captured-run maps and
// read *len* bytes. Reads must fall inside a single captured run.
static bool msl_va_read(RBinMslObj *o, RBuffer *b, ut64 va, ut8 *out, int len) {
	RListIter *it;
	RBinMap *m;
	r_list_foreach (o->maps, it, m) {
		ut64 msize = (ut64)(ut32) m->size;
		if (va >= m->addr && va + (ut64) len <= m->addr + msize) {
			ut64 foff = m->offset + (va - m->addr);
			return r_buf_read_at (b, foff, out, len) == len;
		}
	}
	return false;
}

static ut32 msl_va_u32(RBinMslObj *o, RBuffer *b, ut64 va, bool *ok) {
	ut8 v[4];
	if (msl_va_read (o, b, va, v, 4)) {
		*ok = true;
		return r_read_le32 (v);
	}
	*ok = false;
	return 0;
}

// Read a NUL-terminated ASCII string at *va* into *out* (capped). Returns its
// length, or 0 if unreadable.
static int msl_va_cstr(RBinMslObj *o, RBuffer *b, ut64 va, char *out, int cap) {
	int i;
	for (i = 0; i < cap - 1; i++) {
		ut8 c;
		if (!msl_va_read (o, b, va + i, &c, 1) || c == 0) {
			break;
		}
		out[i] = (c >= 0x20 && c < 0x7f)? (char) c: '_';
	}
	out[i] = 0;
	return i;
}

// Parse the PE export directory of a module mapped at mod->base and emplace one
// FUNC symbol per named export. No-op (returns 0) for non-PE images.
static int msl_pe_exports(RBinMslObj *o, RBuffer *b, MslModule *mod, RVecRBinSymbol *vec) {
	ut64 base = mod->base;
	ut8 mz[2];
	if (!msl_va_read (o, b, base, mz, 2) || mz[0] != 'M' || mz[1] != 'Z') {
		return 0;
	}
	bool ok;
	ut32 lfanew = msl_va_u32 (o, b, base + 0x3c, &ok);
	if (!ok || lfanew > 0x10000) {
		return 0;
	}
	ut8 sig[4];
	if (!msl_va_read (o, b, base + lfanew, sig, 4) || memcmp (sig, "PE\0\0", 4)) {
		return 0;
	}
	ut64 opt = base + lfanew + 24;       // optional header
	ut8 magic[2];
	if (!msl_va_read (o, b, opt, magic, 2)) {
		return 0;
	}
	ut16 omagic = r_read_le16 (magic);
	// DataDirectory[0] (export table) lives at a magic-dependent offset.
	ut64 dd0 = opt + ((omagic == 0x20b)? 112: 96);  // PE32+ : PE32
	ut32 exp_rva = msl_va_u32 (o, b, dd0, &ok);
	if (!ok || exp_rva == 0) {
		return 0;
	}
	ut64 ed = base + exp_rva;            // IMAGE_EXPORT_DIRECTORY
	ut32 n_names = msl_va_u32 (o, b, ed + 0x18, &ok);
	if (!ok || n_names == 0 || n_names > MSL_MAX_EXPORTS) {
		return 0;
	}
	ut32 funcs_rva = msl_va_u32 (o, b, ed + 0x1c, &ok); if (!ok) return 0;
	ut32 names_rva = msl_va_u32 (o, b, ed + 0x20, &ok); if (!ok) return 0;
	ut32 ords_rva  = msl_va_u32 (o, b, ed + 0x24, &ok); if (!ok) return 0;
	const char *lib = msl_basename (mod->path);
	int emitted = 0;
	ut32 i;
	for (i = 0; i < n_names; i++) {
		ut32 name_rva = msl_va_u32 (o, b, base + names_rva + i * 4, &ok);
		if (!ok || name_rva == 0) {
			continue;
		}
		char name[MSL_MAX_NAME];
		if (msl_va_cstr (o, b, base + name_rva, name, sizeof (name)) <= 0) {
			continue;
		}
		ut8 ob[2];
		if (!msl_va_read (o, b, base + ords_rva + i * 2, ob, 2)) {
			continue;
		}
		ut16 ord = r_read_le16 (ob);
		ut32 func_rva = msl_va_u32 (o, b, base + funcs_rva + (ut64) ord * 4, &ok);
		if (!ok || func_rva == 0) {
			continue;
		}
		RBinSymbol *sym = RVecRBinSymbol_emplace_back (vec);
		if (!sym) {
			break;
		}
		memset (sym, 0, sizeof (*sym));
		sym->name = r_bin_name_new (name);
		sym->libname = strdup (lib);
		sym->vaddr = base + func_rva;
		sym->paddr = base + func_rva;
		sym->type = R_BIN_TYPE_FUNC_STR;
		sym->bind = R_BIN_BIND_GLOBAL_STR;
		sym->ordinal = ord;
		sym->bits = o->bits;
		emitted++;
	}
	return emitted;
}

static bool msl_parse(RBinMslObj *o, RBuffer *b) {
	ut8 h[16];
	if (r_buf_read_at (b, 0, h, sizeof (h)) != sizeof (h)) {
		return false;
	}
	if (memcmp (h, MSL_FILE_MAGIC, 8)) {
		return false;
	}
	ut32 flags = r_read_le32 (h + 12);
	if (flags & MSL_HDR_FLAG_ENCRYPTED) {
		R_LOG_ERROR ("msl: encrypted slices are not supported yet");
		return false;
	}
	ut8 header_size = h[9];
	ut8 osarch[4];
	if (r_buf_read_at (b, 0x30, osarch, sizeof (osarch)) == sizeof (osarch)) {
		o->os_type = r_read_le16 (osarch);
		o->arch_type = r_read_le16 (osarch + 2);
	}
	o->maps = r_list_newf (free);
	o->modules = r_list_newf (msl_module_free);
	bool have_current_pc = false;
	ut64 fsize = r_buf_size (b);
	ut64 off = header_size;
	while (off + MSL_BLOCK_HEADER_SIZE <= fsize) {
		ut8 bh[MSL_BLOCK_HEADER_SIZE];
		if (r_buf_read_at (b, off, bh, sizeof (bh)) != sizeof (bh)) {
			break;
		}
		if (memcmp (bh, MSL_BLOCK_MAGIC, 4)) {
			break;
		}
		ut16 btype = r_read_le16 (bh + 4);
		ut16 bflags = r_read_le16 (bh + 6);
		ut32 blen = r_read_le32 (bh + 8);
		if (blen < MSL_BLOCK_HEADER_SIZE) {
			break;
		}
		ut64 payload_off = off + MSL_BLOCK_HEADER_SIZE;
		ut64 payload_len = blen - MSL_BLOCK_HEADER_SIZE;
		if (btype == MSL_BT_MEMORY_REGION) {
			msl_region_maps (o, b, payload_off, bflags);
		} else if (btype == MSL_BT_MODULE_ENTRY) {
			// ModuleEntry: BaseAddr(8) ModuleSize(8) PathLen(2) VerLen(2) rsv(4)
			// followed by the path. Used to resolve exports and label modules.
			ut8 mh[24];
			if (payload_len >= sizeof (mh)
					&& r_buf_read_at (b, payload_off, mh, sizeof (mh)) == sizeof (mh)) {
				ut16 pathlen = r_read_le16 (mh + 16);
				MslModule *mod = R_NEW0 (MslModule);
				if (mod) {
					mod->base = r_read_le64 (mh);
					mod->size = r_read_le64 (mh + 8);
					if (pathlen > 0 && pathlen < 0x1000
							&& 24 + (ut64) pathlen <= payload_len) {
						mod->path = calloc (1, (size_t) pathlen + 1);
						if (mod->path) {
							r_buf_read_at (b, payload_off + 24, (ut8 *) mod->path, pathlen);
						}
					}
					r_list_append (o->modules, mod);
				}
			}
		} else if (btype == MSL_BT_THREAD_CONTEXT && !have_current_pc) {
			ut64 pc = 0;
			bool is_current = false;
			if (msl_thread_pc (b, payload_off, payload_len, &pc, &is_current)) {
				// Prefer the Current thread; otherwise keep the first PC seen.
				if (is_current || !o->has_entry) {
					o->entry = pc;
					o->has_entry = true;
				}
				if (is_current) {
					have_current_pc = true;
				}
			}
		} else if (btype == MSL_BT_END_OF_CAPTURE) {
			break;
		}
		off += blen;
	}
	return true;
}

static bool check(RBinFile *bf, RBuffer *b) {
	ut8 magic[8];
	if (r_buf_read_at (b, 0, magic, sizeof (magic)) != sizeof (magic)) {
		return false;
	}
	return !memcmp (magic, MSL_FILE_MAGIC, 8);
}

static bool load(RBinFile *bf, RBuffer *buf, ut64 loadaddr) {
	RBinMslObj *o = R_NEW0 (RBinMslObj);
	if (!o) {
		return false;
	}
	if (!msl_parse (o, buf)) {
		r_list_free (o->maps);
		free (o);
		return false;
	}
	if (o->compressed_skipped > 0) {
		R_LOG_WARN ("msl: %d compressed region(s) are not mapped by the bin "
			"plugin; open the slice as 'msl://%s' to read them (the io "
			"plugin decompresses lz4).", o->compressed_skipped, bf->file);
	}
	int bits = 64;
	msl_arch_str (o->arch_type, &bits);   // so symbols carry the right width
	o->bits = bits;
	bf->bo->bin_obj = o;
	return true;
}

static void destroy(RBinFile *bf) {
	if (bf && bf->bo && bf->bo->bin_obj) {
		RBinMslObj *o = bf->bo->bin_obj;
		r_list_free (o->maps);
		r_list_free (o->modules);
		free (o);
		bf->bo->bin_obj = NULL;
	}
}

// One symbol per loaded module (at its base) plus, for PE images, one FUNC
// symbol per exported function -- so radare2 names call targets like
// `kernel32.dll!CreateFileW` instead of bare addresses.
static bool symbols_vec(RBinFile *bf) {
	R_RETURN_VAL_IF_FAIL (bf && bf->bo && bf->bo->bin_obj, false);
	RBinMslObj *o = bf->bo->bin_obj;
	RVecRBinSymbol *vec = &bf->bo->symbols_vec;
	RBuffer *b = bf->buf;
	RListIter *it;
	MslModule *mod;
	r_list_foreach (o->modules, it, mod) {
		RBinSymbol *sym = RVecRBinSymbol_emplace_back (vec);
		if (sym) {
			memset (sym, 0, sizeof (*sym));
			sym->name = r_bin_name_new (msl_basename (mod->path));
			sym->vaddr = mod->base;
			sym->paddr = mod->base;
			sym->type = R_BIN_TYPE_OBJECT_STR;
			sym->bind = R_BIN_BIND_GLOBAL_STR;
			sym->size = mod->size;
			sym->bits = o->bits;
		}
		msl_pe_exports (o, b, mod, vec);
	}
	return true;
}

// Expose captured modules as libraries (so `il` lists them).
static RList *libs(RBinFile *bf) {
	R_RETURN_VAL_IF_FAIL (bf && bf->bo && bf->bo->bin_obj, NULL);
	RBinMslObj *o = bf->bo->bin_obj;
	RList *ret = r_list_newf (free);
	if (!ret) {
		return NULL;
	}
	RListIter *it;
	MslModule *mod;
	r_list_foreach (o->modules, it, mod) {
		if (mod->path) {
			r_list_append (ret, strdup (mod->path));
		}
	}
	return ret;
}

static RList *maps(RBinFile *bf) {
	R_RETURN_VAL_IF_FAIL (bf && bf->bo && bf->bo->bin_obj, NULL);
	RBinMslObj *o = bf->bo->bin_obj;
	RList *ret = r_list_newf (free);
	if (!ret) {
		return NULL;
	}
	RListIter *it;
	RBinMap *m;
	r_list_foreach (o->maps, it, m) {
		RBinMap *c = R_NEW0 (RBinMap);
		if (c) {
			*c = *m;
			c->file = m->file? strdup (m->file): NULL;
			r_list_append (ret, c);
		}
	}
	return ret;
}

// Sections with add=true are what radare2 turns into IO maps (the RBinMap
// list is only used to rename them for CORE files). One section per captured
// run; failed/unmapped pages stay unmapped and read back as io.0xff.
static bool sections_vec(RBinFile *bf) {
	R_RETURN_VAL_IF_FAIL (bf && bf->bo && bf->bo->bin_obj, false);
	RBinMslObj *o = bf->bo->bin_obj;
	RVecRBinSection_clear (&bf->bo->sections_vec);
	RListIter *it;
	RBinMap *m;
	int i = 0;
	r_list_foreach (o->maps, it, m) {
		RBinSection *s = RVecRBinSection_emplace_back (&bf->bo->sections_vec);
		if (!s) {
			continue;
		}
		memset (s, 0, sizeof (*s));
		s->name = r_str_newf ("region.%d", i++);
		s->paddr = m->offset;
		s->vaddr = m->addr;
		s->size = (ut64)(ut32)m->size;
		s->vsize = s->size;
		s->perm = m->perms;
		s->add = true;
	}
	return true;
}

static RList *entries(RBinFile *bf) {
	R_RETURN_VAL_IF_FAIL (bf && bf->bo && bf->bo->bin_obj, NULL);
	RBinMslObj *o = bf->bo->bin_obj;
	RList *ret = r_list_newf (free);
	if (!ret || !o->has_entry) {
		return ret;
	}
	RBinAddr *a = R_NEW0 (RBinAddr);
	if (a) {
		a->vaddr = o->entry;
		a->paddr = o->entry;
		a->bits = o->bits;
		r_list_append (ret, a);
	}
	return ret;
}

static RBinInfo *info(RBinFile *bf) {
	R_RETURN_VAL_IF_FAIL (bf && bf->bo && bf->bo->bin_obj, NULL);
	RBinMslObj *o = bf->bo->bin_obj;
	RBinInfo *ret = R_NEW0 (RBinInfo);
	if (!ret) {
		return NULL;
	}
	int bits = 64;
	const char *arch = msl_arch_str (o->arch_type, &bits);
	o->bits = bits;
	ret->file = strdup (bf->file);
	ret->type = strdup ("CORE");
	ret->rclass = strdup ("msl");
	ret->bclass = strdup ("Memory Slice");
	ret->arch = strdup (arch);
	ret->machine = strdup ("Memory Slice dump");
	ret->os = strdup (msl_os_str (o->os_type));
	ret->bits = bits;
	ret->big_endian = false;
	ret->has_va = true;
	return ret;
}

static ut64 baddr(RBinFile *bf) {
	return 0;
}

RBinPlugin r_bin_plugin_msl = {
	.meta = {
		.name = "msl",
		.desc = "Memory Slice (.msl) process memory dump",
		.author = "memslicer",
		.license = "LGPL-3.0-only",
	},
	.load = &load,
	.destroy = &destroy,
	.check = &check,
	.baddr = &baddr,
	.entries = &entries,
	.maps = &maps,
	.sections_vec = &sections_vec,
	.symbols_vec = &symbols_vec,
	.libs = &libs,
	.info = &info,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_msl,
	.version = R2_VERSION
};
#endif
