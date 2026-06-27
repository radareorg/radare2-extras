/* radare - LGPL - Copyright 2026 - memslicer */

// Core plugin for Memory Slice (.msl) production.
//
// Adds the "dgm"/"dgma" commands that write the producer side of the format
// consumed by the io/bin/debug "msl" plugins and by memslicer
// (https://github.com/MemorySlice/memslicer): a file header, Process Identity,
// a Thread Context with the current registers, and one Memory Region per debug
// map (three-state page map + captured bytes). The integrity chain uses
// SHA-256 (HashAlgo 0x01) since radare2 has no BLAKE3.
//
// This lives in radare2-extras as a loadable core plugin instead of in the r2
// core. Load it (after `make install`) and the commands appear under "dg".

#include <r_core.h>
#include <r_cmd.h>
#include <r_lib.h>
#include <fcntl.h>

#define MSLW_HASH R_HASH_SHA256

typedef struct {
	RBuffer *out;
	RHash *fh;        // cumulative file hash (incremental, for End-of-Capture)
	ut8 prev[32];     // hash of the previous element (the chain)
} MslDump;

static void mslw_uuid(ut8 *u) {
	int i;
	for (i = 0; i < 16; i++) {
		u[i] = (ut8)r_num_rand (256);
	}
	u[6] = (u[6] & 0x0f) | 0x40;  // version 4
	u[8] = (u[8] & 0x3f) | 0x80;  // variant
}

static void mslw_sha256(const ut8 *a, ut64 alen, const ut8 *b, ut64 blen, ut8 *out32) {
	RHash *h = r_hash_new (true, MSLW_HASH);
	r_hash_do_begin (h, MSLW_HASH);
	if (alen) {
		r_hash_do_sha256 (h, a, alen);
	}
	if (blen) {
		r_hash_do_sha256 (h, b, blen);
	}
	r_hash_do_end (h, MSLW_HASH);
	memcpy (out32, h->digest, 32);
	r_hash_free (h);
}

static void mslw_append_pad8(RBuffer *b, const ut8 *data, ut64 len) {
	if (len) {
		r_buf_append_bytes (b, data, len);
	}
	ut64 pad = ((len + 7) & ~(ut64)7) - len;
	if (pad) {
		ut8 z[8] = {0};
		r_buf_append_bytes (b, z, pad);
	}
}

// Emit one block: 80-byte header + 8-byte-padded payload; advance the chain.
static void mslw_block(MslDump *d, ut16 type, const ut8 *payload, ut64 plen, bool feed_file) {
	ut64 padded = (plen + 7) & ~(ut64)7;
	ut8 *pl = calloc (1, padded? (size_t)padded: 8);
	if (plen && pl) {
		memcpy (pl, payload, plen);
	}
	ut8 hdr[80] = {0};
	memcpy (hdr, "MSLC", 4);
	r_write_le16 (hdr + 4, type);
	r_write_le32 (hdr + 8, (ut32)(80 + padded));
	r_write_le16 (hdr + 12, 1);  // payload version
	mslw_uuid (hdr + 16);
	memcpy (hdr + 48, d->prev, 32);
	r_buf_append_bytes (d->out, hdr, 80);
	if (padded) {
		r_buf_append_bytes (d->out, pl, padded);
	}
	if (feed_file) {
		r_hash_do_sha256 (d->fh, hdr, 80);
		if (padded) {
			r_hash_do_sha256 (d->fh, pl, padded);
		}
	}
	mslw_sha256 (hdr, 80, pl, padded, d->prev);
	free (pl);
}

static ut16 mslw_arch_code(const char *arch, int bits) {
	if (arch && !strcmp (arch, "x86")) {
		return bits == 64? 1: 0;
	}
	if (arch && !strcmp (arch, "arm")) {
		return bits == 64? 2: 3;
	}
	return 0xFFFF;
}

static ut16 mslw_os_code(const char *os) {
	if (os) {
		if (strstr (os, "linux")) { return 1; }
		if (strstr (os, "macos") || strstr (os, "darwin")) { return 2; }
		if (strstr (os, "windows")) { return 0; }
		if (strstr (os, "android")) { return 3; }
		if (strstr (os, "ios")) { return 4; }
	}
	return 0xFFFF;
}

static bool mslw_dump(RCore *core, const char *path, bool full) {
	if (!core->dbg || core->dbg->pid == -1) {
		R_LOG_ERROR ("Not debugging; cannot write a memory slice");
		return false;
	}
	r_debug_map_sync (core->dbg);
	r_debug_reg_sync (core->dbg, R_REG_TYPE_ALL, false);

	r_file_rm (path);
	RBuffer *out = r_buf_new_file (path, O_RDWR | O_CREAT, 0644);
	if (!out) {
		R_LOG_ERROR ("Cannot create %s", path);
		return false;
	}
	MslDump d = {0};
	d.out = out;
	d.fh = r_hash_new (true, MSLW_HASH);
	r_hash_do_begin (d.fh, MSLW_HASH);

	int bits = r_config_get_i (core->config, "asm.bits");
	ut16 arch_type = mslw_arch_code (r_config_get (core->config, "asm.arch"), bits);
	ut16 os_type = mslw_os_code (r_config_get (core->config, "asm.os"));
	ut64 now_ns = r_time_now () * 1000;

	// Build the Thread Context payload (current thread) first, to know whether
	// to advertise the ThreadContexts capability bit.
	RReg *reg = core->dbg->reg;
	const char *pcname = r_reg_alias_getname (reg, R_REG_ALIAS_PC);
	const char *spname = r_reg_alias_getname (reg, R_REG_ALIAS_SP);
	RBuffer *regs = r_buf_new ();
	ut32 regcount = 0;
	RList *items = r_reg_get_list (reg, R_REG_TYPE_GPR);
	RListIter *it;
	RRegItem *item;
	r_list_foreach (items, it, item) {
		if (!item->name || item->size != bits) {
			continue;  // emit canonical full-width registers only
		}
		int width = item->size / 8;
		if (width < 1 || width > 8) {
			continue;
		}
		ut64 val = r_reg_get_value (reg, item);
		int nlen = (int)strlen (item->name) + 1;
		ut8 e[8] = {0};
		e[0] = (ut8)nlen;
		e[1] = (ut8)width;
		ut16 rflags = 0;
		if (pcname && !strcmp (item->name, pcname)) {
			rflags |= 1;
		} else if (spname && !strcmp (item->name, spname)) {
			rflags |= 2;
		}
		r_write_le16 (e + 2, rflags);
		r_buf_append_bytes (regs, e, 8);
		mslw_append_pad8 (regs, (const ut8 *)item->name, nlen);
		ut8 vbuf[8] = {0};
		r_write_le64 (vbuf, val);
		mslw_append_pad8 (regs, vbuf, width);
		regcount++;
	}

	ut64 cap = (1ULL << 0) | (1ULL << 8);   // MemoryRegions | ProcessIdentity
	if (regcount > 0) {
		cap |= (1ULL << 2);                  // ThreadContexts
	}

	// File header (64 bytes)
	ut8 fhdr[64] = {0};
	memcpy (fhdr, "MEMSLICE", 8);
	fhdr[8] = 1;                  // endianness: little
	fhdr[9] = 64;                 // header size
	r_write_le16 (fhdr + 10, 0x0101);          // version 1.1
	r_write_le64 (fhdr + 16, cap);
	mslw_uuid (fhdr + 24);
	r_write_le64 (fhdr + 40, now_ns);
	r_write_le16 (fhdr + 48, os_type);
	r_write_le16 (fhdr + 50, arch_type);
	r_write_le32 (fhdr + 52, (ut32)core->dbg->pid);
	fhdr[61] = 0x01;              // HashAlgo: SHA-256
	r_buf_append_bytes (out, fhdr, 64);
	r_hash_do_sha256 (d.fh, fhdr, 64);
	mslw_sha256 (fhdr, 64, NULL, 0, d.prev);

	// Block 0: Process Identity (0x0040)
	{
		const char *exe = (core->io && core->io->desc)? core->io->desc->name: "";
		if (r_str_startswith (exe, "dbg://")) {
			exe += strlen ("dbg://");
		}
		int elen = (int)strlen (exe) + 1;
		RBuffer *pi = r_buf_new ();
		ut8 h[24] = {0};
		r_write_le16 (h + 16, (ut16)elen);       // ExePathLen
		r_buf_append_bytes (pi, h, 24);
		mslw_append_pad8 (pi, (const ut8 *)exe, elen);
		ut64 sz = 0;
		const ut8 *bytes = r_buf_data (pi, &sz);
		mslw_block (&d, 0x0040, bytes, sz, true);
		r_unref (pi);
	}

	// Thread Context (0x0011)
	if (regcount > 0) {
		RBuffer *tc = r_buf_new ();
		ut8 h[32] = {0};
		r_write_le64 (h, (ut64)core->dbg->tid);  // ThreadID
		r_write_le16 (h + 16, 1);                // Flags: Current
		h[18] = 3;                               // ThreadState: Stopped
		r_write_le32 (h + 20, regcount);
		r_buf_append_bytes (tc, h, 32);
		ut64 rsz = 0;
		const ut8 *rbytes = r_buf_data (regs, &rsz);
		if (rsz) {
			r_buf_append_bytes (tc, rbytes, rsz);
		}
		ut64 sz = 0;
		const ut8 *bytes = r_buf_data (tc, &sz);
		mslw_block (&d, 0x0011, bytes, sz, true);
		r_unref (tc);
	}
	r_unref (regs);

	// Memory Region blocks (0x0001), one per debug map.
	// Read in 1 MiB chunks (not page-by-page) for speed; skip unreadable maps
	// and, unless 'full', skip very large maps (e.g. the macOS dyld shared
	// cache is multi-GB and would dominate the dump). Use "dgma" for everything.
	const ut64 page = 4096;
	const ut64 CHUNK = 1024 * 1024;
	const ut64 CAP = 512ULL * 1024 * 1024;
	ut8 *cbuf = malloc (CHUNK);
	r_cons_break_push (core->cons, NULL, NULL);
	RDebugMap *map;
	r_list_foreach (core->dbg->maps, it, map) {
		if (r_cons_is_breaked (core->cons)) {
			break;
		}
		ut64 base = map->addr;
		ut64 size = map->addr_end - map->addr;
		if (size == 0 || (size % page) || !cbuf) {
			continue;
		}
		if (!(map->perm & R_PERM_R)) {
			continue;  // cannot read it anyway
		}
		if (!full && size > CAP) {
			R_LOG_WARN ("msl: skipping large map 0x%"PFMT64x" (%"PFMT64u" MB); use dgma for a full dump",
				base, size >> 20);
			continue;
		}
		ut64 npages = size / page;
		ut64 psm_bytes = (((npages + 3) / 4) + 7) & ~(ut64)7;
		ut8 *psm = calloc (1, psm_bytes? (size_t)psm_bytes: 1);
		RBuffer *pdata = r_buf_new ();
		if (!psm || !pdata) {
			free (psm);
			r_unref (pdata);
			continue;
		}
		ut64 done = 0, pidx = 0;
		while (done < size && !r_cons_is_breaked (core->cons)) {
			ut64 clen = R_MIN (CHUNK, size - done);
			ut64 cpages = clen / page;
			if (r_io_read_at (core->io, base + done, cbuf, (int)clen)) {
				r_buf_append_bytes (pdata, cbuf, clen);   // whole chunk CAPTURED
			} else {
				ut64 j;  // partial: fall back to page granularity for this chunk
				for (j = 0; j < cpages; j++) {
					ut64 pi = pidx + j;
					if (r_io_read_at (core->io, base + done + j * page, cbuf, (int)page)) {
						r_buf_append_bytes (pdata, cbuf, page);
					} else {
						psm[pi >> 2] |= 1 << (6 - (int)(pi & 3) * 2);  // FAILED
					}
				}
			}
			pidx += cpages;
			done += clen;
		}
		int prot = ((map->perm & R_PERM_R)? 1: 0)
			| ((map->perm & R_PERM_W)? 2: 0)
			| ((map->perm & R_PERM_X)? 4: 0);
		RBuffer *mr = r_buf_new ();
		ut8 h[32] = {0};
		r_write_le64 (h, base);
		r_write_le64 (h + 8, size);
		h[16] = (ut8)prot;
		h[18] = 12;                  // PageSizeLog2 (4096)
		r_write_le64 (h + 24, now_ns);
		r_buf_append_bytes (mr, h, 32);
		r_buf_append_bytes (mr, psm, psm_bytes);
		ut64 dsz = 0;
		const ut8 *dbytes = r_buf_data (pdata, &dsz);
		if (dsz) {
			r_buf_append_bytes (mr, dbytes, dsz);
		}
		ut64 sz = 0;
		const ut8 *bytes = r_buf_data (mr, &sz);
		mslw_block (&d, 0x0001, bytes, sz, true);
		r_unref (mr);
		r_unref (pdata);
		free (psm);
	}
	r_cons_break_pop (core->cons);
	free (cbuf);

	// End-of-Capture (0x0FFF): FileHash over everything before this block.
	r_hash_do_end (d.fh, MSLW_HASH);
	ut8 eoc[48] = {0};
	memcpy (eoc, d.fh->digest, 32);
	r_write_le64 (eoc + 32, r_time_now () * 1000);
	mslw_block (&d, 0x0FFF, eoc, sizeof (eoc), false);

	r_hash_free (d.fh);
	r_unref (out);
	R_LOG_INFO ("Wrote memory slice to %s", path);
	return true;
}

static const char *help_msg_dgm[] = {
	"Usage:", "dgm", "[a] ([file]) # Generate a Memory Slice (.msl)",
	"dgm", " [file]", "generate a Memory Slice of the debuggee (skips huge maps)",
	"dgma", " [file]", "generate a Memory Slice including all maps",
	NULL
};

static bool cmd_dgm(RCore *core, const char *input) {
	// input is the full command line, e.g. "dgm /tmp/a.msl" or "dgma".
	if (input[3] == '?') {
		r_core_cmd_help (core, help_msg_dgm);
		return true;
	}
	if (!core->dbg || core->dbg->pid == -1) {
		R_LOG_ERROR ("Not debugging; cannot write a memory slice");
		return true;
	}
	bool full = (input[3] == 'a');
	const char *filename = strchr (input, ' ');
	char *out = (filename && filename[1])
		? r_str_trim_dup (filename + 1)
		: r_str_newf ("%d.msl", core->dbg->pid);
	mslw_dump (core, out, full);
	free (out);
	return true;
}

static bool msl_call(RCorePluginSession *cps, const char *input) {
	// Intercept "dgm"/"dgma" before the builtin "dg" coredump handler.
	if (r_str_startswith (input, "dgm")) {
		return cmd_dgm (cps->core, input);
	}
	return false;
}

RCorePlugin r_core_plugin_msl = {
	.meta = {
		.name = "msl",
		.desc = "Memory Slice (.msl) producer: dgm/dgma",
		.author = "memslicer",
		.license = "LGPL-3.0-only",
	},
	.call = msl_call,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_CORE,
	.data = &r_core_plugin_msl,
	.version = R2_VERSION
};
#endif
