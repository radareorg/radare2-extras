/* radare - LGPL - Copyright 2026 - pancake */

#include <r_fs.h>
#include <r_lib.h>
#include <errno.h>
#include <zlib.h>

enum {
	JF_MAGIC = 0x1985,
	JF_ACCURATE = 0x2000,
	JF_DIRENT = 0xe001,
	JF_INODE = 0xe002,
	JF_XATTR = 0xe008,
	JF_XREF = 0xe009,
	JF_RAW = 0,
	JF_ZERO = 1,
	JF_RTIME = 2,
	JF_COPY = 4,
	JF_ZLIB = 6,
	JF_TYPE_MASK = 0170000,
	JF_TYPE_REGULAR = 0100000,
	JF_TYPE_DIRECTORY = 0040000,
	JF_TYPE_LINK = 0120000,
	JF_TYPE_BLOCK = 0060000,
	JF_TYPE_CHAR = 0020000,
	JF_HEADER = 12,
	JF_DIRENT_SIZE = 40,
	JF_INODE_SIZE = 68,
	JF_SCAN_SIZE = 65536,
	JF_DECODE_LIMIT = 16 * 1024 * 1024,
};

#define JF_DELETED_ID ((ut64)1 << 63)

typedef struct {
	ut64 at;
	char *name;
	ut32 parent;
	ut32 version;
	ut32 ino;
	bool accurate;
} JffsName;

typedef struct {
	ut64 data;
	ut32 ino;
	ut32 version;
	ut32 mode;
	ut32 time;
	ut32 size;
	ut32 start;
	ut32 stored;
	ut32 decoded;
	ut32 crc;
	ut16 uid;
	ut16 gid;
	ut8 codec;
	bool accurate;
} JffsNode;

typedef struct {
	ut32 parent;
	const JffsName *entry;
	bool deleted;
} JffsEntry;

typedef struct {
	ut32 off;
	size_t next;
	const JffsNode *node;
} JffsSpan;

static void jffs_name_fini(JffsName *name) {
	free (name->name);
}

R_VEC_TYPE_WITH_FINI (JffsNames, JffsName, jffs_name_fini);
R_VEC_TYPE (JffsEntries, JffsEntry);
R_VEC_TYPE (JffsNodes, JffsNode);
R_VEC_TYPE (JffsSpans, JffsSpan);
R_VEC_TYPE (JffsRanges, RFSRange);

typedef struct {
	RFSRoot *root;
	ut64 size;
	bool big_endian;
	bool damaged;
	JffsNames names;
	JffsEntries entries;
	JffsNodes nodes;
	JffsRanges ranges;
	HtUP *linked;
	HtUP *deleted;
} JffsMount;

typedef struct {
	ut64 start;
	ut64 end;
	ut8 bytes[JF_SCAN_SIZE];
} JffsScan;

typedef struct {
	JffsSpans spans;
	const JffsNode *cached;
	ut8 *data;
} JffsFile;

static bool jffs_read_at(JffsMount *fs, ut64 off, ut8 *data, int len) {
	RFSRoot *root = fs->root;
	return off <= fs->size && (ut64)len <= fs->size - off
		&& root->iob.read_at (root->iob.io, root->delta + off, data, len) == len;
}

static const ut8 *jffs_scan_at(JffsMount *fs, JffsScan *scan, ut64 off, int len) {
	if ((ut64)len > fs->size - off) {
		return NULL;
	}
	if (off < scan->start || off > scan->end || (ut64)len > scan->end - off) {
		int count = R_MIN (sizeof (scan->bytes), fs->size - off);
		if (!jffs_read_at (fs, off, scan->bytes, count)) {
			return NULL;
		}
		scan->start = off;
		scan->end = off + count;
	}
	return scan->bytes + (off - scan->start);
}

static ut16 jffs_u16(JffsMount *fs, const ut8 *p) {
	return r_read_ble16 (p, fs->big_endian);
}

static ut32 jffs_u32(JffsMount *fs, const ut8 *p) {
	return r_read_ble32 (p, fs->big_endian);
}

static ut32 jffs_crc(const ut8 *p, ut32 len) {
	return (ut32)crc32 (UT32_MAX, p, len) ^ UT32_MAX;
}

static bool jffs_add_range(JffsMount *fs, ut64 off, ut64 size, ut32 flags) {
	RFSRange *range = JffsRanges_last (&fs->ranges);
	if (range && range->flags == flags) {
		range->size += size;
		return true;
	}
	range = JffsRanges_emplace_back (&fs->ranges);
	if (!range) {
		return false;
	}
	*range = (RFSRange) { off, fs->root->delta + off, size, flags };
	return true;
}

static int jffs_scan_name(JffsMount *fs, const ut8 *data, ut32 len, ut64 off, bool accurate) {
	ut32 parent = jffs_u32 (fs, data + 12);
	ut8 size = data[28];
	const ut8 *name = data + JF_DIRENT_SIZE;
	if (!parent || !size || size == 255 || len != JF_DIRENT_SIZE + (ut32)size
			|| jffs_crc (data, 32) != jffs_u32 (fs, data + 32)
			|| jffs_crc (name, size) != jffs_u32 (fs, data + 36)
			|| memchr (name, 0, size) || memchr (name, '/', size)
			|| (name[0] == '.' && (size == 1 || (size == 2 && name[1] == '.')))) {
		return 0;
	}
	JffsName *record = JffsNames_emplace_back (&fs->names);
	if (!record) {
		return -1;
	}
	record->at = off;
	record->name = r_str_ndup ((const char *)name, size);
	record->parent = parent;
	record->version = jffs_u32 (fs, data + 16);
	record->ino = jffs_u32 (fs, data + 20);
	record->accurate = accurate;
	return record->name? 1: -1;
}

static int jffs_scan_inode(JffsMount *fs, const ut8 *data, ut32 len, ut64 off, bool accurate) {
	JffsNode node = {
		.data = off + JF_INODE_SIZE,
		.ino = jffs_u32 (fs, data + 12), .version = jffs_u32 (fs, data + 16),
		.mode = jffs_u32 (fs, data + 20), .uid = jffs_u16 (fs, data + 24), .gid = jffs_u16 (fs, data + 26),
		.size = jffs_u32 (fs, data + 28), .time = jffs_u32 (fs, data + 36),
		.start = jffs_u32 (fs, data + 44), .stored = jffs_u32 (fs, data + 48), .decoded = jffs_u32 (fs, data + 52),
		.codec = data[56], .crc = jffs_u32 (fs, data + 60), .accurate = accurate,
	};
	if (!node.ino || jffs_crc (data, 60) != jffs_u32 (fs, data + 64)) {
		return 0;
	}
	// Early writers stored the ZERO length in csize.
	if (node.codec == JF_ZERO && !node.decoded && len == JF_INODE_SIZE) {
		node.decoded = node.stored;
		node.stored = 0;
	}
	if (node.stored != len - JF_INODE_SIZE
			|| ((node.codec == JF_RAW || node.codec == JF_COPY) && node.stored != node.decoded)
			|| (node.codec == JF_ZERO && (node.stored || node.crc))) {
		return 0;
	}
	JffsNode *record = JffsNodes_emplace_back (&fs->nodes);
	if (!record) {
		return -1;
	}
	*record = node;
	return 1;
}

static int jffs_scan_node(JffsMount *fs, JffsScan *scan, ut64 off, ut32 len, ut16 type, bool accurate) {
	ut8 data[JF_DIRENT_SIZE + 254];
	int header = type == JF_INODE? JF_INODE_SIZE: JF_DIRENT_SIZE;
	if (len < (ut32)header || (type == JF_DIRENT && len > sizeof (data))) {
		return 0;
	}
	int count = type == JF_DIRENT? (int)len: header;
	const ut8 *p = jffs_scan_at (fs, scan, off, count);
	if (!p) {
		return -1;
	}
	memcpy (data, p, count);
	data[fs->big_endian? 2: 3] |= JF_ACCURATE >> 8;
	return type == JF_INODE
		? jffs_scan_inode (fs, data, len, off, accurate)
		: jffs_scan_name (fs, data, len, off, accurate);
}

static bool jffs_scan(JffsMount *fs, JffsScan *scan) {
	bool recognized = false;
	ut64 off = 0;
	while (off < fs->size) {
		int count = R_MIN (fs->size - off, JF_HEADER);
		const ut8 *p = jffs_scan_at (fs, scan, off, count);
		if (!p) {
			return false;
		}
		ut64 step = R_MIN (count, 4);
		ut32 flags = R_FS_RANGE_UNKNOWN;
		if (count >= JF_HEADER && (r_read_le16 (p) == JF_MAGIC || r_read_be16 (p) == JF_MAGIC)) {
			bool endian = r_read_be16 (p) == JF_MAGIC;
			if (!recognized || fs->big_endian == endian) {
				fs->big_endian = endian;
				ut8 header[8];
				memcpy (header, p, sizeof (header));
				header[endian? 2: 3] |= JF_ACCURATE >> 8;
				ut16 type = jffs_u16 (fs, header + 2);
				ut32 len = jffs_u32 (fs, header + 4);
				ut64 padded = ((ut64)len + 3) & ~(ut64)3;
				bool accurate = jffs_u16 (fs, p + 2) & JF_ACCURATE;
				if (len >= JF_HEADER && len <= fs->size - off && jffs_crc (header, sizeof (header)) == jffs_u32 (fs, p + 8)) {
					int status = 1;
					if (type == JF_DIRENT || type == JF_INODE) {
						status = jffs_scan_node (fs, scan, off, len, type, accurate);
					} else if (accurate && (type & 0xc000) == 0xc000 && type != JF_XATTR && type != JF_XREF) {
						return false;
					}
					if (status < 0) {
						return false;
					}
					fs->damaged |= !status && accurate;
					recognized |= status > 0 && accurate;
					if (status > 0 && accurate) {
						flags = R_FS_RANGE_ALLOCATED;
					}
					step = R_MIN (padded, fs->size - off);
				} else {
					fs->damaged = true;
				}
			}
		} else if (step == 4 && r_read_le32 (p) == UT32_MAX) {
			flags = R_FS_RANGE_FREE;
		}
		if (!jffs_add_range (fs, off, step, flags)) {
			return false;
		}
		off += step;
	}
	return recognized;
}

static int jffs_cmp(ut64 a, ut64 b) {
	return (a > b) - (a < b);
}

static int jffs_name_cmp(const JffsName *a, const JffsName *b) {
	int order = jffs_cmp (a->parent, b->parent);
	return order? order: strcmp (a->name, b->name);
}

static int jffs_name_order(const JffsName *a, const JffsName *b) {
	int order = jffs_name_cmp (a, b);
	if (!order) {
		order = jffs_cmp (a->version, b->version);
	}
	return order? order: jffs_cmp (a->at, b->at);
}

static int jffs_node_order(const JffsNode *a, const JffsNode *b) {
	int order = jffs_cmp (a->ino, b->ino);
	if (!order) {
		order = jffs_cmp (a->version, b->version);
	}
	if (!order) {
		order = jffs_cmp (a->accurate, b->accurate);
	}
	return order? order: jffs_cmp (a->data, b->data);
}

static bool jffs_index(JffsMount *fs) {
	JffsNames_sort (&fs->names, jffs_name_order);
	JffsNodes_sort (&fs->nodes, jffs_node_order);
	size_t n = JffsNames_length (&fs->names);
	size_t i = 0;
	while (i < n) {
		const JffsName *first = JffsNames_at (&fs->names, i);
		const JffsName *latest = NULL;
		const JffsName *previous = NULL;
		do {
			const JffsName *name = JffsNames_at (&fs->names, i++);
			if (name->accurate) {
				latest = name;
			}
		} while (i < n && !jffs_name_cmp (first, JffsNames_at (&fs->names, i)));
		if (!latest) {
			continue;
		}
		if (latest->ino) {
			if (!ht_up_update (fs->linked, latest->ino, (void *)latest)) {
				return false;
			}
		} else {
			const JffsName *name;
			for (name = latest; name > first;) {
				name--;
				if (name->ino && name->version < latest->version) {
					previous = name;
					break;
				}
			}
			if (!previous) {
				continue;
			}
		}
		JffsEntry *entry = JffsEntries_emplace_back (&fs->entries);
		if (!entry) {
			return false;
		}
		*entry = (JffsEntry) { latest->parent, previous? previous: latest, previous != NULL };
		if (previous && !ht_up_insert (fs->deleted, previous->at, (void *)previous)) {
			return false;
		}
	}
	return true;
}

static int jffs_node_ino_cmp(const JffsNode *a, const JffsNode *b) {
	return jffs_cmp (a->ino, b->ino);
}

static const JffsNode *jffs_latest(JffsMount *fs, ut32 ino, bool recover, size_t *first, size_t *last) {
	JffsNode key = { .ino = ino };
	*first = JffsNodes_lower_bound (&fs->nodes, &key, jffs_node_ino_cmp);
	*last = JffsNodes_upper_bound (&fs->nodes, &key, jffs_node_ino_cmp);
	size_t i = *last;
	while (i > *first) {
		const JffsNode *node = JffsNodes_at (&fs->nodes, --i);
		if (recover || node->accurate) {
			return node;
		}
	}
	return NULL;
}

static char jffs_type(ut32 mode) {
	switch (mode & JF_TYPE_MASK) {
	case JF_TYPE_REGULAR: return 'r';
	case JF_TYPE_DIRECTORY: return 'd';
	case JF_TYPE_LINK: return 'S';
	case JF_TYPE_BLOCK: return 'b';
	case JF_TYPE_CHAR: return 'c';
	default: return 's';
	}
}

static ut32 jffs_size(const JffsNode *node) {
	return !node->size && jffs_type (node->mode) == 'S'? node->decoded: node->size;
}

static int jffs_entry_parent_cmp(const JffsEntry *a, const JffsEntry *b) {
	return jffs_cmp (a->parent, b->parent);
}

static int jffs_entry_cmp(const JffsEntry *a, const JffsEntry *b) {
	int cmp = jffs_entry_parent_cmp (a, b);
	return cmp? cmp: strcmp (a->entry->name, b->entry->name);
}

static bool jffs_is_dir(JffsMount *fs, ut32 ino) {
	size_t first, last;
	const JffsNode *node = jffs_latest (fs, ino, false, &first, &last);
	return ino == 1 || (node && jffs_type (node->mode) == 'd');
}

static ut32 jffs_lookup(JffsMount *fs, const char *path) {
	ut32 ino = 1;
	while (*path) {
		if (*path == '/') {
			path++;
			continue;
		}
		const char *end = strchr (path, '/');
		size_t len = end? (size_t)(end - path): strlen (path);
		char name[255];
		if (len >= sizeof (name) || !jffs_is_dir (fs, ino)) {
			return 0;
		}
		memcpy (name, path, len);
		name[len] = 0;
		JffsName record = { .name = name };
		JffsEntry key = { .parent = ino, .entry = &record };
		JffsEntry *entry = JffsEntries_at (&fs->entries, JffsEntries_lower_bound (&fs->entries, &key, jffs_entry_cmp));
		if (!entry || entry->deleted || jffs_entry_cmp (entry, &key)) {
			return 0;
		}
		ino = entry->entry->ino;
		path += len;
	}
	return ino;
}

static RFSFile *jffs_file_new(RFSRoot *root, const char *path, const JffsNode *node, ut64 id) {
	RFSFile *file = r_fs_file_new (root, path);
	file->id = id;
	file->type = jffs_type (node->mode);
	file->size = file->type == 'd'? 0: jffs_size (node);
	file->time = node->time;
	file->uid = node->uid;
	file->gid = node->gid;
	file->perm = node->mode & 07777;
	return file;
}

static RList *jffs_dir(RFSRoot *root, const char *path, ut64 id, int view) {
	JffsMount *fs = root->ptr;
	ut32 ino = id == UT64_MAX? jffs_lookup (fs, path): id <= UT32_MAX? (ut32)id: 0;
	if (!ino || !jffs_is_dir (fs, ino)) {
		return NULL;
	}
	RList *list = r_list_newf ((RListFree)r_fs_file_free);
	if (!list) {
		return NULL;
	}
	JffsEntry key = { .parent = ino };
	size_t i = JffsEntries_lower_bound (&fs->entries, &key, jffs_entry_parent_cmp);
	const JffsEntry *entry;
	while ((entry = JffsEntries_at (&fs->entries, i++)) && entry->parent == ino) {
		const JffsName *name = entry->entry;
		if (entry->deleted && !(view & R_FS_VIEW_DELETED)) {
			continue;
		}
		size_t first, last;
		const JffsNode *node = jffs_latest (fs, name->ino, entry->deleted, &first, &last);
		if (!node && !entry->deleted) {
			continue;
		}
		char type = node? jffs_type (node->mode): R_FS_FILE_TYPE_DELETED;
		int kind = entry->deleted? R_FS_VIEW_DELETED: (type == 'r' || type == 'd')? R_FS_VIEW_NORMAL: R_FS_VIEW_SPECIAL;
		if (!(view & kind)) {
			continue;
		}
		ut64 file_id = entry->deleted? JF_DELETED_ID | name->at: name->ino;
		RFSFile *file = node? jffs_file_new (NULL, name->name, node, file_id): r_fs_file_new (NULL, name->name);
		if (entry->deleted) {
			file->id = file_id;
			file->flags = R_FS_FILE_DELETED;
			if (!node || fs->damaged) {
				file->flags |= R_FS_FILE_PARTIAL;
			}
			if (ht_up_find (fs->linked, name->ino, NULL)) {
				file->flags |= R_FS_FILE_CONFLICT;
			}
			file->type = R_FS_FILE_TYPE_DELETED;
		}
		if (!r_list_append (list, file)) {
			r_fs_file_free (file);
			r_list_free (list);
			return NULL;
		}
	}
	return list;
}

static int jffs_span_cmp(const JffsSpan *a, const JffsSpan *b) {
	return jffs_cmp (a->off, b->off);
}

static bool jffs_boundary(JffsSpans *spans, ut32 off) {
	JffsSpan *span = JffsSpans_emplace_back (spans);
	if (!span) {
		return false;
	}
	span->off = off;
	return true;
}

static size_t jffs_unassigned(JffsSpans *spans, size_t i) {
	JffsSpan *span;
	while ((span = JffsSpans_at (spans, i))->next) {
		size_t next = span->next;
		JffsSpan *following = JffsSpans_at (spans, next);
		if (following->next) {
			span->next = following->next;
		}
		i = next;
	}
	return i;
}

static bool jffs_plan(JffsMount *fs, JffsSpans *spans, const JffsNode *latest, size_t first, size_t last, bool recover) {
	ut32 size = jffs_size (latest);
	if (!jffs_boundary (spans, 0) || !jffs_boundary (spans, size)) {
		return false;
	}
	int pass;
	for (pass = 0; pass < 2; pass++) {
		ut32 limit = size;
		ut64 version = UT64_MAX;
		size_t i = last;
		// Later truncations cap the surviving bytes of each older fragment.
		while (i > first) {
			const JffsNode *node = JffsNodes_at (&fs->nodes, --i);
			if ((!recover && !node->accurate) || node->version == version) {
				continue;
			}
			version = node->version;
			limit = R_MIN (limit, jffs_size (node));
			ut32 end = R_MIN (limit, (ut64)node->start + node->decoded);
			if (node->start >= end) {
				continue;
			}
			if (!pass) {
				if (!jffs_boundary (spans, node->start) || !jffs_boundary (spans, end)) {
					return false;
				}
				continue;
			}
			JffsSpan low = { .off = node->start }, high = { .off = end };
			size_t begin = JffsSpans_lower_bound (spans, &low, jffs_span_cmp);
			size_t stop = JffsSpans_lower_bound (spans, &high, jffs_span_cmp);
			size_t at;
			for (at = jffs_unassigned (spans, begin); at < stop; at = jffs_unassigned (spans, at + 1)) {
				JffsSpan *span = JffsSpans_at (spans, at);
				span->node = node;
				span->next = at + 1;
			}
		}
		if (!pass) {
			JffsSpans_sort (spans, jffs_span_cmp);
			JffsSpans_uniq (spans, jffs_span_cmp);
		}
	}
	// Remove boundaries left by fragments that were later overwritten.
	size_t count = JffsSpans_length (spans);
	size_t used = 0;
	size_t i;
	for (i = 0; i + 1 < count; i++) {
		JffsSpan *span = JffsSpans_at (spans, i);
		JffsSpan *prev = used? JffsSpans_at (spans, used - 1): NULL;
		if (!prev || prev->node != span->node) {
			*JffsSpans_at (spans, used++) = *span;
		}
	}
	*JffsSpans_at (spans, used++) = *JffsSpans_last (spans);
	JffsSpans_erase_back (spans, JffsSpans_at (spans, used - 1) + 1);
	return true;
}

static bool jffs_rtime(const ut8 *in, ut32 stored, ut8 *out, ut32 decoded) {
	ut16 history[256] = {0};
	ut32 src = 0, dst = 0;
	while (stored - src >= 2 && dst < decoded) {
		ut8 value = in[src++];
		ut8 count = in[src++];
		ut32 back = history[value];
		out[dst++] = value;
		history[value] = dst;
		if (count > decoded - dst || back >= dst) {
			return false;
		}
		while (count--) {
			out[dst++] = out[back++];
		}
	}
	return src == stored && dst == decoded;
}

static bool jffs_load(JffsMount *fs, JffsFile *state, const JffsNode *node) {
	if (state->cached == node) {
		return true;
	}
	state->cached = NULL;
	if (node->codec != JF_ZERO) {
		bool raw = node->codec == JF_RAW || node->codec == JF_COPY;
		if (raw) {
			ut8 buf[8192];
			ut32 done = 0;
			ut32 crc = UT32_MAX;
			while (done < node->stored) {
				int chunk = R_MIN (sizeof (buf), node->stored - done);
				if (!jffs_read_at (fs, node->data + done, buf, chunk)) {
					return false;
				}
				crc = crc32 (crc, buf, chunk);
				done += chunk;
			}
			if ((crc ^ UT32_MAX) != node->crc) {
				return false;
			}
		} else {
			if (!node->stored || node->stored > JF_DECODE_LIMIT || node->decoded > JF_DECODE_LIMIT
					|| (node->codec != JF_ZLIB && node->codec != JF_RTIME)) {
				return false;
			}
			R_FREE (state->data);
			state->data = malloc (node->decoded);
			ut8 *input = malloc (node->stored);
			bool ok = false;
			if (state->data && input && jffs_read_at (fs, node->data, input, node->stored)
					&& jffs_crc (input, node->stored) == node->crc) {
				if (node->codec == JF_ZLIB) {
					unsigned long in = node->stored, out = node->decoded;
					ok = uncompress2 (state->data, &out, input, &in) == Z_OK && in == node->stored && out == node->decoded;
				} else {
					ok = jffs_rtime (input, node->stored, state->data, node->decoded);
				}
			}
			free (input);
			if (!ok) {
				return false;
			}
		}
	}
	state->cached = node;
	return true;
}

static void jffs_close(RFSFile *file) {
	JffsFile *state = file->ptr;
	JffsSpans_fini (&state->spans);
	free (state->data);
	free (state);
	file->ptr = NULL;
}

static RFSFile *jffs_open_inode(RFSRoot *root, const char *path, ut32 ino, ut64 id, bool recover) {
	JffsMount *fs = root->ptr;
	size_t first, last;
	const JffsNode *node = jffs_latest (fs, ino, recover, &first, &last);
	if (!node || (jffs_type (node->mode) != 'r' && (recover || jffs_type (node->mode) != 'S'))) {
		return NULL;
	}
	RFSFile *file = jffs_file_new (root, path, node, id);
	JffsFile *state = R_NEW0 (JffsFile);
	file->ptr = state;
	bool ok = jffs_plan (fs, &state->spans, node, first, last, recover);
	if (ok && recover) {
		file->flags = R_FS_FILE_DELETED;
		size_t n = JffsSpans_length (&state->spans);
		size_t i;
		for (i = 0; i + 1 < n; i++) {
			const JffsNode *fragment = JffsSpans_at (&state->spans, i)->node;
			if (!fragment || !jffs_load (fs, state, fragment)) {
				ok = false;
				break;
			}
		}
	}
	if (!ok) {
		jffs_close (file);
		r_fs_file_free (file);
		return NULL;
	}
	const JffsNode *head = JffsSpans_at (&state->spans, 0)->node;
	if (head && (head->codec == JF_RAW || head->codec == JF_COPY)) {
		file->off = root->delta + head->data;
	}
	return file;
}

static RFSFile *jffs_open(RFSRoot *root, const char *path, bool create) {
	ut32 ino = create? 0: jffs_lookup (root->ptr, path);
	return ino? jffs_open_inode (root, path, ino, ino, false): NULL;
}

static RFSFile *jffs_open_id(RFSRoot *root, ut64 id, ut32 flags) {
	JffsMount *fs = root->ptr;
	if (!(flags & ~R_FS_OPEN_RECOVER) && id && id <= UT32_MAX && ht_up_find (fs->linked, id, NULL)) {
		return jffs_open_inode (root, "", id, id, false);
	}
	if (!(id & JF_DELETED_ID) || (flags & ~(R_FS_OPEN_RECOVER | R_FS_OPEN_SALVAGE)) || fs->damaged) {
		return NULL;
	}
	const JffsName *name = ht_up_find (fs->deleted, id & ~JF_DELETED_ID, NULL);
	return name && !ht_up_find (fs->linked, name->ino, NULL)
		? jffs_open_inode (root, name->name, name->ino, id, true): NULL;
}

static int jffs_read(RFSFile *file, ut64 off, int len) {
	if (off >= file->size) {
		return 0;
	}
	JffsMount *fs = file->root->ptr;
	JffsFile *state = file->ptr;
	JffsSpan key = { .off = off };
	size_t i = JffsSpans_upper_bound (&state->spans, &key, jffs_span_cmp) - 1;
	len = R_MIN ((ut64)len, file->size - off);
	int done = 0;
	while (done < len) {
		const JffsSpan *span = JffsSpans_at (&state->spans, i++);
		const JffsNode *node = span->node;
		int count = R_MIN ((ut64)(len - done), JffsSpans_at (&state->spans, i)->off - off);
		if (node && !jffs_load (fs, state, node)) {
			return done? done: -1;
		}
		if (!node || node->codec == JF_ZERO) {
			memset (file->data + done, 0, count);
		} else if (node->codec == JF_RAW || node->codec == JF_COPY) {
			if (!jffs_read_at (fs, node->data + off - node->start, file->data + done, count)) {
				return done? done: -1;
			}
		} else {
			memcpy (file->data + done, state->data + off - node->start, count);
		}
		off += count;
		done += count;
	}
	return done;
}

static int jffs_extents(RFSFile *file, RFSRangeCb cb, void *user) {
	JffsMount *fs = file->root->ptr;
	JffsFile *state = file->ptr;
	size_t n = JffsSpans_length (&state->spans);
	size_t i;
	for (i = 0; i + 1 < n; i++) {
		const JffsSpan *span = JffsSpans_at (&state->spans, i);
		const JffsNode *node = span->node;
		RFSRange range = {
			.logical = span->off, .physical = UT64_MAX, .size = JffsSpans_at (&state->spans, i + 1)->off - span->off,
		};
		if (!node || node->codec == JF_ZERO) {
			range.flags = R_FS_RANGE_SPARSE;
		} else if (node->codec == JF_RAW || node->codec == JF_COPY) {
			range.flags = node->accurate? R_FS_RANGE_ALLOCATED: R_FS_RANGE_UNKNOWN;
			range.physical = fs->root->delta + node->data + span->off - node->start;
		} else {
			range.flags = R_FS_RANGE_UNKNOWN;
		}
		if (!cb (&range, user)) {
			return R_FS_WALK_STOPPED;
		}
	}
	return R_FS_WALK_COMPLETE;
}

static int jffs_ranges(RFSRoot *root, ut32 flags, RFSRangeCb cb, void *user) {
	JffsMount *fs = root->ptr;
	RFSRange *range;
	R_VEC_FOREACH (&fs->ranges, range) {
		if ((range->flags & flags) && !cb (range, user)) {
			return R_FS_WALK_STOPPED;
		}
	}
	return R_FS_WALK_COMPLETE;
}

static void jffs_free(JffsMount *fs) {
	ht_up_free (fs->deleted);
	ht_up_free (fs->linked);
	JffsEntries_fini (&fs->entries);
	JffsNames_fini (&fs->names);
	JffsNodes_fini (&fs->nodes);
	JffsRanges_fini (&fs->ranges);
	free (fs);
}

static bool jffs_mount(RFSRoot *root) {
	RIO *io = root->iob.io;
	RIOMap *map = io->va? root->iob.map_get_at (io, root->delta): NULL;
	ut64 size = map? r_itv_size (map->itv) - (root->delta - r_itv_begin (map->itv)): r_io_size (io);
	if (!map) {
		if (root->delta >= size) {
			return false;
		}
		size -= root->delta;
	}
	if (R_STR_ISNOTEMPTY (root->options)) {
		char *end;
		if (!r_str_startswith (root->options, "size=") || root->options[5] < '0' || root->options[5] > '9') {
			return false;
		}
		errno = 0;
		ut64 limit = strtoull (root->options + 5, &end, 0);
		if (errno || *end || limit > size) {
			return false;
		}
		size = limit;
	}
	if (size < JF_HEADER || size > JF_DELETED_ID - 1 || size > UT64_MAX - root->delta) {
		return false;
	}
	JffsMount *fs = R_NEW0 (JffsMount);
	fs->root = root;
	fs->size = size;
	fs->linked = ht_up_new0 ();
	fs->deleted = ht_up_new0 ();
	JffsScan *scan = R_NEW0 (JffsScan);
	bool ok = fs->linked && fs->deleted && jffs_scan (fs, scan) && jffs_index (fs);
	free (scan);
	if (!ok) {
		jffs_free (fs);
		return false;
	}
	root->ptr = fs;
	return true;
}

static void jffs_umount(RFSRoot *root) {
	if (root->ptr) {
		jffs_free (root->ptr);
		root->ptr = NULL;
	}
}

static void jffs_details(RFSRoot *root, RStrBuf *out) {
	JffsMount *fs = root->ptr;
	r_strbuf_appendf (out, "JFFS2 %s-endian, %"PFMT64u" bytes, %"PFMTSZu" inode records, %"PFMTSZu" directory entries\n",
		fs->big_endian? "big": "little", fs->size, JffsNodes_length (&fs->nodes), JffsEntries_length (&fs->entries));
	if (fs->damaged) {
		r_strbuf_append (out, "Damaged node headers or metadata detected\n");
	}
}

RFSPlugin r_fs_plugin_jffs2 = {
	.meta = {
		.name = "jffs2",
		.desc = "JFFS2 with versioned inode reads and unlink recovery",
		.license = "LGPL-3.0-only",
	},
	.mount = jffs_mount,
	.umount = jffs_umount,
	.open = jffs_open,
	.open_id = jffs_open_id,
	.read = jffs_read,
	.close = jffs_close,
	.dir = jffs_dir,
	.extents = jffs_extents,
	.ranges = jffs_ranges,
	.details = jffs_details,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_FS,
	.data = &r_fs_plugin_jffs2,
	.version = R2_VERSION,
	.abiversion = R2_ABIVERSION,
};
#endif
