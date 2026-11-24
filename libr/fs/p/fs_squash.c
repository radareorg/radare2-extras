/* radare - LGPL - Copyright 2026 - pancake */

#include <r_fs.h>
#include <r_lib.h>
#include <lzma.h>
#include <zlib.h>

enum {
	SQ_SUPER_SIZE = 96,
	SQ_META_SIZE = 8192,
	SQ_META_RAW = 1 << 15,
	SQ_DATA_RAW = 1 << 24,
	SQ_GZIP = 1,
	SQ_XZ = 4,
	SQ_DIR = 1,
	SQ_FILE = 2,
	SQ_LINK = 3,
	SQ_BLOCK = 4,
	SQ_CHAR = 5,
	SQ_FIFO = 6,
	SQ_SOCKET = 7,
};

typedef struct {
	ut64 block;
	ut32 offset;
} SqCursor;

typedef struct {
	ut64 block;
	ut64 next;
	int size;
	ut8 data[SQ_META_SIZE];
} SqMetadata;

typedef struct {
	RFSRoot *root;
	ut64 size;
	ut64 inode_start;
	ut64 directory_start;
	ut64 directory_end;
	ut64 fragment_index;
	ut64 id_index;
	ut64 root_id;
	ut32 block_size;
	ut32 inode_count;
	ut32 fragments;
	ut16 ids;
	ut16 codec;
	SqMetadata inodes;
	SqMetadata directories;
	SqMetadata index;
} SqMount;

typedef struct {
	SqCursor cursor;
	ut64 id;
	ut64 size;
	ut64 start;
	ut32 offset;
	ut32 fragment;
	ut32 mtime;
	ut32 number;
	ut16 uid;
	ut16 gid;
	ut16 mode;
	ut16 type;
} SqInode;

typedef struct {
	ut64 physical;
	ut64 logical;
	ut32 size;
	ut32 stored;
	ut32 skip;
	bool fragment;
} SqBlock;

typedef struct {
	SqInode inode;
	SqCursor cursor;
	ut64 next;
	ut64 physical;
	ut64 cached_at;
	int cached_size;
	ut8 *cache;
} SqFile;

static bool sq_read_at(SqMount *sq, ut64 off, ut8 *buf, int len) {
	RFSRoot *root = sq->root;
	return off <= sq->size && (ut64)len <= sq->size - off
		&& root->iob.read_at (root->iob.io, root->delta + off, buf, len) == len;
}

static int sq_decode(SqMount *sq, ut64 off, ut32 stored, ut32 raw_bit, ut8 *buf, int capacity) {
	ut32 size = stored & ~raw_bit;
	if (!size || size > (ut32)capacity) {
		return -1;
	}
	if (stored & raw_bit) {
		return sq_read_at (sq, off, buf, size)? (int)size: -1;
	}
	ut8 *input = malloc (size);
	if (!input) {
		return -1;
	}
	int result = -1;
	if (sq_read_at (sq, off, input, size)) {
		if (sq->codec == SQ_GZIP) {
			unsigned long output_size = capacity;
			unsigned long input_size = size;
			if (uncompress2 (buf, &output_size, input, &input_size) == Z_OK && input_size == size) {
				result = output_size;
			}
		} else {
			uint64_t memlimit = 64 * 1024 * 1024;
			size_t in = 0, out = 0;
			if (lzma_stream_buffer_decode (&memlimit, 0, NULL, input, &in, size, buf, &out, capacity) == LZMA_OK
					&& in == size) {
				result = out;
			}
		}
	}
	free (input);
	return result;
}

static bool sq_meta_read(SqMount *sq, SqCursor *cursor, ut64 end, ut8 *buf, int len) {
	SqMetadata *meta = cursor->block < sq->directory_start? &sq->inodes
		: cursor->block < sq->directory_end? &sq->directories: &sq->index;
	while (len > 0) {
		if (cursor->block >= end || end - cursor->block < 2) {
			return false;
		}
		if (meta->block != cursor->block) {
			ut8 header[2];
			if (!sq_read_at (sq, cursor->block, header, sizeof (header))) {
				return false;
			}
			ut16 stored = r_read_le16 (header);
			ut64 next = cursor->block + 2 + (stored & ~SQ_META_RAW);
			if (next > end) {
				return false;
			}
			meta->block = UT64_MAX;
			int size = sq_decode (sq, cursor->block + 2, stored, SQ_META_RAW, meta->data, sizeof (meta->data));
			if (size <= 0) {
				return false;
			}
			meta->size = size;
			meta->next = next;
			meta->block = cursor->block;
		}
		if (meta->next > end || cursor->offset >= (ut32)meta->size) {
			return false;
		}
		int chunk = R_MIN ((ut32)len, meta->size - cursor->offset);
		memcpy (buf, meta->data + cursor->offset, chunk);
		cursor->offset += chunk;
		if (cursor->offset == (ut32)meta->size) {
			cursor->block = meta->next;
			cursor->offset = 0;
		}
		buf += chunk;
		len -= chunk;
	}
	return true;
}

static bool sq_index_block(SqMount *sq, ut64 index, ut64 number, ut64 *block) {
	ut8 data[8];
	if (index >= sq->size || number >= (sq->size - index) / sizeof (data)
			|| !sq_read_at (sq, index + number * sizeof (data), data, sizeof (data))) {
		return false;
	}
	*block = r_read_le64 (data);
	return *block >= sq->directory_start && *block < index;
}

static bool sq_index_read(SqMount *sq, ut64 index, ut64 offset, ut8 *buf, int len) {
	SqCursor cursor = { .offset = offset % SQ_META_SIZE };
	return sq_index_block (sq, index, offset / SQ_META_SIZE, &cursor.block)
		&& sq_meta_read (sq, &cursor, index, buf, len);
}

static bool sq_inode_read(SqMount *sq, ut64 id, SqInode *inode) {
	if ((id >> 16) >= sq->directory_start - sq->inode_start || (id & UT16_MAX) >= SQ_META_SIZE) {
		return false;
	}
	SqCursor cur = { sq->inode_start + (id >> 16), id & UT16_MAX };
	ut8 base[16], data[40];
	if (!sq_meta_read (sq, &cur, sq->directory_start, base, sizeof (base))) {
		return false;
	}
	ut16 type = r_read_le16 (base);
	static const ut8 sizes[] = { 0, 16, 16, 8, 8, 8, 4, 4, 24, 40, 8, 12, 12, 8, 8 };
	if (!type || type >= R_ARRAY_SIZE (sizes)
			|| !sq_meta_read (sq, &cur, sq->directory_start, data, sizes[type])) {
		return false;
	}
	*inode = (SqInode) {
		.cursor = cur, .id = id, .type = type > SQ_SOCKET? type - SQ_SOCKET: type,
		.mode = r_read_le16 (base + 2), .uid = r_read_le16 (base + 4), .gid = r_read_le16 (base + 6),
		.mtime = r_read_le32 (base + 8), .number = r_read_le32 (base + 12),
		.fragment = UT32_MAX,
	};
	if (!inode->number || inode->number > sq->inode_count || inode->uid >= sq->ids || inode->gid >= sq->ids) {
		return false;
	}
	switch (type) {
	case SQ_DIR:
		inode->start = r_read_le32 (data);
		inode->size = r_read_le16 (data + 8);
		inode->offset = r_read_le16 (data + 10);
		break;
	case SQ_DIR + SQ_SOCKET:
		inode->size = r_read_le32 (data + 4);
		inode->start = r_read_le32 (data + 8);
		inode->offset = r_read_le16 (data + 18);
		break;
	case SQ_FILE:
		inode->start = r_read_le32 (data);
		inode->fragment = r_read_le32 (data + 4);
		inode->offset = r_read_le32 (data + 8);
		inode->size = r_read_le32 (data + 12);
		break;
	case SQ_FILE + SQ_SOCKET:
		inode->start = r_read_le64 (data);
		inode->size = r_read_le64 (data + 8);
		inode->fragment = r_read_le32 (data + 28);
		inode->offset = r_read_le32 (data + 32);
		break;
	case SQ_LINK:
	case SQ_LINK + SQ_SOCKET:
		inode->size = r_read_le32 (data + 4);
		break;
	}
	if (inode->type == SQ_DIR) {
		return inode->size >= 3 && (inode->size == 3
			|| (inode->start < sq->directory_end - sq->directory_start && inode->offset < SQ_META_SIZE));
	}
	if (inode->type == SQ_FILE) {
		return inode->fragment == UT32_MAX
			|| (inode->fragment < sq->fragments && inode->offset < sq->block_size);
	}
	return true;
}

static char sq_type(ut16 type) {
	static const char types[] = { 0, 'd', 'r', 'S', 'b', 'c', 's', 's' };
	return types[type];
}

static RFSFile *sq_entry(SqMount *sq, RFSRoot *root, const char *name, const SqInode *inode) {
	ut8 uid[4], gid[4];
	if (!sq_index_read (sq, sq->id_index, (ut64)inode->uid * 4, uid, sizeof (uid))
			|| !sq_index_read (sq, sq->id_index, (ut64)inode->gid * 4, gid, sizeof (gid))) {
		return NULL;
	}
	RFSFile *file = r_fs_file_new (root, name);
	file->id = inode->id;
	file->type = sq_type (inode->type);
	file->perm = inode->mode;
	file->time = inode->mtime;
	file->size = inode->type == SQ_DIR? 0: inode->size;
	file->uid = r_read_le32 (uid);
	file->gid = r_read_le32 (gid);
	return file;
}

static bool sq_directory(SqMount *sq, const SqInode *dir, const char *name, size_t len, SqInode *found, RList *list, int view) {
	if (dir->type != SQ_DIR) {
		return false;
	}
	ut64 left = dir->size - 3;
	SqCursor cur = { sq->directory_start + dir->start, dir->offset };
	while (left) {
		ut8 header[12];
		if (left < sizeof (header) || !sq_meta_read (sq, &cur, sq->directory_end, header, sizeof (header))) {
			return false;
		}
		left -= sizeof (header);
		ut32 count = r_read_le32 (header);
		ut64 block = r_read_le32 (header + 4);
		ut32 base_number = r_read_le32 (header + 8);
		if (count >= 256) {
			return false;
		}
		do {
			ut8 entry[8];
			char component[257];
			if (left < sizeof (entry) || !sq_meta_read (sq, &cur, sq->directory_end, entry, sizeof (entry))) {
				return false;
			}
			left -= sizeof (entry);
			size_t length = (size_t)r_read_le16 (entry + 6) + 1;
			if (length >= sizeof (component) || length > left
					|| !sq_meta_read (sq, &cur, sq->directory_end, (ut8 *)component, length)
					|| memchr (component, 0, length) || memchr (component, '/', length)
					|| (component[0] == '.' && (length == 1 || (length == 2 && component[1] == '.')))) {
				return false;
			}
			left -= length;
			component[length] = 0;
			ut64 id = (block << 16) | r_read_le16 (entry);
			if (name && (len != length || memcmp (name, component, len))) {
				continue;
			}
			SqInode child;
			st64 number = (st64)base_number + (st16)r_read_le16 (entry + 2);
			if (!sq_inode_read (sq, id, &child) || child.number != number || child.type != r_read_le16 (entry + 4)) {
				return false;
			}
			if (name) {
				*found = child;
				return true;
			}
			int kind = child.type <= SQ_FILE? R_FS_VIEW_NORMAL: R_FS_VIEW_SPECIAL;
			if (view & kind) {
				RFSFile *file = sq_entry (sq, NULL, component, &child);
				if (!file || !r_list_append (list, file)) {
					r_fs_file_free (file);
					return false;
				}
			}
		} while (count--);
	}
	return !name;
}

static bool sq_lookup(SqMount *sq, const char *path, SqInode *inode) {
	if (!sq_inode_read (sq, sq->root_id, inode)) {
		return false;
	}
	while (*path) {
		if (*path == '/') {
			path++;
			continue;
		}
		const char *end = strchr (path, '/');
		size_t len = end? (size_t)(end - path): strlen (path);
		if (!sq_directory (sq, inode, path, len, inode, NULL, 0)) {
			return false;
		}
		path += len;
	}
	return true;
}

static bool sq_next_block(SqMount *sq, SqFile *state, SqBlock *block);

static RFSFile *sq_open_inode(RFSRoot *root, const char *path, const SqInode *inode) {
	if (inode->type != SQ_FILE && inode->type != SQ_LINK) {
		return NULL;
	}
	RFSFile *file = sq_entry (root->ptr, root, path, inode);
	if (file) {
		SqFile *state = R_NEW0 (SqFile);
		state->inode = *inode;
		state->cursor = inode->cursor;
		state->physical = inode->start;
		state->cached_at = UT64_MAX;
		file->ptr = state;
		SqFile walk = *state;
		SqBlock first;
		if (inode->type == SQ_FILE && inode->size && sq_next_block (root->ptr, &walk, &first)
				&& (first.stored & SQ_DATA_RAW)) {
			file->off = root->delta + first.physical + first.skip;
		}
	}
	return file;
}

static RFSFile *sq_open(RFSRoot *root, const char *path, bool create) {
	SqInode inode;
	return !create && sq_lookup (root->ptr, path, &inode)? sq_open_inode (root, path, &inode): NULL;
}

static RFSFile *sq_open_id(RFSRoot *root, ut64 id, ut32 flags) {
	SqInode inode;
	return !(flags & ~R_FS_OPEN_RECOVER) && sq_inode_read (root->ptr, id, &inode)
		? sq_open_inode (root, "", &inode): NULL;
}

static RList *sq_dir(RFSRoot *root, const char *path, ut64 id, int view) {
	SqMount *sq = root->ptr;
	SqInode inode;
	if (!(id == UT64_MAX? sq_lookup (sq, path, &inode): sq_inode_read (sq, id, &inode))) {
		return NULL;
	}
	RList *list = r_list_newf ((RListFree)r_fs_file_free);
	if (!list || !sq_directory (sq, &inode, NULL, 0, NULL, list, view)) {
		r_list_free (list);
		return NULL;
	}
	return list;
}

static bool sq_next_block(SqMount *sq, SqFile *state, SqBlock *block) {
	const SqInode *inode = &state->inode;
	ut64 logical = state->next;
	SqCursor cursor = state->cursor;
	ut8 data[16];
	*block = (SqBlock) {
		.physical = state->physical, .logical = logical, .size = R_MIN (inode->size - logical, sq->block_size),
	};
	block->fragment = inode->fragment != UT32_MAX && block->size < sq->block_size;
	if (block->fragment) {
		if (!sq_index_read (sq, sq->fragment_index, (ut64)inode->fragment * 16, data, sizeof (data))) {
			return false;
		}
		block->physical = r_read_le64 (data);
		block->stored = r_read_le32 (data + 8);
		block->skip = inode->offset;
		if (!block->stored || block->size > sq->block_size - block->skip) {
			return false;
		}
	} else {
		if (!sq_meta_read (sq, &cursor, sq->directory_start, data, 4)) {
			return false;
		}
		block->stored = r_read_le32 (data);
	}
	ut32 size = block->stored & ~SQ_DATA_RAW;
	if (block->stored && (!size || size > sq->block_size || block->physical < SQ_SUPER_SIZE
			|| block->physical >= sq->inode_start || size > sq->inode_start - block->physical
			|| ((block->stored & SQ_DATA_RAW) && (block->fragment? size < block->size + block->skip: size != block->size)))) {
		return false;
	}
	state->cursor = cursor;
	state->physical += block->fragment? 0: size;
	state->next += block->size;
	return true;
}

static int sq_read(RFSFile *file, ut64 off, int len) {
	if (off >= file->size) {
		return 0;
	}
	SqMount *sq = file->root->ptr;
	SqFile *state = file->ptr;
	len = R_MIN ((ut64)len, file->size - off);
	if (state->inode.type == SQ_LINK) {
		SqCursor cur = state->inode.cursor;
		ut8 discard[SQ_META_SIZE];
		while (off) {
			int chunk = R_MIN (off, sizeof (discard));
			if (!sq_meta_read (sq, &cur, sq->directory_start, discard, chunk)) {
				return -1;
			}
			off -= chunk;
		}
		return sq_meta_read (sq, &cur, sq->directory_start, file->data, len)? len: -1;
	}
	int done = 0;
	while (done < len) {
		if (state->cached_at > off || off - state->cached_at >= (ut64)state->cached_size) {
			if (off < state->next) {
				state->cursor = state->inode.cursor;
				state->physical = state->inode.start;
				state->next = 0;
			}
			SqBlock block;
			do {
				if (!sq_next_block (sq, state, &block)) {
					return done? done: -1;
				}
			} while (off >= state->next);
			if (!state->cache) {
				state->cache = malloc (sq->block_size);
				if (!state->cache) {
					return done? done: -1;
				}
			}
			state->cached_at = UT64_MAX;
			if (block.stored) {
				int decoded = sq_decode (sq, block.physical, block.stored, SQ_DATA_RAW, state->cache, sq->block_size);
				if (decoded < 0 || (ut32)decoded < block.skip + block.size
						|| (!block.fragment && (ut32)decoded != block.size)) {
					return done? done: -1;
				}
				memmove (state->cache, state->cache + block.skip, block.size);
			} else {
				memset (state->cache, 0, block.size);
			}
			state->cached_at = block.logical;
			state->cached_size = block.size;
		}
		size_t within = off - state->cached_at;
		int chunk = R_MIN ((size_t)(len - done), state->cached_size - within);
		memcpy (file->data + done, state->cache + within, chunk);
		off += chunk;
		done += chunk;
	}
	return done;
}

static void sq_close(RFSFile *file) {
	SqFile *state = file->ptr;
	free (state->cache);
	free (state);
	file->ptr = NULL;
}

static int sq_extents(RFSFile *file, RFSRangeCb cb, void *user) {
	const SqFile *state = file->ptr;
	if (state->inode.type != SQ_FILE) {
		return R_FS_WALK_UNSUPPORTED;
	}
	SqMount *sq = file->root->ptr;
	SqFile walk = { .inode = state->inode, .cursor = state->inode.cursor, .physical = state->inode.start };
	while (walk.next < file->size) {
		SqBlock block;
		if (!sq_next_block (sq, &walk, &block)) {
			return R_FS_WALK_ERROR;
		}
		RFSRange range = { .logical = block.logical, .physical = UT64_MAX, .size = block.size };
		if (!block.stored) {
			range.flags = R_FS_RANGE_SPARSE;
		} else if (block.stored & SQ_DATA_RAW) {
			range.physical = file->root->delta + block.physical + block.skip;
			range.flags = R_FS_RANGE_ALLOCATED;
		} else {
			range.flags = R_FS_RANGE_UNKNOWN;
		}
		if (!cb (&range, user)) {
			return R_FS_WALK_STOPPED;
		}
	}
	return R_FS_WALK_COMPLETE;
}

static int sq_ranges(RFSRoot *root, ut32 flags, RFSRangeCb cb, void *user) {
	SqMount *sq = root->ptr;
	RFSRange range = { .physical = root->delta, .size = sq->size, .flags = R_FS_RANGE_ALLOCATED };
	return !(flags & range.flags) || cb (&range, user)? R_FS_WALK_COMPLETE: R_FS_WALK_STOPPED;
}

static bool sq_mount(RFSRoot *root) {
	ut8 data[SQ_SUPER_SIZE];
	if (root->delta > UT64_MAX - sizeof (data)
			|| root->iob.read_at (root->iob.io, root->delta, data, sizeof (data)) != sizeof (data)
			|| memcmp (data, "hsqs", 4) || r_read_le16 (data + 28) != 4 || r_read_le16 (data + 30)) {
		return false;
	}
	SqMount *sq = R_NEW0 (SqMount);
	sq->root = root;
	sq->inode_count = r_read_le32 (data + 4);
	sq->block_size = r_read_le32 (data + 12);
	sq->fragments = r_read_le32 (data + 16);
	sq->codec = r_read_le16 (data + 20);
	sq->ids = r_read_le16 (data + 26);
	sq->root_id = r_read_le64 (data + 32);
	sq->size = r_read_le64 (data + 40);
	sq->id_index = r_read_le64 (data + 48);
	sq->inode_start = r_read_le64 (data + 64);
	sq->directory_start = r_read_le64 (data + 72);
	sq->fragment_index = r_read_le64 (data + 80);
	sq->inodes.block = sq->directories.block = sq->index.block = UT64_MAX;
	ut16 log = r_read_le16 (data + 22);
	ut8 last;
	ut64 id_meta, fragment_meta, export_meta;
	ut64 export_index = r_read_le64 (data + 88);
	SqInode inode;
	if (log < 12 || log > 20 || sq->block_size != (1U << log) || !sq->ids
			|| (sq->codec != SQ_GZIP && sq->codec != SQ_XZ)
			|| sq->size > UT64_MAX - root->delta || sq->inode_start < sizeof (data)
			|| sq->inode_start >= sq->directory_start || sq->directory_start >= sq->size
			|| !sq_read_at (sq, sq->size - 1, &last, 1)
			|| !sq_index_block (sq, sq->id_index, 0, &id_meta)
			|| (sq->fragments && !sq_index_block (sq, sq->fragment_index, 0, &fragment_meta))
			|| (export_index != UT64_MAX && !sq_index_block (sq, export_index, 0, &export_meta))) {
		free (sq);
		return false;
	}
	sq->directory_end = id_meta;
	if (sq->fragments) {
		sq->directory_end = R_MIN (sq->directory_end, fragment_meta);
	}
	if (export_index != UT64_MAX) {
		sq->directory_end = R_MIN (sq->directory_end, export_meta);
	}
	if (!sq_inode_read (sq, sq->root_id, &inode) || inode.type != SQ_DIR) {
		free (sq);
		return false;
	}
	root->ptr = sq;
	return true;
}

static void sq_umount(RFSRoot *root) {
	R_FREE (root->ptr);
}

static void sq_details(RFSRoot *root, RStrBuf *out) {
	SqMount *sq = root->ptr;
	r_strbuf_appendf (out, "SquashFS 4.0 %s, block size %u, %u inodes, %u fragments, %"PFMT64u" bytes used\n",
		sq->codec == SQ_GZIP? "gzip": "xz", sq->block_size, sq->inode_count, sq->fragments, sq->size);
}

RFSPlugin r_fs_plugin_squash = {
	.meta = {
		.name = "squash",
		.desc = "SquashFS 4.0 with inode and extent inspection",
		.license = "LGPL-3.0-only",
	},
	.mount = sq_mount,
	.umount = sq_umount,
	.open = sq_open,
	.open_id = sq_open_id,
	.read = sq_read,
	.close = sq_close,
	.dir = sq_dir,
	.extents = sq_extents,
	.ranges = sq_ranges,
	.details = sq_details,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_FS,
	.data = &r_fs_plugin_squash,
	.version = R2_VERSION,
	.abiversion = R2_ABIVERSION,
};
#endif
