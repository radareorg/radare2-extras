/* radare - LGPL - Copyright 2017 - pancake */

#include <r_fs.h>
#include <r_lib.h>
#include <sys/stat.h>

typedef int (*SquashDirCallback)(void *user,const char *name, int type, int size);
int sq_mount(RFSRoot *root, ut64 delta);
int sq_dir(const char *path, SquashDirCallback cb, void *user);
unsigned char *sq_cat(const char *path, int *len);

static RFSFile *fs_squash_open(RFSRoot *root, const char *path) {
	int size = 0;
	unsigned char *buf = sq_cat (path, &size);
	if (buf) {
		RFSFile *file = r_fs_file_new (root, path);
		if (!file) {
			return NULL;
		}
		file->path = strdup (path);
		file->ptr = NULL;
		file->p = root->p;
		file->size = size;
		free (buf);
		return file;
	}
	return NULL;
}

static bool fs_squash_read(RFSFile *file, ut64 addr, int len) {
	int size = 0;
	unsigned char *buf = sq_cat (file->path, &size);
	if (buf) {
		file->data = buf;
		// file->size = size;
		return file;
	}
	return NULL;
}

static void fs_squash_close(RFSFile *file) {
	// free (file->data);
	file->data = NULL;
	// fclose (file->ptr);
}

static void append_file(RList *list, const char *name, int type, int time, ut64 size) {
	RFSFile *fsf = r_fs_file_new (NULL, name);
	if (!fsf) {
		return;
	}
	fsf->type = type;
	fsf->time = time;
	fsf->size = size;
	r_list_append (list, fsf);
}

typedef struct {
	RList *list;
	const char *path;
} SquashUser;

static int cb(void *user, const char *name, int type, int size) {
	SquashUser *su = user;
	if (!su || !su->path) {
		return 0;
	}
	if (!strncmp (name, su->path, strlen (su->path))) {
		name += strlen (su->path);
		if (*name == '/') {
			name++;
		}
	}
	if (*name && strchr (name, '/')) {
		return 0;
	}
	append_file (su->list, name, type, 0, size);
	return 1;
}

static RList *fs_squash_dir(RFSRoot *root, const char *path, int view /*ignored*/) {
	RList *list = r_list_new ();
	if (!list) {
		return NULL;
	}
	SquashUser su = { list, path };
	sq_dir (path, cb, &su);
	return list;
}

static int fs_squash_mount(RFSRoot *root) {
	root->ptr = NULL;
	return sq_mount (root, root->delta);
}

static void fs_squash_umount(RFSRoot *root) {
	root->ptr = NULL;
}

RFSPlugin r_fs_plugin_io = {
	.name = "squashfs",
	.desc = "SquashFS filesystem (XZ + LZMA)",
	.license = "GPL",
	.open = fs_squash_open,
	.read = fs_squash_read,
	.close = fs_squash_close,
	.dir = &fs_squash_dir,
	.mount = fs_squash_mount,
	.umount = fs_squash_umount,
};

#ifndef CORELIB
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_FS,
	.data = &r_fs_plugin_io,
	.version = R2_VERSION
};
#endif
