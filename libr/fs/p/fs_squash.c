/* radare - LGPL - Copyright 2016 - pancake */

#include <r_fs.h>
//#include <dirent.h>
#include <sys/stat.h>
#include "../squashfs/squashfs_fs.h"
#include "../squashfs/unsquashfs.h"
#include "../squashfs/xattr.h"

extern int fd;
extern int read_super(char *source);
extern int squashfs_readdir(struct dir *d, char **name, unsigned int *start_block, unsigned int *offset, unsigned int *type);
extern int squashfs_closedir(struct dir *d);
//struct dir *squashfs_opendir_4(unsigned int block_start, unsigned int offset, struct inode **i);

static RFSFile* fs_squash_open(RFSRoot *root, const char *path) {
	FILE *fd;
	RFSFile *file = r_fs_file_new (root, path);
	file->ptr = NULL;
	file->p = root->p;
eprintf ("squash-open %s\n", path);
	fd = r_sandbox_fopen (path, "r");
	if (fd) {
		fseek (fd, 0, SEEK_END);
		file->size = ftell (fd);
		fclose (fd);
	} else {
		r_fs_file_free (file);
		file = NULL;
	}
	return file;
}

static bool fs_squash_read(RFSFile *file, ut64 addr, int len) {
eprintf ("squash-read %s\n", file->path);
	free (file->data);
	file->data = (void*)r_file_slurp_range (file->name, 0, len, NULL);
	return true;
}

static void fs_squash_close(RFSFile *file) {
	//fclose (file->ptr);
}

static RList *fs_squash_dir(RFSRoot *root, const char *path, int view /*ignored*/) {
	unsigned int type;
	char *name;
	ut32 start_block = 0;
	ut32 offset = 0;
	struct inode *i = NULL;
	struct dir *d;
	RList *list;
struct super_block sBlk;

	list = r_list_new ();
// TODO: choose version
#if 0
	if (read_xattrs_from_disk (fd, &sBlk.s) == 0)
		EXIT_UNSQUASH ("failed to read the xattr table\n");
#endif
	start_block = SQUASHFS_INODE_BLK (sBlk.s.root_inode);
	offset = SQUASHFS_INODE_OFFSET (sBlk.s.root_inode);

eprintf ("-->\n");
	d = squashfs_opendir_4 (start_block, offset, &i);
	if (!d) return NULL;
	while (squashfs_readdir (d, &name, &start_block, &offset, &type)) {
		RFSFile *fsf = r_fs_file_new (NULL, name);
eprintf ("-> %s\n", name);
		fsf->type = (type == SQUASHFS_DIR_TYPE)? 'd': 'f';
		fsf->off = start_block;
		fsf->size = 1024; // ???
		fsf->time = 0;
		r_list_append (list, fsf);
	}
	squashfs_closedir (d);
	return list;
}

static int fs_squash_mount(RFSRoot *root) {
	char *path = NULL;
	if (root && root->iob.io && root->iob.io->desc) {
		path = strdup (root->iob.io->desc->uri);
	}
	fd = open (path, 0);
fprintf (stderr, "fd = %d\n", fd);
	if (read_super (path) == 0) {
		eprintf ("Error reading super block\n");
		return false;
	}
	root->ptr = NULL; // XXX: TODO
	free (path);
	return true;
}

static void fs_squash_umount(RFSRoot *root) {
	if (root) {
		root->ptr = NULL;
	}
}

struct r_fs_plugin_t r_fs_plugin_squash = {
	.name = "squash",
	.desc = "SQUASHFS (xz, gzip)",
	.open = fs_squash_open,
	.read = fs_squash_read,
	.close = fs_squash_close,
	.dir = &fs_squash_dir,
	.mount = fs_squash_mount,
	.umount = fs_squash_umount,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
        .type = R_LIB_TYPE_FS,
        .data = &r_fs_plugin_squash,
        .version = R2_VERSION
};
#endif
