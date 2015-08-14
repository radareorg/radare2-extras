/* radare - LGPL - Copyright 2015 - pancake */

#include "r_io.h"
#include "r_lib.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>

#include "../../../kdp/src/kdp-protocol.h"

typedef struct {
	int fd;
	ut8 *buf;
	ut32 size;
	ut64 offset;
} RIOKdp;

#define RIOKDP_FD(x) (((RIOKdp*)x->data)->fd)
#define RIOKDP_SZ(x) (((RIOKdp*)x->data)->size)
#define RIOKDP_BUF(x) (((RIOKdp*)x->data)->buf)
#define RIOKDP_OFF(x) (((RIOKdp*)x->data)->offset)

static int __write(RIO *io, RIODesc *fd, const ut8 *buf, int count) {
	if (!fd || !buf || count<0 || fd->data == NULL)
		return -1;
	if (RIOKDP_OFF (fd) > RIOKDP_SZ (fd))
		return -1;
	if (RIOKDP_OFF (fd) + count > RIOKDP_SZ (fd))
		count -= (RIOKDP_OFF (fd) + count-(RIOKDP_SZ (fd)));

	if (count > 0) {
		memcpy (RIOKDP_BUF (fd) + RIOKDP_OFF (fd), buf, count);
		RIOKDP_OFF (fd) += count;
		return count;
	}
	return -1;
}

static int __resize(RIO *io, RIODesc *fd, ut64 count) {
	ut8 * new_buf = NULL;
	if (fd == NULL || fd->data == NULL || count == 0)
		return -1;
	if (RIOKDP_OFF (fd) > RIOKDP_SZ (fd))
		return -1;
	new_buf = malloc (count);
	if (!new_buf) return -1;
	memcpy (new_buf, RIOKDP_BUF (fd), R_MIN(count, RIOKDP_SZ (fd)));
	if (count > RIOKDP_SZ (fd) )
		memset (new_buf+RIOKDP_SZ (fd), 0, count-RIOKDP_SZ (fd));

	free (RIOKDP_BUF (fd));
	RIOKDP_BUF (fd) = new_buf;
	RIOKDP_SZ (fd) = count;

	return count;
}

static int __read(RIO *io, RIODesc *fd, ut8 *buf, int count) {
	memset (buf, 0xff, count);
	if (fd == NULL || fd->data == NULL)
		return -1;
	if (RIOKDP_OFF (fd) > RIOKDP_SZ (fd))
		return -1;
	if (RIOKDP_OFF (fd) + count >= RIOKDP_SZ (fd))
		count = RIOKDP_SZ (fd) - RIOKDP_OFF (fd);
	memcpy (buf, RIOKDP_BUF (fd) + RIOKDP_OFF (fd), count);
	return count;
}

static int __close(RIODesc *fd) {
	RIOKdp *riom;
	if (fd == NULL || fd->data == NULL)
		return -1;
	riom = fd->data;
	free (riom->buf);
	riom->buf = NULL;
	free (fd->data);
	fd->data = NULL;
	fd->state = R_IO_DESC_TYPE_CLOSED;
	return 0;
}

static ut64 __lseek(RIO* io, RIODesc *fd, ut64 offset, int whence) {
	ut64 r_offset = offset;
	if (!fd || !fd->data)
		return offset;
	switch (whence) {
	case SEEK_SET:
		r_offset = (offset <= RIOKDP_SZ (fd)) ? offset : RIOKDP_SZ (fd);
		break;
	case SEEK_CUR:
		r_offset = (RIOKDP_OFF (fd) + offset <= RIOKDP_SZ (fd)) ? RIOKDP_OFF (fd) + offset : RIOKDP_SZ (fd);
		break;
	case SEEK_END:
		r_offset = RIOKDP_SZ (fd);
		break;
	}
	RIOKDP_OFF (fd) = r_offset;
	return RIOKDP_OFF (fd);
}

static int __plugin_open(struct r_io_t *io, const char *pathname, ut8 many) {
	return (!strncmp (pathname, "kdp://", 6));
}

static RIODesc *__open(RIO *io, const char *pathname, int rw, int mode) {
	if (__plugin_open (io, pathname, 0)) {
		const char *hostport = pathname + 6;
		RIOKdp *mal = R_NEW (RIOKdp);
		mal->fd = -2; /* causes r_io_desc_new() to set the correct fd */
		eprintf ("HOST:PORT = %s", hostport);
		//mal->sock = r_socket_new();
		mal->size = strlen (pathname);
		mal->buf = malloc (mal->size+1);
		mal->offset = 0;
		memset (mal->buf, 0, mal->size);
		mal->size = r_hex_str2bin (hostport, mal->buf);
		if ((int)mal->size<1) {
			free (mal->buf);
			mal->buf = NULL;
		}
		if (mal->buf != NULL) {
			RETURN_IO_DESC_NEW (&r_io_plugin_kdp,
				mal->fd, pathname, rw, mode,mal);
		}
		eprintf ("Cannot connect to %s\n", hostport);
		free (mal);
	}
	return NULL;
}

struct r_io_plugin_t r_io_plugin_kdp = {
	.name = "kdp",
	.desc = "XNU's Kernel Debugger Protocol",
	.license = "GPL2", // because of GDB sauces
	.open = __open,
	.close = __close,
	.read = __read,
	.plugin_open = __plugin_open,
	.lseek = __lseek,
	.write = __write,
	.resize = __resize,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_IO,
	.data = &r_io_plugin_kdp,
	.version = R2_VERSION
};
#endif
