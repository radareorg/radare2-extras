/* radare - LGPL3 - Copyright 2016 - Matthieu (c0riolis) Tardy */

#ifndef PYC_MAGIC_H
#define PYC_MAGIC_H

#include <r_types.h>

struct pyc_version {
	ut32 magic;
	char *version;
	char *revision;
};

struct pyc_version get_pyc_version(ut32 magic);

#endif
