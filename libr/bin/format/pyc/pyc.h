/* radare - LGPL3 - Copyright 2016 - Matthieu (c0riolis) Tardy */

#ifndef PYC_H
#define PYC_H

#include <r_types.h>
#include <r_util.h>
#include <r_bin.h>
#include "pyc_magic.h"

bool pyc_get_sections(RList *sections, RBuffer *buf, ut32 magic);
ut64 pyc_get_entrypoint(ut32 magic);

#endif
