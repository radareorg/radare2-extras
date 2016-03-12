/* radare - LGPL3 - Copyright 2016 - Matthieu (c0riolis) Tardy */

#ifndef PYC_H
#define PYC_H

#include <r_types.h>
#include "pyc_specs.h"

char *get_pyc_file_type(enum pyc_magic magic);
char *get_pyc_file_machine(enum pyc_magic magic);
bool check_magic(enum pyc_magic magic);

#endif
