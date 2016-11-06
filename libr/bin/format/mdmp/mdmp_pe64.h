/* radare2 - LGPL - Copyright 2016 - Davis, Alex Kornitzer */

#ifndef MDMP_PE64_H
#define MDMP_PE64_H

#define R_BIN_PE64 1

#undef MDMP_PE_H

#include "mdmp_pe.h"

#if 0
#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>

#include "pe/pe.h"

#include "mdmp_specs.h"

struct Pe64_r_bin_mdmp_pe_bin {
	ut64 vaddr;
	ut64 paddr;
	struct Pe64_r_bin_pe_obj_t *bin;
};


RList *Pe64_r_bin_mdmp_pe_get_entrypoint(struct Pe64_r_bin_mdmp_pe_bin *pe_bin);
RList *Pe64_r_bin_mdmp_pe_get_imports(struct Pe64_r_bin_mdmp_pe_bin *pe_bin);
RList *Pe64_r_bin_mdmp_pe_get_symbols(struct Pe64_r_bin_mdmp_pe_bin *pe_bin);
#endif

#endif /* MDMP_PE64_H */
