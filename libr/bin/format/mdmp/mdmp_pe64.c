/* radare2 - LGPL - Copyright 2016 - Davis, Alex Kornitzer */

#define R_BIN_PE64 1
#include "mdmp_pe.c"

#if 0
#include "mdmp_pe64.h"

RList *Pe64_r_bin_mdmp_pe_get_entrypoint(struct Pe64_r_bin_mdmp_pe_bin *pe_bin) {
	ut64 offset;
	struct r_bin_pe_addr_t *entry = NULL;
	RBinAddr *ptr = NULL;
	RList* ret;

	if (!(entry = PE_(r_bin_pe_get_entrypoint) (pe_bin->bin))) {
		return NULL;
	}

	if (!(ret = r_list_newf (free))) {
		return NULL;
	}

	if ((ptr = R_NEW0 (RBinAddr))) {
		offset = entry->vaddr;
		if (offset > pe_bin->vaddr) {
			offset -= pe_bin->vaddr;
		}
		ptr->paddr = offset + pe_bin->paddr;
		ptr->vaddr = offset + pe_bin->vaddr;
		ptr->type  = R_BIN_ENTRY_TYPE_PROGRAM;
		r_list_append (ret, ptr);
	}

	// TODO: TLS Callback
	// get TLS callback addresses
	//add_tls_callbacks (arch, ret);

	free (entry);

	return ret;
}

static void filter_import(ut8 *n) {
	int I;
	for (I = 0; n[I]; I++) {
		if (n[I] < 30 || n[I] >= 0x7f) {
			n[I] = 0;
			break;
		}
	}
}

RList *Pe64_r_bin_mdmp_pe_get_imports(struct Pe64_r_bin_mdmp_pe_bin *pe_bin) {
	int i;
	ut64 offset;
	struct r_bin_pe_import_t *imports = NULL;
	RBinImport *ptr = NULL;
	RBinReloc *rel;
	RList *ret, *relocs;

	if (!(imports = PE_(r_bin_pe_get_imports)(pe_bin->bin))) {
		return NULL;
	}
	if (!(ret = r_list_newf (free))) {
		return NULL;
	}
	if (!(relocs = r_list_new ())) {
		free (ret);
		return NULL;
	}
	relocs->free = free;
	pe_bin->bin->relocs = relocs;
	for (i = 0; !imports[i].last; i++) {
		if (!(ptr = R_NEW0 (RBinImport))) {
			break;
		}
		filter_import (imports[i].name);
		ptr->name = strdup ((char*)imports[i].name);
		ptr->bind = r_str_const ("NONE");
		ptr->type = r_str_const ("FUNC");
		ptr->ordinal = imports[i].ordinal;
		r_list_append (ret, ptr);

		if (!(rel = R_NEW0 (RBinReloc))) {
			break;
		}
#ifdef R_BIN_PE64
		rel->type = R_BIN_RELOC_64;
#else
		rel->type = R_BIN_RELOC_32;
#endif
		offset = imports[i].vaddr;
		if (offset > pe_bin->vaddr) {
			offset -= pe_bin->vaddr;
		}
		rel->additive = 0;
		rel->import = ptr;
		rel->addend = 0;
		rel->vaddr = offset + pe_bin->vaddr;
		rel->paddr = imports[i].paddr + pe_bin->paddr;
		r_list_append (relocs, rel);
	}
	free (imports);

	return ret;
}

RList *Pe64_r_bin_mdmp_pe_get_symbols(struct Pe64_r_bin_mdmp_pe_bin *pe_bin) {
	int i;
	ut64 offset;
	struct r_bin_pe_export_t *symbols = NULL;
	struct r_bin_pe_import_t *imports = NULL;
	RBinSymbol *ptr = NULL;
	RList* ret;

	if (!(ret = r_list_newf (free))) {
		return NULL;
	}

	/* TODO: Load symbol table from pdb file */
	if ((symbols = PE_(r_bin_pe_get_exports) (pe_bin->bin))) {
		for (i = 0; !symbols[i].last; i++) {
			if (!(ptr = R_NEW0 (RBinSymbol))) {
				break;
			}
			offset = symbols[i].vaddr;
			if (offset > pe_bin->vaddr) {
				offset -= pe_bin->vaddr;
			}
			ptr->name = strdup ((char *)symbols[i].name);
			ptr->forwarder = r_str_const ((char *)symbols[i].forwarder);
			ptr->bind = r_str_const ("GLOBAL");
			ptr->type = r_str_const ("FUNC");
			ptr->size = 0;
			ptr->vaddr = offset + pe_bin->vaddr;
			ptr->paddr = symbols[i].paddr + pe_bin->paddr;
			ptr->ordinal = symbols[i].ordinal;
			r_list_append (ret, ptr);
		}
		free (symbols);
	}

	if ((imports = PE_(r_bin_pe_get_imports) (pe_bin->bin))) {
		for (i = 0; !imports[i].last; i++) {
			if (!(ptr = R_NEW0 (RBinSymbol))) {
				break;
			}
			offset = imports[i].vaddr;
			if (offset > pe_bin->vaddr) {
				offset -= pe_bin->vaddr;
			}
			ptr->name = r_str_newf ("imp.%s", imports[i].name);
			ptr->bind = r_str_const ("NONE");
			ptr->type = r_str_const ("FUNC");
			ptr->size = 0;
			ptr->vaddr = offset + pe_bin->vaddr;
			ptr->paddr = imports[i].paddr + pe_bin->paddr;
			ptr->ordinal = imports[i].ordinal;
			r_list_append (ret, ptr);
		}
		free (imports);
	}
	return ret;
}
#endif
