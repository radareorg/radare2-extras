/* radare2 - LGPL - Copyright 2016 - Davis, Alex Kornitzer */

#include <r_util.h>

#include "mdmp.h"

ut64 r_bin_mdmp_get_baddr(struct r_bin_mdmp_obj *obj) {
	return (ut64)(obj->b->buf);
}

ut64 r_bin_mdmp_get_paddr(struct r_bin_mdmp_obj *obj, ut64 vaddr) {
	/* FIXME: Will only resolve exact matches, probably no need to fix as
	** this function will become redundant on the optimisation stage */
	struct minidump_memory_descriptor64 *memory;
	ut64 index, paddr = 0;
	RListIter *it;

	/* Loop through the memories sections looking for a match */
	index = obj->streams.memories64.base_rva;
	r_list_foreach (obj->streams.memories64.memories, it, memory) {
		if (vaddr == memory->start_of_memory_range) {
			paddr = index;
			break;
		}
		index += memory->data_size;
	}
	return paddr;
}

ut32 r_bin_mdmp_get_srwx(struct r_bin_mdmp_obj *obj, ut64 vaddr)
{
	bool found = false;
	struct minidump_memory_info *mem_info;
	RListIter *it;

	r_list_foreach (obj->streams.memory_infos, it, mem_info) {
		if (mem_info->allocation_base && vaddr == mem_info->base_address) {
			found = true;
			break;
		}
	}

	if (!found) return 0;

	/* FIXME: Have I got these mappings right, I am not sure I have!!! */

	switch (mem_info->protect) {
	case MINIDUMP_PAGE_READONLY:
		return R_BIN_SCN_READABLE;
	case MINIDUMP_PAGE_READWRITE:
		return R_BIN_SCN_READABLE | R_BIN_SCN_WRITABLE;
	case MINIDUMP_PAGE_EXECUTE:
		return R_BIN_SCN_EXECUTABLE;
	case MINIDUMP_PAGE_EXECUTE_READ:
		return R_BIN_SCN_EXECUTABLE | R_BIN_SCN_READABLE;
	case MINIDUMP_PAGE_EXECUTE_READWRITE:
		return R_BIN_SCN_EXECUTABLE | R_BIN_SCN_READABLE | R_BIN_SCN_WRITABLE;
	case MINIDUMP_PAGE_NOACCESS:
	case MINIDUMP_PAGE_WRITECOPY:
	case MINIDUMP_PAGE_EXECUTE_WRITECOPY:
	case MINIDUMP_PAGE_GUARD:
	case MINIDUMP_PAGE_NOCACHE:
	case MINIDUMP_PAGE_WRITECOMBINE:
	default:
		return 0;
	}
}

static void r_bin_mdmp_free_pe32_bin(void *pe_bin_) {
	struct Pe32_r_bin_mdmp_pe_bin *pe_bin = pe_bin_;
	if (pe_bin) {
		Pe32_r_bin_pe_free (pe_bin->bin);
		R_FREE (pe_bin);
	}
}

static void r_bin_mdmp_free_pe64_bin(void *pe_bin_) {
	struct Pe64_r_bin_mdmp_pe_bin *pe_bin = pe_bin_;
	if (pe_bin) {
		Pe64_r_bin_pe_free (pe_bin->bin);
		R_FREE (pe_bin);
	}
}

void r_bin_mdmp_free(struct r_bin_mdmp_obj *obj) {
	if (!obj) return;

	if (obj->streams.ex_threads) r_list_free (obj->streams.ex_threads);
	if (obj->streams.memories) r_list_free (obj->streams.memories);
	if (obj->streams.memories64.memories) r_list_free (obj->streams.memories64.memories);
	if (obj->streams.memory_infos) r_list_free (obj->streams.memory_infos);
	if (obj->streams.modules) r_list_free (obj->streams.modules);
	if (obj->streams.operations) r_list_free (obj->streams.operations);
	if (obj->streams.thread_infos) r_list_free (obj->streams.thread_infos);
	if (obj->streams.threads) r_list_free (obj->streams.threads);
	if (obj->streams.unloaded_modules) r_list_free (obj->streams.unloaded_modules);

	if (obj->pe32_bins) r_list_free (obj->pe32_bins);
	if (obj->pe64_bins) r_list_free (obj->pe64_bins);

	if (obj->kv) {
		sdb_free (obj->kv);
		obj->kv = NULL;
	}
	if (obj->b) {
		r_buf_free (obj->b);
		obj->kv = NULL;
	}
	R_FREE (obj);

	return;
}

static bool r_bin_mdmp_init_hdr(struct r_bin_mdmp_obj *obj) {
	obj->hdr = (struct minidump_header *)obj->b->buf;

	sdb_num_set (obj->kv, "mdmp.hdr.time_date_stamp", obj->hdr->time_date_stamp, 0);
	sdb_num_set (obj->kv, "mdmp.hdr.flags", obj->hdr->flags, 0);

	if (obj->hdr->number_of_streams == 0) {
		eprintf ("Warning: No streams present!\n");
		return false;
	}

	if (obj->hdr->stream_directory_rva < sizeof (struct minidump_header))
	{
		eprintf ("Error: RVA for directory resides in the header!\n");
		return false;
	}

	if (obj->hdr->check_sum) {
		eprintf ("TODO: Checksum present but needs validating!\n");
		return false;
	}

	return true;
}

static bool r_bin_mdmp_init_directory_entry(struct r_bin_mdmp_obj *obj, struct minidump_directory *entry) {
	int i;

	struct minidump_handle_operation_list *handle_operation_list;
	struct minidump_memory_list *memory_list;
	struct minidump_memory64_list *memory64_list;
	struct minidump_memory_info_list *memory_info_list;
	struct minidump_module_list *module_list;
	struct minidump_thread_list *thread_list;
	struct minidump_thread_ex_list *thread_ex_list;
	struct minidump_thread_info_list *thread_info_list;
	struct minidump_unloaded_module_list *unloaded_module_list;

	struct avrf_handle_operation *handle_operations;
	struct minidump_memory_descriptor *memories;
	struct minidump_memory_descriptor64 *memories64;
	struct minidump_memory_info *memory_infos;
	struct minidump_module *modules;
	struct minidump_thread *threads;
	struct minidump_thread_ex *ex_threads;
	struct minidump_thread_info *thread_infos;
	struct minidump_unloaded_module *unloaded_modules;

	/* We could confirm data sizes but a malcious MDMP will always get around
	** this! But we can ensure that the data is not outside of the file */
	if (entry->location.rva + entry->location.data_size > obj->b->length) {
		eprintf("ERROR: Size Mismatch - Stream data is larger than file size!\n");
		return false;
	}

	switch (entry->stream_type) {
	case THREAD_LIST_STREAM:
		/* TODO: Not yet fully parsed or utilised */
		thread_list = (struct minidump_thread_list *)(obj->b->buf + entry->location.rva);
		for (i = 0; i < thread_list->number_of_threads; i++) {
			threads = (struct minidump_thread *)(&(thread_list->threads));
			r_list_append (obj->streams.threads, &(threads[i]));
		}
		break;
	case MODULE_LIST_STREAM:
		module_list = (struct minidump_module_list *)(obj->b->buf + entry->location.rva);
		for (i = 0; i < module_list->number_of_modules; i++) {
			modules = (struct minidump_module *)(&(module_list->modules));
			r_list_append(obj->streams.modules, &(modules[i]));
		}
		break;
	case MEMORY_LIST_STREAM:
		memory_list = (struct minidump_memory_list *)(obj->b->buf + entry->location.rva);
		for (i = 0; i < memory_list->number_of_memory_ranges; i++) {
			memories = (struct minidump_memory_descriptor *)(&(memory_list->memory_ranges));
			r_list_append (obj->streams.memories, &(memories[i]));
		}
		break;
	case EXCEPTION_STREAM:
		/* TODO: Not yet fully parsed or utilised */
		obj->streams.exception = (struct minidump_exception_stream *)(obj->b->buf + entry->location.rva);
		break;
	case SYSTEM_INFO_STREAM:
		obj->streams.system_info = (struct minidump_system_info *)(obj->b->buf + entry->location.rva);
		break;
	case THREAD_EX_LIST_STREAM:
		/* TODO: Not yet fully parsed or utilised */
		thread_ex_list = (struct minidump_thread_ex_list *)(obj->b->buf + entry->location.rva);
		for (i = 0; i < thread_ex_list->number_of_threads; i++) {
			ex_threads = (struct minidump_thread_ex *)(&(thread_ex_list->threads));
			r_list_append (obj->streams.ex_threads, &(ex_threads[i]));
		}
		break;
	case MEMORY_64_LIST_STREAM:
		memory64_list = (struct minidump_memory64_list *)(obj->b->buf + entry->location.rva);
		obj->streams.memories64.base_rva = memory64_list->base_rva;
		for (i = 0; i < memory64_list->number_of_memory_ranges; i++) {
			memories64 = (struct minidump_memory_descriptor64 *)(&(memory64_list->memory_ranges));
			r_list_append (obj->streams.memories64.memories, &(memories64[i]));
		}
		break;
	case COMMENT_STREAM_A:
		/* TODO: Not yet fully parsed or utilised */
		obj->streams.comments_a = obj->b->buf + entry->location.rva;
		break;
	case COMMENT_STREAM_W:
		/* TODO: Not yet fully parsed or utilised */
		obj->streams.comments_w = obj->b->buf + entry->location.rva;
		break;
	case HANDLE_DATA_STREAM:
		/* TODO: Not yet fully parsed or utilised */
		obj->streams.handle_data = (struct minidump_handle_data_stream *)(obj->b->buf + entry->location.rva);
		break;
	case FUNCTION_TABLE_STREAM:
		/* TODO: Not yet fully parsed or utilised */
		obj->streams.function_table = (struct minidump_function_table_stream *)(obj->b->buf + entry->location.rva);
		break;
	case UNLOADED_MODULE_LIST_STREAM:
		/* TODO: Not yet fully parsed or utilised */
		unloaded_module_list = (struct minidump_unloaded_module_list *)(obj->b->buf + entry->location.rva);
		for (i = 0; i < unloaded_module_list->number_of_entries; i++) {
			unloaded_modules = (struct minidump_unloaded_module *)((ut8 *)&unloaded_module_list + sizeof (struct minidump_unloaded_module_list));
			r_list_append (obj->streams.unloaded_modules, &(unloaded_modules[i]));
		}
		break;
	case MISC_INFO_STREAM:
		/* TODO: Not yet fully parsed or utilised */
		obj->streams.misc_info.misc_info_1 = (struct minidump_misc_info *)(obj->b->buf + entry->location.rva);
		break;
	case MEMORY_INFO_LIST_STREAM:
		memory_info_list = (struct minidump_memory_info_list *)(obj->b->buf + entry->location.rva);
		for (i = 0; i < memory_info_list->number_of_entries; i++) {
			memory_infos = (struct minidump_memory_info *)((ut8 *)memory_info_list + sizeof (struct minidump_memory_info_list));
			r_list_append (obj->streams.memory_infos, &(memory_infos[i]));
		}
		break;
	case THREAD_INFO_LIST_STREAM:
		/* TODO: Not yet fully parsed or utilised */
		thread_info_list = (struct minidump_thread_info_list *)(obj->b->buf + entry->location.rva);
		for (i = 0; i < thread_info_list->number_of_entries; i++) {
			thread_infos = (struct minidump_thread_info *)((ut8 *)thread_info_list + sizeof (struct minidump_thread_info_list));
			r_list_append (obj->streams.thread_infos, &(thread_infos[i]));
		}
		break;
	case HANDLE_OPERATION_LIST_STREAM:
		/* TODO: Not yet fully parsed or utilised */
		handle_operation_list = (struct minidump_handle_operation_list *)(obj->b->buf + entry->location.rva);
		for (i = 0; i < handle_operation_list->number_of_entries; i++) {
			handle_operations = (struct avrf_handle_operation *)((ut8 *)handle_operation_list + sizeof (struct minidump_handle_operation_list));
			r_list_append (obj->streams.operations, &(handle_operations[i]));
		}

		break;
	case LAST_RESERVED_STREAM:
		/* TODO: Not yet fully parsed or utilised */
		break;
	case UNUSED_STREAM:
	case RESERVED_STREAM_0:
	case RESERVED_STREAM_1:
		/* Silently ignore reserved streams */
		break;
	default:
		eprintf ("WARNING: Invalid or unsupported enumeration encountered %i\n", entry->stream_type);
		return false;
	}
	return true;
}

static bool r_bin_mdmp_init_directory(struct r_bin_mdmp_obj *obj) {
	int i;
	ut8 *directory_base;
	struct minidump_directory *entry;

	directory_base = obj->b->buf + obj->hdr->stream_directory_rva;

	/* Parse each entry in the directory */
	for (i = 0; i < obj->hdr->number_of_streams; i++) {
		entry = (struct minidump_directory *)(directory_base + (i * sizeof (struct minidump_directory)));
		r_bin_mdmp_init_directory_entry (obj, entry);
	}

	return true;
}

static bool r_bin_mdmp_patch_pe_headers(RBuffer *pe_buf) {
	int i;
	Pe64_image_dos_header dos_hdr;
	Pe64_image_nt_headers nt_hdr;
	Pe64_image_section_header *section_hdrs;

	r_buf_read_at (pe_buf, 0, (ut8 *)&dos_hdr, sizeof (Pe64_image_dos_header));
	r_buf_read_at (pe_buf, dos_hdr.e_lfanew, (ut8 *)&nt_hdr, sizeof (Pe64_image_nt_headers));

	/* Patch RawData in headers */
	section_hdrs = (Pe64_image_section_header *)(pe_buf->buf + dos_hdr.e_lfanew + 4 + sizeof (Pe64_image_file_header) + nt_hdr.file_header.SizeOfOptionalHeader);
	for (i = 0; i < nt_hdr.file_header.NumberOfSections; i++) {
		section_hdrs[i].PointerToRawData = section_hdrs[i].VirtualAddress;
	}

	return true;
}

static int check_pe32_bytes(const ut8 *buf, ut64 length) {
	unsigned int idx;
	if (!buf) return false;
	if (length <= 0x3d)
		return false;
	idx = (buf[0x3c] | (buf[0x3d]<<8));
	if (length > idx+0x18+2)
		if (!memcmp (buf, "MZ", 2) && !memcmp (buf+idx, "PE", 2) && !memcmp (buf+idx+0x18, "\x0b\x01", 2))
			return true;
	return false;
}

static int check_pe64_bytes(const ut8 *buf, ut64 length) {
	int idx, ret = false;
	if (!buf || length <= 0x3d)
		return false;
	idx = buf[0x3c] | (buf[0x3d]<<8);
	if (length >= idx+0x20)
		if (!memcmp (buf, "MZ", 2) && !memcmp (buf+idx, "PE", 2) && !memcmp (buf+idx+0x18, "\x0b\x02", 2))
			ret = true;
	return ret;
}

static bool r_bin_mdmp_init_pe_bins(struct r_bin_mdmp_obj *obj) {
	ut64 paddr;
	struct minidump_module *module;
	struct Pe32_r_bin_mdmp_pe_bin *pe32_bin;
	struct Pe64_r_bin_mdmp_pe_bin *pe64_bin;
	RBuffer *buf;
	RListIter *it;

	r_list_foreach (obj->streams.modules, it, module) {
		if (!(paddr = r_bin_mdmp_get_paddr (obj, module->base_of_image))) {
			continue;
		}
		buf = r_buf_new_with_bytes (obj->b->buf + paddr, module->size_of_image);
		if (check_pe32_bytes (buf->buf, module->size_of_image)) {
			if (!(pe32_bin = R_NEW0 (struct Pe32_r_bin_mdmp_pe_bin))) {
				continue;
			}
			r_bin_mdmp_patch_pe_headers (buf);
			pe32_bin->vaddr = module->base_of_image;
			pe32_bin->paddr = paddr;
			pe32_bin->bin = Pe32_r_bin_pe_new_buf (buf);

			r_list_append (obj->pe32_bins, pe32_bin);
		} else if (check_pe64_bytes (buf->buf, module->size_of_image)) {
			if (!(pe64_bin = R_NEW0 (struct Pe64_r_bin_mdmp_pe_bin))) {
				continue;
			}
			r_bin_mdmp_patch_pe_headers (buf);
			pe64_bin->vaddr = module->base_of_image;
			pe64_bin->paddr = paddr;
			pe64_bin->bin = Pe64_r_bin_pe_new_buf (buf);

			r_list_append (obj->pe64_bins, pe64_bin);
		}
		r_buf_free (buf);
	}

	return true;
}

static int r_bin_mdmp_init(struct r_bin_mdmp_obj *obj) {
	if (!r_bin_mdmp_init_hdr (obj)) {
		eprintf ("Error: Failed to initialise header\n");
		return false;
	}

	if (!r_bin_mdmp_init_directory (obj)) {
		eprintf ("Error: Failed to initialise directory structures!\n");
		return false;
	}

	if (!r_bin_mdmp_init_pe_bins (obj)) {
		eprintf ("Error: Failed to initialise pe binaries!\n");
		return false;
	}

	return true;
}

struct r_bin_mdmp_obj *r_bin_mdmp_new_buf(struct r_buf_t *buf) {
	bool fail = false;
	struct r_bin_mdmp_obj *obj;

	obj = R_NEW0 (struct r_bin_mdmp_obj);
	obj->kv = sdb_new0 ();
	obj->b = r_buf_new ();
	obj->size = (ut32)buf->length;

	fail |= (!(obj->streams.ex_threads = r_list_new ()));
	fail |= (!(obj->streams.memories = r_list_new ()));
	fail |= (!(obj->streams.memories64.memories = r_list_new ()));
	fail |= (!(obj->streams.memory_infos = r_list_new ()));
	fail |= (!(obj->streams.modules = r_list_new ()));
	fail |= (!(obj->streams.operations = r_list_new ()));
	fail |= (!(obj->streams.thread_infos = r_list_new ()));
	fail |= (!(obj->streams.threads = r_list_new ()));
	fail |= (!(obj->streams.unloaded_modules = r_list_new ()));

	fail |= (!(obj->pe32_bins = r_list_newf (r_bin_mdmp_free_pe32_bin)));
	fail |= (!(obj->pe64_bins = r_list_newf (r_bin_mdmp_free_pe64_bin)));

	if (fail) {
		r_bin_mdmp_free (obj);
		return NULL;
	}

	if (!r_buf_set_bytes (obj->b, buf->buf, buf->length)) {
		r_bin_mdmp_free (obj);
		return NULL;
	}

	if (!r_bin_mdmp_init (obj)) {
		r_bin_mdmp_free (obj);
		return NULL;
	}

	return obj;
}
