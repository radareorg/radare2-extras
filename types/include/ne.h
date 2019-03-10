// http://www.fileformat.info/format/exe/corion-ne.htm
// http://bytepointer.com/resources/win16_ne_exe_format_win3.0.htm

// at offset 0x200
struct ne_header {
	uint16_t magic; // "NE"
	uint8_t version_major;
	uint8_t version_minor;

	uint16_t entry_table_offset;
	uint16_t entry_table_length;
	uint32_t crc;

	uint8_t program_flags;

	uint8_t application_flags;

	uint8_t auto_data_segment_index;
	uint16_t initial_local_heap_size;
	uint16_t initial_stack_size;
	uint32_t entrypoint; // CS:IP

	uint16_t segment_count;
	uint16_t module_reference_count;
	uint16_t size_of_nonresident_names_table_in_bytes;
	uint16_t offset_of_segment_table;
	uint16_t offset_of_resource_table;
	uint16_t offset_of_resident_names_table;
	uint16_t offset_of_module_reference_table;
	uint16_t offset_of_imported_names_table;

	uint32_t nonresident_offset; // names table
	uint16_t moveable_entrypoints_count_in_entry_table;
	uint16_t file_alignment_size_shift_count;
	uint16_t number_of_resource_table_entries;
	uint8_t target_operating_system;
/*
		0 - unknown
		1 - OS/2
		2 - Windows
		3 - European MS-DOS 4.x
		4 - Windows 386
		5 - BOSS (Borland Operating System Services)
*/
	uint8_t other_os2_exe_flags;
	uint16_t offset_to_return_thunks_of_gangload_area;
	uint16_t offset_to_segment_reference_thunks_or_gangload_length;

	uint16_t minimum_code_swap_area;
	uint16_t expected_windows_version;
};
