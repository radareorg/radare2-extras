#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <r_core.h>
#include "sdb.h"

#include "dwarf.h"
#include "libdwarf.h"

static Sdb *s = NULL;
static int fd = -1;
static Dwarf_Debug dbg = 0;

// Current Output Format::
// name = offset_from_start_addr -- size -- value_for_name

/*
 * DW_DLV_NO_ENTRY -1
 * DW_DLV_OK 0
 * DW_DLV_ERROR 1
 *
 * TODO: check for return values
 */

//TODO: free all the possible dwarf variables
//TODO: print string instead of its address

char *data = NULL;

static int print_struct_or_union_die (Dwarf_Off offset, int indentlevel, Dwarf_Unsigned startaddr, int isStruct);
static int get_size (Dwarf_Die die, Dwarf_Unsigned *size, int *inbits);

static int get_type_die_offset (Dwarf_Die die, Dwarf_Off *offset, Dwarf_Error *error) {
	int res = DW_DLV_ERROR;
	Dwarf_Attribute attr = 0;

	res = dwarf_attr (die, DW_AT_type, &attr, error);
	if (res != DW_DLV_OK) {
		return res;
	}

	res = dwarf_global_formref (attr, offset, error);
	return res;
}

static int get_type_die (Dwarf_Die die, Dwarf_Die *typedie, Dwarf_Error *error) {
	int res = DW_DLV_ERROR;
	Dwarf_Off offset = 0;

	res = get_type_die_offset (die, &offset, error);
	if (res == DW_DLV_ERROR) {
		printf ("ERROR: get_type_die :: get_type_die_offset :: %d\n", __LINE__);
		return res;
	} else if (res == DW_DLV_NO_ENTRY) {
		return res;
	}

	res = dwarf_offdie (dbg, offset, typedie, error);
	return res;
}

static int get_type_tag (Dwarf_Die die, Dwarf_Half *tag, Dwarf_Error *error) {
	int res = DW_DLV_ERROR;
	Dwarf_Die typedie = 0;

	res = get_type_die (die, &typedie, error);
	if (res != DW_DLV_OK) {
		return res;
	}

	res = dwarf_tag (typedie, tag, error);
	return res;
}

static int get_num_from_attr (Dwarf_Attribute attr, Dwarf_Unsigned *val) {
	int res = DW_DLV_ERROR;
	Dwarf_Signed sval = 0;
	Dwarf_Unsigned uval = 0;

	res = dwarf_formudata (attr, &uval, NULL);
	if (res == DW_DLV_OK) {
		*val = uval;
		return res;
	}

	res = dwarf_formsdata (attr, &sval, NULL);
	if (res == DW_DLV_OK) {
		*val = (Dwarf_Unsigned)sval;
		return res;
	}

	return DW_DLV_ERROR;
}

/*
 * get_dwarf_diename
 * A wrapper around dwarf_diename to lookup at the typdef
 */
static int get_dwarf_diename (Dwarf_Die die, char **diename, Dwarf_Error *error) {
	int res = DW_DLV_ERROR;
	Dwarf_Half tag;
	Dwarf_Die typedie = 0;

	res = dwarf_diename (die, diename, error);
	if (res != DW_DLV_NO_ENTRY) {  // Return if error or OK
		return res;
	}

	res = get_type_tag (die, &tag, error);
	if (res != DW_DLV_OK || tag != DW_TAG_typedef) {
		return (res == DW_DLV_OK) ? DW_DLV_NO_ENTRY : res;
	}

	res = dwarf_diename (die, diename, error);
	return res;
}

static int get_array_length (Dwarf_Die die, Dwarf_Unsigned *len) {
	int res = DW_DLV_ERROR;
	Dwarf_Half tag = 0;
	Dwarf_Attribute attr = 0;
	Dwarf_Die child = 0;
	Dwarf_Die sibdie = 0;

	*len = 1;

	res = dwarf_child (die, &child, NULL);
	if (res == DW_DLV_ERROR) {
		printf ("ERROR: get_array_length :: dwarf_child :: %d\n", __LINE__);
		return res;
	} else if (res == DW_DLV_NO_ENTRY) {
		*len = 0;
		return DW_DLV_ERROR;
	}

	while (res != DW_DLV_NO_ENTRY) {
		Dwarf_Unsigned temp_len = 0;
		res = dwarf_tag (child, &tag, NULL);
		if (res == DW_DLV_ERROR) {
			printf ("ERROR: get_array_length :: dwarf_tag :: %d\n", __LINE__);
			return res;
		}

		if (tag == DW_TAG_subrange_type) {
			res = dwarf_attr (child, DW_AT_count, &attr, NULL);
			if (res == DW_DLV_ERROR) {
				printf ("ERROR: get_array_length :: dwarf_attr :: %d\n", __LINE__);
				return res;
			} else if (res == DW_DLV_OK) {
				res = get_num_from_attr (attr, &temp_len);
			    if (res != DW_DLV_OK) {
				    *len = 0;
					return res;
				}
			} else {
				res = dwarf_attr (child, DW_AT_upper_bound, &attr, NULL);
				if (res == DW_DLV_ERROR) {
					*len = 0;
					printf ("ERROR: get_array_length :: dwarf_attr :: %d\n", __LINE__);
					return DW_DLV_ERROR;
				} else if (res == DW_DLV_NO_ENTRY) {
					temp_len = 0;
					res = DW_DLV_OK;
				} else {
					res = get_num_from_attr (attr, &temp_len);
					if (res != DW_DLV_OK) {
						*len = 0;
						return DW_DLV_ERROR;
					}
				}
				temp_len += 1;
			}
		} else {
			printf ("[!] New tag found in array's child : %d\n", tag);
			*len = 0;
			return DW_DLV_ERROR;
		}

		*len *= temp_len;
		res = dwarf_siblingof (dbg, child, &sibdie, NULL);
		if (res == DW_DLV_ERROR) {
			printf ("ERROR: get_array_length :: dwarf_siblingof :: %d\n", __LINE__);
			*len = 0;
			return res;
		}
		dwarf_dealloc (dbg, child, DW_DLA_DIE);
		child = sibdie;
	}

	return DW_DLV_OK;
}

/*
 * get_size
 * RETURN size and set inbits flag accordingly
 */
static int get_size (Dwarf_Die die, Dwarf_Unsigned *size, int *inbits) {
	int res = DW_DLV_ERROR;
	Dwarf_Bool ret;
	Dwarf_Half tag;
	Dwarf_Off offset;
	Dwarf_Die typedie;
	Dwarf_Attribute attr;

	// Return size value if DW_AT_byte_size or DW_AT_bit_size entry, if present
	res = dwarf_bytesize (die, size, NULL);
	if (res == DW_DLV_ERROR) {
		printf ("ERROR: get_size::dwarf_bytesize::%d\n", __LINE__);
		return res;
	} else if (res == DW_DLV_OK) {
		*inbits = 0;
		return res;
	} else {
		res = dwarf_bitsize (die, size, NULL);
		if (res == DW_DLV_ERROR) {
			printf ("ERROR: get_size::dwarf_bitsize::%d\n", __LINE__);
			return res;
		} else if (res == DW_DLV_OK) {
			*inbits = 1;
			return res;
		}
	}

	/*** Return size value from their DW_AT_type tag ***/

	res = get_type_die (die, &typedie, NULL);
	if (res != DW_DLV_OK) {
		printf ("ERROR | NO_ENTRY: get_size::get_type_die::%d\n", __LINE__);
		return res;
	}

	tag = 0;
	res = dwarf_tag (typedie, &tag, NULL);
	if (res == DW_DLV_ERROR) {
		printf ("ERROR: get_size::dwarf_tag::%d\n", __LINE__);
		return res;
	}

	switch (tag) {
	case DW_TAG_base_type:
	case DW_TAG_pointer_type:
	case DW_TAG_enumeration_type:
		{
			// This is repetition from above. Can be made into a function
			res = dwarf_bytesize (typedie, size, NULL);
			if (res == DW_DLV_ERROR) {
				printf ("ERROR: get_size::dwarf_bytesize::%d\n", __LINE__);
				return res;
			} else if (res == DW_DLV_OK) {
				*inbits = 0;
				return res;
			} else {
				res = dwarf_bitsize (typedie, size, NULL);
				if (res == DW_DLV_ERROR) {
					printf ("ERROR: get_size::dwarf_bitsize::%d\n", __LINE__);
					return res;
				} else if (res == DW_DLV_OK) {
					*inbits = 1;
					return res;
				}
			}
		}
		break;
	case DW_TAG_array_type:
		{
			unsigned long long arrlength = 0;
			unsigned long long typesize = 0;
			int bits = 0;

			res = get_size (typedie, &typesize, &bits);
			if (res == DW_DLV_ERROR) {
				printf ("ERROR: %d\n", __LINE__);
				return res;
			}

			res = get_array_length (typedie, &arrlength);
			if (res == DW_DLV_ERROR) {
				printf ("ERROR: %d\n", __LINE__);
				return res;
			}

			*size = (arrlength * typesize);
			*inbits = bits;
			if (bits == 1 && (*size) % 8 == 0 ) {
				*inbits = 0;
				*size /= 8;
			}
		}
		break;
	case DW_TAG_typedef:
	case DW_TAG_const_type:
	case DW_TAG_union_type:
	case DW_TAG_volatile_type:
	case DW_TAG_structure_type:
		{
			res = get_size (typedie, size, inbits);
		}
		break;
	default:
		printf ("[*] NEW TAG found: get_size :: %d\n",tag);
	}
	return res;
}

static int print_value (Dwarf_Die die, char *data, Dwarf_Unsigned addr, int indentlevel, Dwarf_Unsigned size) {
	int res = DW_DLV_ERROR;
	Dwarf_Half tag = 0;

	res = get_type_tag (die, &tag, NULL);
	if (res == DW_DLV_ERROR) {
		printf ("ERROR: print_value::get_type_die::%d\n", __LINE__);
		return res;
	}

	switch (tag) {
	case DW_TAG_structure_type:
	case DW_TAG_union_type:
		{
			Dwarf_Off offset = 0;
			int isStruct = (tag == DW_TAG_structure_type) ? 1 : 0;
			int i;

			res = get_type_die_offset (die, &offset, NULL);
			if (res != DW_DLV_OK) {
				printf ("ERROR: print_value :: get_type_die_offset :: %d\n", __LINE__);
				return res;
			}
			printf (" {\n");
			res = print_struct_or_union_die (offset, indentlevel + 1, addr, isStruct);
			for (i = 0; i < indentlevel; i++) {
				printf ("  ");
			}
			printf ("}");
		}
		break;
	case DW_TAG_typedef:
	case DW_TAG_volatile_type:
	case DW_TAG_const_type:
		{
			Dwarf_Die typedie = 0;
			res = get_type_die (die, &typedie, NULL);
			if (res == DW_DLV_ERROR) {
				printf ("ERROR: print_value :: get_type_die :: %d\n", __LINE__);
				return res;
			}
			res = print_value (typedie, data, addr, indentlevel, size);
		}
		break;
	case DW_TAG_base_type:
	case DW_TAG_pointer_type:
	case DW_TAG_enumeration_type:
		res = DW_DLV_OK;
		if (size == 1) {
			printf ("0x%hhx", *(ut8 *)(data + addr));
		} else if (size == 2) {
			printf ("0x%hx", *(ut16 *)(data + addr));
		} else if (size == 4) {
			printf ("0x%x", *(ut32 *)(data + addr));
		} else if (size == 8) {
			printf ("0x%"PFMT64x"", *(ut64 *)(data + addr));
		} else {
			printf ("ERROR: print_value :: size = %llu", size);
		}
		break;
	case DW_TAG_array_type:
		printf ("PRINT RAW BYTES FROM MEMORY");// Lets do this :)
		break;
	default:
		printf ("[*] NEW TAG found: get_size :: %d\n",tag);
		break;
	}
	return res;
}

/*
 * TODO :: handle inbits value
 *
 * ofStrct means parent is struct (print member of struct)
 */
static int print_member (Dwarf_Die die, char *data, Dwarf_Unsigned startaddr, int indentlevel, int ofStruct) {
	int res = DW_DLV_ERROR;
	char *membername = NULL;
	Dwarf_Attribute attr = 0;
	Dwarf_Unsigned offset = 0;
	unsigned long long size = 0;
	int inbits = 0;
	int i = 0;

	//Get name
	res = get_dwarf_diename (die, &membername, NULL);
	if (res == DW_DLV_ERROR) {
		printf ("ERROR: print_member::get_dwarf_diename::%d\n", __LINE__);
		return res;
	}

	//Get size <-- not require since print_value is another function
	res = get_size (die, &size, &inbits);
	if (res == DW_DLV_ERROR) {
		printf ("ERROR: print_member::get_size::%d\n", __LINE__);
		return res;
	}

	if (ofStruct) {
		//Get data_member_location (byte offset from start)
		res = dwarf_attr (die, DW_AT_data_member_location, &attr, NULL);
		if (res == DW_DLV_ERROR) {
			printf ("ERROR: print_member::dwarf_attr::%d\n", __LINE__);
			return res;
		}

		res = get_num_from_attr (attr, &offset);
		if (res == DW_DLV_ERROR) {
			printf ("ERROR: print_member::get_num_from_attr::%d\n", __LINE__);
			return res;
		}
	}

	for (i = 0; i < indentlevel; i++) {
		printf ("  ");
	}
	printf ("%s = ", membername, offset+startaddr, size);
	print_value (die, data, offset+startaddr, indentlevel, size);
	return DW_DLV_OK;
}

static int print_struct_or_union_die (Dwarf_Off offset, int indentlevel, Dwarf_Unsigned startaddr, int isStruct) {
	int res = DW_DLV_ERROR;
	Dwarf_Die die = 0;
	Dwarf_Die member = 0;
	Dwarf_Die sibdie = 0;

	if (!offset) {
		printf ("ERROR: Invalid offset\n");
		return DW_DLV_ERROR;
	}

	res = dwarf_offdie (dbg, offset, &die, NULL);
	if (res != DW_DLV_OK) {
		return res;
	}

	/***** temporary add for memory read *****/
	if (indentlevel == 0) {
		int inbits = 0;
		unsigned long long size = 0;
		res = get_size (die, &size, &inbits);
		if (res != DW_DLV_OK) {
			printf ("ERROR: lulz :P  No\n");
			return DW_DLV_ERROR;
		}
		data = (char *)malloc (size + 10);
		if (!data) {
			printf ("Cannot malloc %d bytes\n", size + 10);
			return DW_DLV_ERROR;
		}
		int fd = open ("/dev/urandom", O_RDONLY);
		if (fd < 0) {printf ("nopety nope\n");return DW_DLV_ERROR;}
		res = read (fd, data, size+5);
		if (res == -1 || res != size+5) {
			printf ("nopety pope\n");return DW_DLV_ERROR;
		}
		close (fd);
	}

	res = dwarf_child (die, &member, NULL);
	if (res == DW_DLV_ERROR) {
		printf ("ERROR: print_struct_die :: dwarf_child\n");
		return res;
	}

	while (res != DW_DLV_NO_ENTRY) {
		print_member (member, data, startaddr, indentlevel, isStruct);
		res = dwarf_siblingof (dbg, member, &sibdie, NULL);
		if (res == DW_DLV_ERROR) {
			printf ("ERROR: print_struct_die :: dwarf_siblingof\n");
		}
		if (res == DW_DLV_NO_ENTRY) {
			printf ("\n");
			break;
		}
		printf (",\n");
		dwarf_dealloc (dbg, member, DW_DLA_DIE);
		member = sibdie;
	}

	if (indentlevel == 0) {
		free (data);
	}
	return DW_DLV_OK;
}


/* is_declaration
 * return 1 is DIE has DW_AT_declaration attribute
 * else return 0
 */
static int is_declaration (Dwarf_Die die) {
	int res = DW_DLV_ERROR;
	Dwarf_Half attr;
	Dwarf_Bool ret;

	attr = DW_AT_declaration;
	ret = 0;
	res = dwarf_hasattr (die, attr, &ret, NULL);
	if (res == DW_DLV_ERROR) {
		printf ("ERROR: is_declaration\n");
	}

	return ret;
}

/* store_die_offset
 * stores the struct name and its offset in Sdb if struct entry is not empty and not anon
 * Return Value:
 * 	-1: cannot retreive offset
 * 	 0: Success OR Empty struct entry
 * 	 1: Does not have name entry
 */
static int store_die_offset (Dwarf_Die die) {
	int res = DW_DLV_ERROR;
	char *diename = NULL;
	Dwarf_Off off;

	char offset[32] = {0};

	res = get_dwarf_diename (die, &diename, NULL);
	if (res == DW_DLV_ERROR || res == DW_DLV_NO_ENTRY) {
		return 1;
	}

	res = DW_DLV_ERROR;
	res = dwarf_dieoffset (die, &off, NULL);
	if (res == DW_DLV_ERROR) {
		printf ("ERROR: store_die_offset\n");
		return -1;
	}

	sdb_num_add (s, (const char *)diename, off, 0);

out:
	dwarf_dealloc (dbg, diename, DW_DLA_STRING);
	return 0;
}

/*
 * is_struct_type
 * if the tag of die has DW_TAG_structure_type, return 1 else return 0
 */
static int is_struct_type (Dwarf_Die die) {
	int res = DW_DLV_ERROR;
	Dwarf_Half tag;

	res = dwarf_tag (die, &tag, NULL);
	if (res == DW_DLV_ERROR) {
		printf ("ERROR: is_struct_type\n");
	}

	return (res == DW_DLV_OK && tag == DW_TAG_structure_type) ? 1 : 0;
}


/* First parse
 * > Parse through all the DIEs which are directly the child of CU
 * > Does not look at the child DIE's
 * > Store the struct names along with their DIE offset in sdb
 */
static int first_parse (Dwarf_Die in_die) {
	Dwarf_Die cur_die = in_die;
	Dwarf_Die child = 0;
	Dwarf_Die nextdie = 0;	//can be child or sibling
	int res = DW_DLV_ERROR;

	res = dwarf_child (cur_die, &nextdie, NULL);
	if (res == DW_DLV_ERROR) {
		printf ("Error: dwarf_child\n");
	} else if (res == DW_DLV_NO_ENTRY) {
		return 0;
	}

	cur_die = nextdie;
	while (1) {
		nextdie = 0;
		
		if (is_struct_type (cur_die) && !is_declaration (cur_die)) {
			store_die_offset (cur_die);
		}

		/*
		 * res = dwarf_child (cur_die, &child, NULL);
		 * if (res == DW_DLV_ERROR) {
		 * 	printf ("Error: dwarf_child, level %d\n", in_level);
		 * 	return -1;
		 * }
		 * if (res == DW_DLV_OK) {
		 * 	get_die_and_siblings (s, dbg, child, in_level+1);
		 * 	}
		 */

		res = dwarf_siblingof (dbg, cur_die, &nextdie, NULL);
		if (res == DW_DLV_ERROR) {
			printf ("Error: dwarf_siblingof\n");
			return -1;
		}
		if (res == DW_DLV_NO_ENTRY) {
			break;
		}

		if (cur_die != in_die) {
			dwarf_dealloc (dbg, cur_die, DW_DLA_DIE);
		}
		cur_die = nextdie;
	}

	if (cur_die != in_die) {
		dwarf_dealloc (dbg, cur_die, DW_DLA_DIE);
	}
	return 0;
}

static int read_cu_list () {
	int res;
	Dwarf_Half address_size = 0;
	Dwarf_Half version_stamp = 0;
	Dwarf_Unsigned abbrev_offset = 0;
	Dwarf_Unsigned next_cu_header = 0;
	Dwarf_Unsigned cu_header_length = 0;

	Dwarf_Die cu_die = 0;

	for (;;) {
		cu_die = 0;
		res = DW_DLV_ERROR;

		res = dwarf_next_cu_header (dbg, &cu_header_length, &version_stamp,
				&abbrev_offset, &address_size, &next_cu_header, NULL);
		if (res == DW_DLV_ERROR) {
			continue;
		}

		if (res == DW_DLV_NO_ENTRY) {
			return 0;
		}

		res = dwarf_siblingof (dbg, NULL, &cu_die, NULL);
		if (res == DW_DLV_ERROR) {
			printf ("Error in dwarf_siblingof on CU die\n");
			return 1;
		}

		if (res == DW_DLV_NO_ENTRY) {
			printf ("NO ENTRY! in dwarf_siblingof on CU die.\n");
			return -1;
		}

		//get_die_and_siblings (dbg, cu_die, 0);
		first_parse (cu_die);
		dwarf_dealloc (dbg, cu_die, DW_DLA_DIE);
	}
}

/*
 * int printdb (void *user, const char *key, const char *value) {
 * 	printf ("%s : %s\n", key, value);
 * }
 */

int main (int argc, char **argv) {
	int opt;
	
	/* SDB variables */
	char *dbname = "structinfo.db";
	char *symarg = NULL;

	/* DWARF variables */
	int res = DW_DLV_ERROR;
	Dwarf_Handler errhand = 0;
	Dwarf_Ptr errarg = 0;

	while ((opt = getopt (argc, argv, "d:s:")) != -1) {
		switch (opt) {
		case 'd':
			dbname = optarg;
			break;
		case 's':
			symarg = optarg;
			break;
		case ':':
			printf ("ERROR: \"%c\" requires an argument.\n", optopt);
			exit (1);
		case '?':
			printf ("ERROR: unrecognized option \"%c\"\n", optopt);
			exit (1);
		}
	}

	/* TODO: Use file as a database instead. Can be used to load later. */
	s = sdb_new0 ();

	fd = open (argv[optind], O_RDONLY);
	if (fd < 0) {
		return -1;
	}

	res = dwarf_init (fd, DW_DLC_READ, errhand, errarg, &dbg, NULL);
	if (res != DW_DLV_OK) {
		return -1;
	}

	res = read_cu_list ();
	if (res != 0) {
		return -1;
	}

	//sdb_foreach (s, printdb, NULL);
	if (symarg) {
		//printf ("%s : %llx\n", symarg, sdb_num_get (s, symarg, 0));
		// TODO: fix mem_start
		print_struct_or_union_die (sdb_num_get (s, symarg, 0), 0 /*mem_start*/, 0, 1);
	}

	res = dwarf_finish (dbg, NULL);
	if (res != DW_DLV_OK) {
		printf ("dwarf_finish failed\n");
	}

	sdb_close (s);
	close (fd);
	return 0;
}

static const char* getargpos (const char *buf, int pos) {
	int i;
	for (i = 0; buf && i < pos; i++) {
		buf = strchr (buf, ' ');
		if (!buf) {
			break;
		}
		buf = r_str_ichr ((char *) buf, ' ');
	}
	return buf;
}

static ut64 getvalue (const char *buf, int pos) {
    ut64 ret;
	buf = getargpos (buf, pos);
	if (buf) {
		ret = strtoull (buf, 0, 0);
	} else {
		ret = -1;
	}
	return ret;
}

static int r_cmd_dwarf_init (void *user, const char *input) {
	if (!input) {
		return -1;
	}

	int res = DW_DLV_ERROR;
	Dwarf_Handler errhand = 0;
	Dwarf_Ptr errarg = 0;

	s = sdb_new0 ();

	fd = open (input, O_RDONLY);
	if (fd < 0) {
		return -1;
	}

	res = dwarf_init (fd, DW_DLC_READ, errhand, errarg, &dbg, NULL);
	if (res != DW_DLV_OK) {
		return -1;
	}

	res = read_cu_list (dbg);
	if (res != 0) {
		return -1;
	}

	return 0;
}

static int r_cmd_dwarf_call (void *user, const char *input) {
	const char *arg1 = getargpos (input, 1);
	const char *arg2 = getargpos (input, 2);
	const char *init = "init";

	if (!arg1) {
		printf ("DWARF: invalid command\n");
		return 0;
	}

	if (fd == -1) {
		if (arg1 && arg2) {
			if (!strncmp (arg1, init, 4)) {
				return r_cmd_dwarf_init (user, arg2);
			}
		}
		printf ("DWARF: sdb not initialised. Run: dwarf init filename\n");
		return 0;
	}

	if (!strncmp (arg1, init, 4)) {
		printf ("DWARF: don't do this to me. leave me alone.\n");
		return 0;
	}

	RCore *core = (RCore *) user;
	int res = DW_DLV_ERROR;
    char *structname = NULL;
	char *temp = NULL;
	unsigned long addr = 0;

	structname = strdup (arg1);
	temp = strchr (structname, ' ');
	if (temp) {
		*temp = 0;
	}
	addr = getvalue (input, 2);
	if (addr == -1) {
		addr = core->offset;
	}

	res = print_struct_or_union_die (sdb_num_get (s, structname, 0), 0, addr, 1);
	if (res != DW_DLV_OK) {
		printf ("Error while printing structure\n");
	}

	free (structname);
	return res;
}

static int r_cmd_dwarf_deinit () {
	int res = DW_DLV_ERROR;

	res = dwarf_finish (dbg, NULL);
	if (res != DW_DLV_OK) {
		printf ("dwarf_finish failed\n");
	}

	sdb_close (s);
	close (fd);
	return 0;
}

RCorePlugin r_core_plugin_dwarf = {
	.name = "dwarf",
	.desc = "DWARF",
	.license = "gpl",
	.call = r_cmd_dwarf_call,
	//.init = r_cmd_dwarf_init,
	.deinit = r_cmd_dwarf_deinit
};

#ifndef CORELIB
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_CORE,
	.data = &r_core_plugin_dwarf,
	.version = R2_VERSION
};
#endif
