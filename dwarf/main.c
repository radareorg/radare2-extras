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

/*
 * DW_DLV_NO_ENTRY -1
 * DW_DLV_OK 0
 * DW_DLV_ERROR 1
 *
 * TODO: check for return values
 */

//TODO: print string instead of its address

//char *data = NULL;

#define NRM_FORMAT  0
#define JSON_FORMAT 1
#define C_FORMAT    2

static int print_struct_or_union_die (RCore *core, Dwarf_Off offset, int indentlevel, Dwarf_Unsigned startaddr, int isStruct, int type);
static int get_size (Dwarf_Die die, Dwarf_Unsigned *size, int *inbits);

static int get_type_die_offset (Dwarf_Die die, Dwarf_Off *offset, Dwarf_Error *error) {
	int res = DW_DLV_ERROR;
	Dwarf_Attribute attr = 0;

	res = dwarf_attr (die, DW_AT_type, &attr, error);
	if (res != DW_DLV_OK) {
		dwarf_dealloc (dbg, attr, DW_DLA_ATTR);
		return res;
	}

	res = dwarf_global_formref (attr, offset, error);
	dwarf_dealloc (dbg, attr, DW_DLA_ATTR);
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
		dwarf_dealloc (dbg, typedie, DW_DLA_DIE);
		return res;
	}

	res = dwarf_tag (typedie, tag, error);
	dwarf_dealloc (dbg, typedie, DW_DLA_DIE);
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

	res = get_type_die (die, &typedie, error);
	if (res == DW_DLV_ERROR) {
		printf ("ERROR: get_dwarf_diename :: get_type_die :: %d\n", __LINE__);
		dwarf_dealloc (dbg, typedie, DW_DLA_DIE);
		return res;
	}

	res = dwarf_diename (typedie, diename, error);
	dwarf_dealloc (dbg, typedie, DW_DLA_DIE);
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
		dwarf_dealloc (dbg, child, DW_DLA_DIE);
		return res;
	} else if (res == DW_DLV_NO_ENTRY) {
		*len = 0;
		dwarf_dealloc (dbg, child, DW_DLA_DIE);
		return DW_DLV_ERROR;
	}

	while (res != DW_DLV_NO_ENTRY) {
		Dwarf_Unsigned temp_len = 0;
		res = dwarf_tag (child, &tag, NULL);
		if (res == DW_DLV_ERROR) {
			printf ("ERROR: get_array_length :: dwarf_tag :: %d\n", __LINE__);
			dwarf_dealloc (dbg, child, DW_DLA_DIE);
			return res;
		}

		if (tag == DW_TAG_subrange_type) {
			res = dwarf_attr (child, DW_AT_count, &attr, NULL);
			if (res == DW_DLV_ERROR) {
				printf ("ERROR: get_array_length :: dwarf_attr :: %d\n", __LINE__);
				dwarf_dealloc (dbg, attr, DW_DLA_ATTR);
				dwarf_dealloc (dbg, child, DW_DLA_DIE);
				return res;
			} else if (res == DW_DLV_OK) {
				res = get_num_from_attr (attr, &temp_len);
			    if (res != DW_DLV_OK) {
				    *len = 0;
					dwarf_dealloc (dbg, attr, DW_DLA_ATTR);
					dwarf_dealloc (dbg, child, DW_DLA_DIE);
					return res;
				}
			} else {
				dwarf_dealloc (dbg, attr, DW_DLA_ATTR);
				res = dwarf_attr (child, DW_AT_upper_bound, &attr, NULL);
				if (res == DW_DLV_ERROR) {
					*len = 0;
					printf ("ERROR: get_array_length :: dwarf_attr :: %d\n", __LINE__);
					dwarf_dealloc (dbg, attr, DW_DLA_ATTR);
					dwarf_dealloc (dbg, child, DW_DLA_DIE);
					return DW_DLV_ERROR;
				} else if (res == DW_DLV_NO_ENTRY) {
					temp_len = 0;
					res = DW_DLV_OK;
				} else {
					res = get_num_from_attr (attr, &temp_len);
					if (res != DW_DLV_OK) {
						*len = 0;
						dwarf_dealloc (dbg, attr, DW_DLA_ATTR);
						dwarf_dealloc (dbg, child, DW_DLA_DIE);
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
			dwarf_dealloc (dbg, attr, DW_DLA_ATTR);
			dwarf_dealloc (dbg, child, DW_DLA_DIE);
			return res;
		}
		dwarf_dealloc (dbg, child, DW_DLA_DIE);
		child = sibdie;
	}

	dwarf_dealloc (dbg, child, DW_DLA_DIE);
	dwarf_dealloc (dbg, attr, DW_DLA_ATTR);
	return DW_DLV_OK;
}

/*
 * get_size
 * RETURN size and set inbits flag accordingly
 * TODO: Maybe have another function for getting size in bits (if DIE has attribute DW_AT_bit_size)
 */
static int get_size (Dwarf_Die die, Dwarf_Unsigned *size, int *inbits) {
	int res = DW_DLV_ERROR;
	Dwarf_Bool ret;
	Dwarf_Half tag;
	Dwarf_Off offset;
	Dwarf_Die typedie;

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
		dwarf_dealloc (dbg, typedie, DW_DLA_DIE);
		return res;
	}

	tag = 0;
	res = dwarf_tag (typedie, &tag, NULL);
	if (res == DW_DLV_ERROR) {
		printf ("ERROR: get_size::dwarf_tag::%d\n", __LINE__);
		dwarf_dealloc (dbg, typedie, DW_DLA_DIE);
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
				dwarf_dealloc (dbg, typedie, DW_DLA_DIE);
				return res;
			} else if (res == DW_DLV_OK) {
				*inbits = 0;
				dwarf_dealloc (dbg, typedie, DW_DLA_DIE);
				return res;
			} else {
				res = dwarf_bitsize (typedie, size, NULL);
				if (res == DW_DLV_ERROR) {
					printf ("ERROR: get_size::dwarf_bitsize::%d\n", __LINE__);
					dwarf_dealloc (dbg, typedie, DW_DLA_DIE);
					return res;
				} else if (res == DW_DLV_OK) {
					*inbits = 1;
					dwarf_dealloc (dbg, typedie, DW_DLA_DIE);
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
				dwarf_dealloc (dbg, typedie, DW_DLA_DIE);
				return res;
			}

			res = get_array_length (typedie, &arrlength);
			if (res == DW_DLV_ERROR) {
				printf ("ERROR: %d\n", __LINE__);
				dwarf_dealloc (dbg, typedie, DW_DLA_DIE);
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

static int print_value (RCore *core, Dwarf_Die die, Dwarf_Unsigned addr, int indentlevel, Dwarf_Unsigned size, int type) {
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

			if (type == NRM_FORMAT) {
				printf ("{\n");
			} else if (type == JSON_FORMAT) {
				//printf ("{");
			} else if (type == C_FORMAT) {
			    //TODO
			}
			res = print_struct_or_union_die (core, offset, indentlevel + 1, addr, isStruct, type);
			if (type == NRM_FORMAT) {
				for (i = 0; i < indentlevel; i++) {
					printf ("  ");
				}
				printf ("}");
			} else if (type == JSON_FORMAT) {
				//printf ("}");
			} else if (type == C_FORMAT) {
				//TODO
			}
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
				dwarf_dealloc (dbg, typedie, DW_DLA_DIE);
				return res;
			}
			res = print_value (core, typedie, addr, indentlevel, size, type);
			dwarf_dealloc (dbg, typedie, DW_DLA_DIE);
		}
		break;
	case DW_TAG_base_type:
	case DW_TAG_pointer_type:
	case DW_TAG_enumeration_type:
		if (type == JSON_FORMAT) {
			printf ("\"");
		}
		res = DW_DLV_OK;
		if (size == 1) {
			printf ("0x%hhx", *(ut8 *)(core->block + addr));
		} else if (size == 2) {
			printf ("0x%hx", *(ut16 *)(core->block + addr));
		} else if (size == 4) {
			printf ("0x%x", *(ut32 *)(core->block + addr));
		} else if (size == 8) {
			printf ("0x%"PFMT64x"", *(ut64 *)(core->block + addr));
		} else {
			printf ("ERROR: print_value :: size = %llu", size);
		}
		if (type == JSON_FORMAT) {
			printf ("\"");
		}
		break;
	case DW_TAG_array_type:
		//TODO: proper output for multidimensional array instead of printing it as linear array
		{
			int i;
			Dwarf_Die typedie = 0;
			ut64 arrlength = 0;
			ut64 typesize = 0;
			int inbits;
			res = get_type_die (die, &typedie, NULL);
			if (res == DW_DLV_ERROR) {
				printf ("ERROR: print_value :: get_type_die :: %d\n", __LINE__);
				dwarf_dealloc (dbg, typedie, DW_DLA_DIE);
				return res;
			}
			res = get_size (typedie, &typesize, &inbits);
			if (res == DW_DLV_ERROR) {
				printf ("ERROR: print_value :: get_size :: %d\n", __LINE__);
				dwarf_dealloc (dbg, typedie, DW_DLA_DIE);
				return res;
			}
			res = get_array_length (typedie, &arrlength);
			if (res == DW_DLV_ERROR) {
				printf ("ERROR: %d\n", __LINE__);
				dwarf_dealloc (dbg, typedie, DW_DLA_DIE);
				return res;
			}

			printf ("[");
			for (i = 0; i < arrlength; i++) {
				if (type == JSON_FORMAT) {
					printf ("\"");
				}
				if (typesize == 1) {
					printf ("0x%hhx", *(ut8 *)(core->block + addr));
				} else if (typesize == 2) {
					printf ("0x%hx", *(ut16 *)(core->block + addr));
				} else if (typesize == 4) {
					printf ("0x%x", *(ut32 *)(core->block + addr));
				} else if (typesize == 8) {
					printf ("0x%"PFMT64x, *(ut64 *)(core->block + addr));
				} else {
					printf ("ERROR: print_value :: size = %llu", typesize);
				}
				if (type == JSON_FORMAT) {
					printf ("\"");
				}
				if (i != arrlength - 1) {
					printf (", ");
				}
				addr += typesize;
			}
			printf ("]");
			dwarf_dealloc (dbg, typedie, DW_DLA_DIE);
		}
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
static int print_member_name (RCore *core, Dwarf_Die die, Dwarf_Unsigned startaddr, int indentlevel, int ofStruct, int type) {
	int res = DW_DLV_ERROR;
	char *membername = NULL;

	//Get name
	res = get_dwarf_diename (die, &membername, NULL);
	if (res == DW_DLV_ERROR) {
		printf ("ERROR: print_member_name::get_dwarf_diename::%d\n", __LINE__);
		dwarf_dealloc (dbg, membername, DW_DLA_STRING);
		return res;
	}

	if (type == NRM_FORMAT) {
		printf ("%s", membername);
	} else if (type == JSON_FORMAT) {
		printf ("\"%s\"", membername);
	} else if (type == C_FORMAT) {
		//TODO
	}
	dwarf_dealloc (dbg, membername, DW_DLA_STRING);
	return DW_DLV_OK;
}

/*
 * Type:
 **  0: normal
 **  1: json
 **  2: C-like format
 */
static int print_struct_or_union_die (RCore *core, Dwarf_Off offset, int indentlevel, Dwarf_Unsigned startaddr, int isStruct, int type) {
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
		dwarf_dealloc (dbg, die, DW_DLA_DIE);
		return res;
	}

	res = dwarf_child (die, &member, NULL);
	if (res == DW_DLV_ERROR) {
		printf ("ERROR: print_struct_die :: dwarf_child\n");
		dwarf_dealloc (dbg, die, DW_DLA_DIE);
		dwarf_dealloc (dbg, member, DW_DLA_DIE);
		return res;
	}

	if (type == JSON_FORMAT) {
		printf ("{");
	}
	while (res != DW_DLV_NO_ENTRY) {
		if (type == NRM_FORMAT) {
			int i;
			for (i = 0; i < indentlevel; i++) {
				printf ("  ");
			}
		}
		print_member_name (core, member, startaddr, indentlevel, isStruct, type);
		if (type == NRM_FORMAT) {
			printf (" = ");
		} else if (type == JSON_FORMAT) {
			printf (":");
		} else if (type == C_FORMAT) {
			//TODO
		}
		{
			Dwarf_Unsigned off = 0;
			Dwarf_Attribute attr = 0;
			ut64 size = 0;
			int inbits = 0;
			res = get_size (member, &size, &inbits);
			if (res == DW_DLV_ERROR) {
				printf ("ERROR: print_struct_or_union_die::get_size::%d\n", __LINE__);
				return res;
			}

			if (isStruct) {
				//Get data_member_location (byte offset from start)
				res = dwarf_attr (member, DW_AT_data_member_location, &attr, NULL);
				if (res == DW_DLV_ERROR || res == DW_DLV_NO_ENTRY) {
					printf ("ERROR: print_struct_or_union_die::dwarf_attr::%d\n", __LINE__);
					dwarf_dealloc (dbg, attr, DW_DLA_ATTR);
					return res;
				}

				res = get_num_from_attr (attr, &off);
				dwarf_dealloc (dbg, attr, DW_DLA_ATTR);
				if (res == DW_DLV_ERROR) {
					printf ("ERROR: print_struct_or_union_die::get_num_from_attr::%d\n", __LINE__);
					return res;
				}
			}
			print_value (core, member, startaddr + off, indentlevel, size, type);
		}

		res = dwarf_siblingof (dbg, member, &sibdie, NULL);
		if (res == DW_DLV_ERROR) {
			printf ("ERROR: print_struct_die :: dwarf_siblingof\n"); //TODO: should return from here?
		}
		if (res == DW_DLV_NO_ENTRY) {
			break;
		}
		printf (",");
		if (type != JSON_FORMAT) {
			printf ("\n");
		}
		dwarf_dealloc (dbg, member, DW_DLA_DIE);
		member = sibdie;
	}
	if (type == NRM_FORMAT) {
		printf ("\n");
	} else if (type == JSON_FORMAT) {
		printf ("}");
		if (indentlevel == 0) {
			printf ("\n");
		}
	}

	dwarf_dealloc (dbg, die, DW_DLA_DIE);
	dwarf_dealloc (dbg, member, DW_DLA_DIE);
	dwarf_dealloc (dbg, sibdie, DW_DLA_DIE);
	return DW_DLV_OK;
}

static int get_address_and_die (RCore *core, Dwarf_Die die, Dwarf_Unsigned startaddr, char *namestr, Dwarf_Die *retdie, ut64 *retaddr) {
	int res = DW_DLV_ERROR;
	Dwarf_Die member = 0;
	Dwarf_Die sibdie = 0;
	char *remain = namestr;
	int flag = 0;

	if (!namestr) {
		/*
		 * *retdie = die;
		 * *retaddr = startaddr;
		 *  return DW_DLV_OK;
		 */
		printf ("ERROR: get_address_and_die :: namestr is NULL :: %d\n", __LINE__);
		return DW_DLV_ERROR;
	}

	if (strlen (namestr) == 0) {
		*retaddr = startaddr;
		if (retdie) {
			*retdie = die;
		}
		return DW_DLV_OK;
	}

	res = dwarf_child (die, &member, NULL);
	if (res == DW_DLV_ERROR) {
		printf ("ERROR: get_address_and_die :: dwarf_child :: %d\n", __LINE__);
		return res;
	} else if (res == DW_DLV_NO_ENTRY) {
		Dwarf_Half tag = 0;
		res = get_type_tag (die, &tag, NULL);
		if (res != DW_DLV_OK) {
			printf ("ERROR: get_address_and_die :: get_type_tag :: %d\n", __LINE__);
			return res;
		}

		switch (tag) {
		case DW_TAG_structure_type:
		case DW_TAG_union_type:
		case DW_TAG_typedef:
		case DW_TAG_volatile_type:
		case DW_TAG_const_type:
			{
				Dwarf_Die typedie = 0;
				res = get_type_die (die, &typedie, NULL);
				if (res == DW_DLV_ERROR) {
					printf ("ERROR: get_address_and_die :: get_type_die :: %d\n", __LINE__);
					dwarf_dealloc (dbg, typedie, DW_DLA_DIE);
					return res;
				}

				res = get_address_and_die (core, typedie, startaddr, remain, retdie, retaddr);
				if (res != DW_DLV_OK) {
					printf ("ERROR | NO_ENTRY: get_address_and_die :: get_address_and_die :: %d\n", __LINE__);
				}

				if (typedie != *retdie) {
					dwarf_dealloc (dbg, typedie, DW_DLA_DIE);
				}
				return res;
			}
			break;
		case DW_TAG_pointer_type:
			printf ("woohoo!! not implemented\n");
			break;
		default:
			printf ("ERROR: get_address_and_die :: something new that is not implemented\n");
			break;
		}

		return DW_DLV_OK;
	} else {
		while (res != DW_DLV_NO_ENTRY) {
			char *diename = NULL;

			if (!flag) {
				remain = strchr (namestr, '.');
				if (remain) {
					flag = 1;
					*remain = 0;
					remain += 1;
				} else {
					flag = 1;
					remain = namestr + strlen (namestr);
				}
			}

			res = dwarf_diename (member, &diename, NULL);
			if (res == DW_DLV_ERROR) {
				printf ("ERROR: get_address_and_die :: dwarf_diename :: %d\n", __LINE__);
				return res;
			} else if (res == DW_DLV_OK) {
				if (!strcmp (diename, namestr)) {
					Dwarf_Bool ret = 0;
					Dwarf_Unsigned off = 0;
					Dwarf_Attribute attr = 0;

					flag = 0;
					namestr = remain;

					res = dwarf_hasattr (member, DW_AT_data_member_location, &ret, NULL);
					if (res == DW_DLV_ERROR) {
						printf ("ERROR: dwarf_hasattr :: %d\n", __LINE__);
						return res;
					}

					if (ret) {
						res = dwarf_attr (member, DW_AT_data_member_location, &attr, NULL);
						if (res != DW_DLV_OK) {
							printf ("ERROR: get_address_and_die :: dwarf_attr :: %d\n", __LINE__);
							dwarf_dealloc (dbg, attr, DW_DLA_ATTR);
							return res;
						}

						res = get_num_from_attr (attr, &off);
						dwarf_dealloc (dbg, attr, DW_DLA_ATTR);
						if (res == DW_DLV_ERROR) {
							printf ("ERROR: get_address_and_die :: get_num_from_attr :: %d\n", __LINE__);
							return res;
						}
					}
					res = get_address_and_die (core, member, startaddr + off, remain, retdie, retaddr);
					if (res != DW_DLV_OK) {
						printf ("ERROR | NO_ENTRY: get_address_and_die :: get_address_and_die :: %d\n", __LINE__);
						//return res;
					}

					return res;
				}
			}
			res = dwarf_siblingof (dbg, member, &sibdie, NULL);
			if (res == DW_DLV_ERROR) {
				printf ("ERROR: get_address_and_die :: dwarf_siblingof :: %d\n", __LINE__);
				return res;
			}
			//dwarf_dealloc (dbg, member, DW_DLA_DIE);
			member = sibdie;
		}
	}
	return res;
}

/*
 * Used to print when the input requires specific field from the struct. For example: abc.xyz
 */
static int print_specific_stuff (RCore *core, ut64 offset, Dwarf_Unsigned startaddr, char *remain, int onlyaddr) {
	int res = DW_DLV_ERROR;
	Dwarf_Die die = 0;
	Dwarf_Die member = 0;
	ut64 addr;
	ut64 size = 0;
	int inbits = 0;
	char *name;
	ut64 oldoffset = 0;
	ut64 oldblocksize = 0;

	if (!offset) {
		printf ("ERROR: Invalid offset\n");
		return DW_DLV_ERROR;
	}

	res = dwarf_offdie (dbg, offset, &die, NULL);
	if (res != DW_DLV_OK) {
		dwarf_dealloc (dbg, die, DW_DLA_DIE);
		return res;
	}

	res = dwarf_diename (die, &name, NULL);

	res = get_address_and_die (core, die, startaddr, remain, &member, &addr);
	if (res != DW_DLV_OK) {
		printf ("ERROR: _something_something_ :: get_address_and_die :: %d\n", __LINE__);
		printf ("res = %d\n", res);
		return res;
	}

	if (onlyaddr) {
		printf ("0x%"PFMT64x"\n", addr);
		return res;
	}

	res = get_size (member, &size, &inbits);
	if (res == DW_DLV_ERROR) {
		printf ("ERROR: print_struct_or_union_die::get_size::%d\n", __LINE__);
		return res;
	}

	oldoffset = core->offset;
	oldblocksize = core->blocksize;
	if (addr < core->offset || (addr + size) > (core->offset + core->blocksize)) {
		core->offset = addr;
		res = r_core_block_size (core, size);
		if (!res) {
			printf ("ERROR: r_core_block_size :: %d\n", __LINE__);
			return DW_DLV_ERROR;
		}
	}

	print_value (core, member, addr - core->offset, 0, size, NRM_FORMAT);
	printf ("\n");
	if (core->offset != oldoffset || core->blocksize != oldblocksize) {
		core->offset = oldoffset;
		core->blocksize = oldblocksize;
		r_core_block_size (core, oldblocksize);
	}
	return 0;
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

		first_parse (cu_die);
		dwarf_dealloc (dbg, cu_die, DW_DLA_DIE);
	}
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
		return false;
	}

	int res = DW_DLV_ERROR;
	Dwarf_Handler errhand = 0;
	Dwarf_Ptr errarg = 0;

	s = sdb_new0 ();

	fd = open (input, O_RDONLY);
	if (fd < 0) {
		return false;
	}

	res = dwarf_init (fd, DW_DLC_READ, errhand, errarg, &dbg, NULL);
	if (res != DW_DLV_OK) {
		close (fd);
		fd = -1;
		return false;
	}

	res = read_cu_list (dbg);
	if (res != 0) {
		close (fd);
		res = dwarf_finish (dbg, NULL);
		return false;
	}

	return true;
}

/*
 * r2 commands overwritten: idd, idda, iddi
 * Usage:
 *    idd structname[.abc.xyz] == ?:dwarf structname[.abc.xyz]
 *    idda structname[.abc.xyz] == ?:dwarfa structname[.abc.xyz]
 *    iddi filename == ?:dwarf init filename
 */
static int r_cmd_dwarf_call (void *user, const char *input) {
	const char *arg1 = getargpos (input, 1);
	const char *arg2 = getargpos (input, 2);
	const char *init = "init";
	int call1 = 0;
	int call2 = 0;

	if (!strncmp (input, "dwarf", 5)) {
		call1 = 1;
	}

	if (!strncmp (input, "idd", 3)) {
		call2 = 0;
	}

	//printf ("input = %s\n", input);
	if (!strncmp (input, "dwarf", 5) || !strncmp (input, "idd", 3)) {
		if (!arg1) {
			printf ("DWARF: invalid command\n");
			return false;
		}

		if (fd == -1) {
			if (call1) {
				if (arg1 && arg2) {
					if (!strncmp (arg1, init, 4)) {
						return r_cmd_dwarf_init (user, arg2);
					}
				}
			} else if (call2) {
				if (!strncmp (input, "iddi", 4) && arg1) {
					return r_cmd_dwarf_init (user, arg1);
				}
			}
			printf ("DWARF: sdb not initialised. Run: `?:dwarf init filename` OR `iddi filename`\n");
			return false;
		}

		if (!strncmp (arg1, init, 4)) {
			printf ("DWARF: don't do this to me. leave me alone.\n");
			return false;
		}

		RCore *core = (RCore *) user;
		int res = DW_DLV_ERROR;
		char *structname = NULL;
		char *temp = NULL;
		//char *temp1 = NULL;
		ut64 addr = 0;
		int inbits = 0;
		ut64 size = 0;
		Dwarf_Die die = NULL;
		ut64 oldblocksize = 0;
		ut64 oldoffset = 0;
		ut64 sdboffset = 0;
		int needaddr = 0;
		int type;

		type = NRM_FORMAT;
		if (call1) {
			char *t = NULL;
			t = strchr (input, ' ');
			if (t) {
				if (*(t-1) == 'j') {
					type = JSON_FORMAT;
				}
			}
			if (!strncmp (input+5, "a", 1)) {
				needaddr = 1;
			}
		} else if (call2) {
			char *t = NULL;
			t = strchr (input, ' ');
			if (t) {
				if (*(t-1) == 'j') {
					type = JSON_FORMAT;
				}
			}
		}

		structname = strdup (arg1);
		temp = strchr (structname, ' ');
		if (temp) {
			*temp = 0;
			if (arg2) {
				*(temp+1) = 0;
			}
		}

		temp = strchr (structname, '.');
		if (temp) {
			*temp = 0;
			temp += 1;

			sdboffset = sdb_num_get (s, structname, 0);
			if (sdboffset != 0) {
				addr = getvalue (input, 2);
				if (addr != -1) {
					oldoffset = core->offset;
					core->offset = addr;
				}

				res = dwarf_offdie (dbg, sdb_num_get (s, structname, 0), &die, NULL);
				if (res != DW_DLV_OK) {
					printf ("ERROR: dwarf_offdie %d\n", __LINE__);
					return false;
				}
				res = get_size (die, &size, &inbits);
				if (res != DW_DLV_OK) {
					printf ("ERROR: lulz :P No %d\n", __LINE__);
					return false;
				}

				oldblocksize = core->blocksize;
				if (r_core_block_size (core, size)) {
					res = print_specific_stuff (core, sdb_num_get (s, structname, 0), core->offset, temp, needaddr);
					if (res != DW_DLV_OK) {
						printf ("ERROR: _something_new_i_dont_know_ %d\n", __LINE__);
					}
				}

				if (addr != -1) {
					core->offset = oldoffset;
				}
				r_core_block_size (core, oldblocksize);
			}
		} else {
			sdboffset = sdb_num_get (s, structname, 0);
			if (sdboffset != 0) {
				addr = getvalue (input, 2);
				if (addr != -1) {
					oldoffset = core->offset;
					core->offset = addr;
				}

				res = dwarf_offdie (dbg, sdb_num_get (s, structname, 0), &die, NULL);
				if (res != DW_DLV_OK) {
					printf ("ERROR: dwarf_offdie %d\n", __LINE__);
					return false;
				}
				res = get_size (die, &size, &inbits);
				if (res != DW_DLV_OK) {
					printf ("ERROR: lulz :P  No %d\n", __LINE__);
					return false;
				}

				oldblocksize = core->blocksize;
				if (r_core_block_size (core, size)) {
					res = print_struct_or_union_die (core, sdb_num_get (s, structname, 0), 0, 0, 1, type);
					if (res != DW_DLV_OK) {
						printf ("Error while printing structure\n");
					}
				}

				if (addr != -1) {
					core->offset = oldoffset;
				}
				r_core_block_size (core, oldblocksize);
			}
		}

		free (structname);
		return res ? false : true;
	}
	return false;
}

static int r_cmd_dwarf_deinit () {
	int res = DW_DLV_ERROR;

	if (fd && dbg) {
		res = dwarf_finish (dbg, NULL);
		if (res != DW_DLV_OK) {
			printf ("dwarf_finish failed\n");
		}

		sdb_close (s);
		close (fd);
	}
	return true;
}

RCorePlugin r_core_plugin_dwarf = {
	.name = "dwarf",
	.desc = "DWARF",
	.license = "gpl",
	.call = r_cmd_dwarf_call,
	.deinit = r_cmd_dwarf_deinit
};

#ifndef CORELIB
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_CORE,
	.data = &r_core_plugin_dwarf,
	.version = R2_VERSION
};
#endif
