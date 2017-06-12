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

#define NRM_FORMAT  0
#define JSON_FORMAT 1
#define C_FORMAT    2

#define NONE_DEF     0
#define TYPEDEF_DEF  1
#define CONST_DEF    2
#define VOLATILE_DEF 4
#define POINTER_DEF  8
#define ENUM_DEF     16

#define DEBUG_MODE 1


static Dwarf_Debug dbg = 0;
static Sdb *s = NULL;
static int fd = -1;

//baseoff in below two is ignored unless type == (JSON_FORMAT | C_FORMAT) == 3
static int print_struct_or_union_die (RCore *core, Dwarf_Off offset, int indentlevel, Dwarf_Unsigned startaddr, int baseoff, int isStruct, int type, int longlist, int printmemberonly);
static int print_value (RCore *core, Dwarf_Die die, Dwarf_Unsigned addr, int baseoff, int indentlevel, int type, int flags);

void print_error (const char *str, int line) {
	if (DEBUG_MODE) {
		printf ("ERROR: %s :: %d\n", str, line);
	}
}

/* is_declaration
 * return 1 is DIE has DW_AT_declaration attribute
 * else return 0
 */
static int is_declaration (Dwarf_Die die) {
	int res = DW_DLV_ERROR;
	Dwarf_Bool ret;

	ret = 0;
	res = dwarf_hasattr (die, DW_AT_declaration, &ret, NULL);
	if (res == DW_DLV_ERROR) {
		print_error ("is_declaration", __LINE__);
	}

	return ret;
}

/* get_type_die_offset
 * Helper function to retrieve DIE offset for the type DW_AT_type entry of DIE
 * Return Value following the standard
 */
static int get_type_die_offset (Dwarf_Die die, Dwarf_Off *offset, Dwarf_Error *error) {
	int res = DW_DLV_ERROR;
	Dwarf_Attribute attr = 0;

	if (!offset) {
		return res;
	}

	res = dwarf_attr (die, DW_AT_type, &attr, error);
	if (res != DW_DLV_OK) {
		dwarf_dealloc (dbg, attr, DW_DLA_ATTR);
		return res;
	}

	res = dwarf_global_formref (attr, offset, error);
	dwarf_dealloc (dbg, attr, DW_DLA_ATTR);
	return res;
}

/* get_type_die
 * Helper function to extract the typedie at the offset mentioned in the DW_AT_type attribute of DIE
 */
static int get_type_die (Dwarf_Die die, Dwarf_Die *typedie, Dwarf_Error *error) {
	int res = DW_DLV_ERROR;
	Dwarf_Off offset = 0;

	if (!typedie) {
		return res;
	}

	res = get_type_die_offset (die, &offset, error);
	if (res == DW_DLV_ERROR) {
		print_error (" ", __LINE__);
		return res;
	} else if (res == DW_DLV_NO_ENTRY) {
		return res;
	}

	res = dwarf_offdie (dbg, offset, typedie, error);
	return res;
}

/* get_type_tag_and_die
 * Helper function to get type die and its tag. typedie is optional (can be NULL)
 */
static int get_type_tag_and_die (Dwarf_Die die, Dwarf_Half *tag, Dwarf_Die *typedie, Dwarf_Error *error) {
	int res = DW_DLV_ERROR;
	Dwarf_Die type_die;

	if (!tag) {
		return res;
	}

	res = get_type_die (die, &type_die, error);
	if (res != DW_DLV_OK) {
		dwarf_dealloc (dbg, typedie, DW_DLA_DIE);
		return res;
	}

	res = dwarf_tag (type_die, tag, error);
	if (typedie) {
		*typedie = type_die; // Dwarf_Die is a pointer to struct
	} else {
		dwarf_dealloc (dbg, typedie, DW_DLA_DIE);
	}
	return res;
}

/* get_num_from_attr
 * get the value stored in the attribute attr passed as argument
 * Return Value:
 *   DW_DLV_OK: Success
 *   DW_DLV_ERROR: Error
 */
static int get_num_from_attr (Dwarf_Attribute attr, Dwarf_Unsigned *val, Dwarf_Error *error) {
	int res = DW_DLV_ERROR;
	Dwarf_Signed sval = 0;
	Dwarf_Unsigned uval = 0;

	res = dwarf_formudata (attr, &uval, error);
	if (res ==  DW_DLV_OK) {
		*val = uval;
		return res;
	}

	res = dwarf_formsdata (attr, &sval, error);
	if (res == DW_DLV_OK) {
		*val = (Dwarf_Unsigned) sval;
		return res;
	}

	return DW_DLV_ERROR;
}

/* get_dwarf_diename
 * Wrapper around dwarf_diename to look for typedef entries in case no name entry available in DIE
 * Return Value is as normal, i.e.: DW_DLV_OK, DW_DLV_ERROR and DW_DLV_NO_ENTRY
 */
static int get_dwarf_diename (Dwarf_Die die, char **diename, Dwarf_Error *error) {
	int res = DW_DLV_ERROR;
	Dwarf_Half tag = 0;
	Dwarf_Die typedie = 0;

	// Look using dwarf_diename
	res = dwarf_diename (die, diename, error);
	if (res != DW_DLV_NO_ENTRY) {
		return res;
	}

	// Check for typedef entry in DIE type. If found, use that name
	res = get_type_tag_and_die (die, &tag, &typedie, error);
	if (res != DW_DLV_OK || tag != DW_TAG_typedef) {
		dwarf_dealloc (dbg, typedie, DW_DLA_DIE);
		return (res == DW_DLV_OK) ? DW_DLV_NO_ENTRY : res;
	}

	/*
	 * res = get_type_die (die, &typedie, error);
	 * if (res == DW_DLV_ERROR) {
	 * 	  print_error (" ", __LINE__);
	 * 	  goto out;
	 * }
	 */

	res = dwarf_diename (typedie, diename, error);
 out:
	dwarf_dealloc (dbg, typedie, DW_DLA_DIE);
	return res;
}

/*
 *
 */
static int get_array_dimension (Dwarf_Die die, RList *l) {
	int res = DW_DLV_ERROR;
	Dwarf_Half tag = 0;
	Dwarf_Attribute attr = 0;
	Dwarf_Die child = 0;
	Dwarf_Die sibdie = 0;

	res = dwarf_child (die, &child, NULL);
	if (res != DW_DLV_OK) {
		if (res == DW_DLV_ERROR) {
			print_error (" ", __LINE__);
		}
		dwarf_dealloc (dbg, child, DW_DLA_DIE);
		return res;
	}

	while (res != DW_DLV_NO_ENTRY) {
		Dwarf_Unsigned temp_len = 0;
		attr = 0;
		res = dwarf_tag (child, &tag, NULL);
		if (res == DW_DLV_ERROR) {
			print_error (" ", __LINE__);
			dwarf_dealloc (dbg, child, DW_DLA_DIE);
			return res; // REALLY???
		}

		if (tag == DW_TAG_subrange_type) {
			res = dwarf_attr (child, DW_AT_count, &attr, NULL);
			if (res == DW_DLV_ERROR) {
				print_error (" ", __LINE__);
				goto errout;
			} else if (res == DW_DLV_OK) {
				res = get_num_from_attr (attr, &temp_len, NULL);
				if (res != DW_DLV_OK) {
					goto errout;
				}
			} else {
				dwarf_dealloc (dbg, attr, DW_DLA_ATTR);
				res = dwarf_attr (child, DW_AT_upper_bound, &attr, NULL);
				if (res == DW_DLV_ERROR) {
					print_error (" ", __LINE__);
					goto errout;
				} else if (res == DW_DLV_NO_ENTRY) {
					temp_len = 0; // XXX: actually the size is unknown and not 0
					res = DW_DLV_OK;
				} else if (res == DW_DLV_OK) {
					res = get_num_from_attr (attr, &temp_len, NULL);
					if (res != DW_DLV_OK) {
						goto errout;
					}
				}
				temp_len += 1;
			}
			dwarf_dealloc (dbg, attr, DW_DLA_ATTR);
		} else {
			printf ("[!] Possible DW_TAG_enumeration_type entry array's child\n");
			dwarf_dealloc (dbg, child, DW_DLA_DIE);
			return DW_DLV_ERROR;
		}

		{
			ut64 *len = malloc (8);
			*len = temp_len;
			r_list_append (l, len);
		}
		res = dwarf_siblingof (dbg, child, &sibdie, NULL);
		if (res == DW_DLV_ERROR) {
			print_error (" ", __LINE__);
			dwarf_dealloc (dbg, child, DW_DLA_DIE);
			dwarf_dealloc (dbg, sibdie, DW_DLA_DIE);
			return res;
		}
		dwarf_dealloc (dbg, child, DW_DLA_DIE);
		child = sibdie;
	}

	dwarf_dealloc (dbg, child, DW_DLA_DIE);
	return DW_DLV_OK;

 errout:
	dwarf_dealloc (dbg, attr, DW_DLA_ATTR);
	dwarf_dealloc (dbg, child, DW_DLA_DIE);
	return DW_DLV_ERROR;
}

/* get_size
 * TODO: handle if the size is in bits but since I don't have any example in mind, it is hard to test.
 *		hence I am not implementing it properly right now.
 */
static int get_size (Dwarf_Die die, Dwarf_Unsigned *size, int *inbits) {
	int res = DW_DLV_ERROR;
	Dwarf_Half tag = 0;
	Dwarf_Die typedie = NULL;

	// Return size value if DW_AT_byte_size or DW_AT_bit_size attribute present
	res = dwarf_bytesize (die, size, NULL);
	if (res == DW_DLV_ERROR) {
		print_error (" ", __LINE__);
		return res;
	} else if (res == DW_DLV_OK) {
		*inbits = 0;
		return res;
	}

	res = dwarf_bitsize (die, size, NULL);
	if (res == DW_DLV_ERROR) {
		print_error (" ", __LINE__);
		return res;
	} else if (res == DW_DLV_OK) {
		*inbits = 1;
		return res;
	}

	// Get type die and returns its size
	res = get_type_tag_and_die (die, &tag, &typedie, NULL);
	if (res != DW_DLV_OK) {
		print_error (" ", __LINE__);
		dwarf_dealloc (dbg, typedie, DW_DLA_DIE);
		return res;
	}

	switch (tag) {
	case DW_TAG_base_type:
	case DW_TAG_pointer_type:
	case DW_TAG_enumeration_type:
	case DW_TAG_typedef:
	case DW_TAG_const_type:
	case DW_TAG_union_type:
	case DW_TAG_volatile_type:
	case DW_TAG_structure_type:
	case DW_TAG_variable:
		res = get_size (typedie, size, inbits);
		dwarf_dealloc (dbg, typedie, DW_DLA_DIE);
		break;
	case DW_TAG_array_type:
		{
			RList *arr = r_list_new ();
			RListIter *iter;
			ut64 typesz = 0;
			ut64 totalelem = 1;
			ut64 listlen = 0;
			int in_bits = 0;
			ut64 *num = 0;

			res = get_size (typedie, &typesz, &in_bits);
			if (res == DW_DLV_ERROR) {
				print_error (" ", __LINE__);
				dwarf_dealloc (dbg, typedie, DW_DLA_DIE);
				return res;
			}

			res = get_array_dimension (typedie, arr);
			dwarf_dealloc (dbg, typedie, DW_DLA_DIE);
			if (res == DW_DLV_ERROR) {
				print_error (" ", __LINE__);
				r_list_free (arr);
				return res;
			}

			listlen = r_list_length (arr);
			r_list_foreach (arr, iter, num) {
				if (listlen == 1 && *num == 0) {
					totalelem = 0;
				} else if (*num == 0) {
					totalelem *= 1; // 0 because of some issue. This situation will produce wrong output
				} else {
					totalelem *= *num;
				}
			}

			*size = totalelem * typesz;
			*inbits = in_bits;
			break;
		}
	default:
		printf ("[*] NO METHOED DEFINED TO GET SIZE FOR TAG: %d\n", tag);
	}
	return DW_DLV_OK;
}

static int get_type_in_str (RList **l, Dwarf_Die die, char **nameref, int indentlevel, int type, int longlist) {
	int res = DW_DLV_ERROR;
	int typedieres = DW_DLV_ERROR;
	Dwarf_Half tag = 0;
	Dwarf_Die typedie = 0;

	res = dwarf_tag (die, &tag, NULL);
	if (res == DW_DLV_ERROR) {
		print_error (" ", __LINE__);
		return res;
	}

	typedieres = get_type_die (die, &typedie, NULL);
	if (typedieres == DW_DLV_ERROR) {
		print_error (" ", __LINE__);
	    goto out;
	}

	switch (tag) {
	case DW_TAG_base_type:
		{
			char *name = NULL;
			res = get_dwarf_diename (die, &name, NULL);
			if (res == DW_DLV_ERROR) {
				print_error (" ", __LINE__);
				dwarf_dealloc (dbg, name, DW_DLA_STRING);
				goto out;
			} else if (res == DW_DLV_NO_ENTRY) {
				*nameref = r_str_append (*nameref, "void ");
			} else {
				*nameref = r_str_appendf (*nameref, "%s ", name);
			}

			dwarf_dealloc (dbg, name, DW_DLA_STRING);
			break;
		}
	case DW_TAG_pointer_type:
		{
			if (typedieres == DW_DLV_NO_ENTRY) {
				*nameref = r_str_append (*nameref, "void *");
			} else {
				res = get_type_in_str (l, typedie, nameref, indentlevel, type, 0); // longlist == 1 may lead to infinite recursion since pointer to same struct is valid.
				if (res == DW_DLV_ERROR) {
					print_error (" ", __LINE__);
				    goto out;
				}

				*nameref = r_str_append (*nameref, "*");
			}

			break;
		}
	case DW_TAG_typedef:
		{
			char *name = NULL;

			res = get_dwarf_diename (die, &name, NULL);
			if (res == DW_DLV_ERROR) {
				print_error (" ", __LINE__);
				dwarf_dealloc (dbg, name, DW_DLA_STRING);
			    goto out;
			} else if (res == DW_DLV_NO_ENTRY) {
				if (typedieres == DW_DLV_OK) {
					res = get_type_in_str (l, typedie, nameref, indentlevel, type, longlist);
					if (res == DW_DLV_ERROR) {
						print_error (" ", __LINE__);
					    goto out;
					}
				} else {
					*nameref = r_str_append (*nameref, "void ");
				}
			} else {
				*nameref = r_str_appendf (*nameref, "%s ", name);
			}

			dwarf_dealloc (dbg, name, DW_DLA_STRING);
			break;
		}
	case DW_TAG_const_type:
	case DW_TAG_volatile_type:
		{
			if (tag == DW_TAG_const_type) {
				*nameref = r_str_append (*nameref, "const ");
			} else if (tag == DW_TAG_volatile_type) {
				*nameref = r_str_append (*nameref, "volatile ");
			}

			if (! *nameref) {
				print_error (" ", __LINE__);
			    res = DW_DLV_ERROR;
				goto out;
			}

			if (typedieres == DW_DLV_NO_ENTRY) {
				*nameref = r_str_append (*nameref, "void ");
			} else if (typedie == DW_DLV_OK) {
				res = get_type_in_str (l, typedie, nameref, indentlevel, type, longlist);
				if (res == DW_DLV_ERROR) {
					print_error (" ", __LINE__);
					goto out;
				}
			}

			break;
		}
	case DW_TAG_structure_type:
	case DW_TAG_union_type:
		{
		    char *name = NULL;
			int isStruct = (tag == DW_TAG_structure_type) ? 1 : 0;

			res = get_dwarf_diename (die, &name, NULL);
			if (res == DW_DLV_ERROR) {
				print_error (" ", __LINE__);
				dwarf_dealloc (dbg, name, DW_DLA_STRING);
				goto out;
			} else if (res == DW_DLV_NO_ENTRY || longlist) {
				if (type == (C_FORMAT | JSON_FORMAT)) {
					if (isStruct) {
						*nameref = r_str_append (*nameref, "struct ");
					} else {
						*nameref = r_str_append (*nameref, "union " );
					}
				} else {
					Dwarf_Off offset = 0;

					res = dwarf_dieoffset (die, &offset, NULL);
					if (res == DW_DLV_ERROR) {
						print_error (" ", __LINE__);
						goto out;
					}

					res = print_struct_or_union_die (NULL, offset, indentlevel, 0, 0, isStruct, type, longlist, 1);
					if (res == DW_DLV_ERROR) {
						print_error (" ", __LINE__);
						goto out;
					}

				    r_cons_printf (" ");
				}
			} else {
				if (isStruct) {
					*nameref = r_str_appendf (*nameref, "struct %s ", name);
				} else {
					*nameref = r_str_appendf (*nameref, "union %s ", name);
				}
			}

			dwarf_dealloc (dbg, name, DW_DLA_STRING);
			break;
		}
	case DW_TAG_array_type:
		{
			char *name = NULL;

			if (*l) { // Seems like an impossible case
				print_error (" ", __LINE__);
				res = DW_DLV_ERROR;
				goto out;
			}

			res = get_dwarf_diename (die, &name, NULL);
			if (res == DW_DLV_ERROR) {
				print_error (" ", __LINE__);
				dwarf_dealloc (dbg, name, DW_DLA_STRING);
				goto out;
			}

			if (res == DW_DLV_NO_ENTRY) {
				dwarf_dealloc (dbg, name, DW_DLA_STRING);

				if (typedieres == DW_DLV_NO_ENTRY) {
					*nameref = r_str_append (*nameref, "void ");
				} else if (typedieres == DW_DLV_OK) {
					res = get_type_in_str (l, typedie, nameref, indentlevel, type, longlist);
					if (res == DW_DLV_ERROR) {
						print_error (" ", __LINE__);
						goto out;
					}
				}
			} else {
				*nameref = r_str_appendf (*nameref, "%s ", name);
				dwarf_dealloc (dbg, name, DW_DLA_STRING);
			}

			*l = r_list_new ();
			res = get_array_dimension (die, *l);

			if (res == DW_DLV_ERROR) {
				r_list_free (*l);
				*l = NULL;
				goto out;
			}

			break;
		}
	case DW_TAG_enumeration_type:
		{
			char *name = NULL;

			res = get_dwarf_diename (die, &name, NULL);
			if (res == DW_DLV_ERROR) {
				print_error (" ", __LINE__);
				dwarf_dealloc (dbg, name, DW_DLA_STRING);
			    goto out;
			} else if (res == DW_DLV_NO_ENTRY) {
				dwarf_dealloc (dbg, name, DW_DLA_STRING);
				if (typedieres == DW_DLV_OK) {
					res = get_type_in_str (l, typedie, nameref, indentlevel, type, longlist);
					if (res == DW_DLV_ERROR) {
						print_error (" ", __LINE__);
					    goto out;
					}
				} else if (typedieres == DW_DLV_NO_ENTRY) {
					*nameref = r_str_append (*nameref, "void ");
				}
			} else if (res == DW_DLV_OK) {
				*nameref = r_str_appendf (*nameref, "%s ", name);
			}

			if (! *nameref) {
				print_error (" ", __LINE__);
			    res = DW_DLV_ERROR;
				goto out;
			}

			*nameref = r_str_append (*nameref, "enum ");
			break;
		}
	case DW_TAG_member:
	case DW_TAG_variable:
		{
			if (typedieres == DW_DLV_NO_ENTRY) {
				*nameref = r_str_append (*nameref, "void ");
			} else if (typedieres == DW_DLV_OK) {
				res = get_type_in_str (l, typedie, nameref, indentlevel, type, longlist);
				if (res == DW_DLV_ERROR) {
					print_error (" ", __LINE__);
					goto out;
				}
			}
			break;
		}
	case DW_TAG_subroutine_type:
		{
			*nameref = r_str_append (*nameref, "FUNC_PTR ");
			break;
		}
	default:
		eprintf ("[*] TAG not handled in get_type_in_str");
		break;
	}

	if (! *nameref) { // Find the error yourself xP
		print_error (" ", __LINE__);
		res = DW_DLV_ERROR;
		goto out;
	}

	res = DW_DLV_OK;
 out:
	dwarf_dealloc (dbg, typedie, DW_DLA_DIE);
	return res;
}

/*
 *
 */
static int get_address_and_die (RCore *core, Dwarf_Die die, Dwarf_Unsigned startaddr, char *namestr, Dwarf_Die *retdie, ut64 *retaddr, ut64 *retoff) {
	int res = DW_DLV_ERROR;
	Dwarf_Die member = 0;
	Dwarf_Die sibdie = 0;
	char *remain = namestr;
	int flag = 0;
	Dwarf_Unsigned off = 0;

	if (!namestr) {
		print_error (" ", __LINE__);
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
		print_error (" ", __LINE__);
		return res;
	} else if (res == DW_DLV_NO_ENTRY) {
		Dwarf_Half tag = 0;
		Dwarf_Die typedie = 0;

		Dwarf_Bool ret = 0;
		Dwarf_Unsigned off = 0;
		Dwarf_Attribute attr = 0;
		ut64 ptraddr = 0;
		ut64 typesize = 0;
		int inbits = 0;
		Dwarf_Die tmpdie = 0;

		res = get_type_tag_and_die (die, &tag, &typedie, NULL);
		if (res != DW_DLV_OK) {
			print_error (" ", __LINE__);
			dwarf_dealloc (dbg, typedie, DW_DLA_DIE);
			return res;
		}

		if (retoff && (st64)(*retoff) != -1) {
			res = dwarf_attr (die, DW_AT_data_member_location, &attr, NULL);
			if (res == DW_DLV_ERROR) {
				print_error (" ", __LINE__);
				dwarf_dealloc (dbg, typedie, DW_DLA_DIE);
				return res;
			} else if (res == DW_DLV_OK) {
				res = get_num_from_attr (attr, &off, NULL);
				if (res == DW_DLV_ERROR) {
					dwarf_dealloc (dbg, attr, DW_DLA_ATTR);
				}

				*retoff = *retoff + off;
			} else {
				off = 0;
			}
		}

		if (tag == DW_TAG_pointer_type) {
			if (retoff) {
				*retoff = (ut64)-1;
			}
			res = get_size (typedie, &typesize, &inbits);
			if (res == DW_DLV_ERROR) {
				print_error (" ", __LINE__);
				dwarf_dealloc (dbg, typedie, DW_DLA_DIE);
				return res;
			}

			if (typesize == 2) {
				startaddr = (ut64)*((ut16 *)(core->block + startaddr - core->offset));
			} else if (typesize == 4) {
				startaddr = (ut64)*((ut32 *)(core->block + startaddr - core->offset));
			} else if (typesize == 8) {
				startaddr = (ut64)*((ut64 *)(core->block + startaddr - core->offset));
			}
		}

		res = get_address_and_die (core, typedie, startaddr, remain, retdie, retaddr, retoff);
		if (res != DW_DLV_OK) {
			print_error (" ", __LINE__);
		}

		if (typedie != *retdie) {
			dwarf_dealloc (dbg, typedie, DW_DLA_DIE);
		}
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
				print_error (" ", __LINE__);
				return res;
			} else if (res == DW_DLV_OK) {
				if (!strcmp (diename, namestr)) {
					Dwarf_Bool ret = 0;
					Dwarf_Unsigned off = 0;
					Dwarf_Attribute attr = 0;

					flag = 0;
					namestr = remain;

					res = dwarf_attr (member, DW_AT_data_member_location, &attr, NULL);
					if (res == DW_DLV_ERROR) {
						print_error (" ", __LINE__);
						dwarf_dealloc (dbg, attr, DW_DLA_ATTR);
						dwarf_dealloc (dbg, diename, DW_DLA_STRING);
						return res;
					} else if (res == DW_DLV_OK) {
						res = get_num_from_attr (attr, &off, NULL);
						if (res == DW_DLV_ERROR) {
							dwarf_dealloc (dbg, attr, DW_DLA_ATTR);
							dwarf_dealloc (dbg, diename, DW_DLA_STRING);
						}
					} else {
						off = 0;
					}

					if (retoff && (st64)(*retoff) != -1) {
						*retoff = *retoff + off;
					}

					res = get_address_and_die (core, member, startaddr + off, remain, retdie, retaddr, retoff);
					if (res != DW_DLV_OK) {
						print_error (" ", __LINE__);
						//return res;
					}

					dwarf_dealloc (dbg, attr, DW_DLA_ATTR);
					dwarf_dealloc (dbg, diename, DW_DLA_STRING);
					break;
				}
			}

			res = dwarf_siblingof (dbg, member, &sibdie, NULL);
			if (res == DW_DLV_ERROR) {
				print_error (" ", __LINE__);
				dwarf_dealloc (dbg, sibdie, DW_DLA_DIE);
				return res;
			}

			dwarf_dealloc (dbg, member, DW_DLA_DIE);
			member = sibdie;
		}
	}

	return res;
}

/* load_globals
 * load the global variables and their address in memory
 * Return Value: (In the current version of code, return value is ignored)
 *   DW_DLV_OK: Success
 *   DW_DLV_ERROR: Error in traversing dwarf file
 *   DW_DLV_NO_ENTRY: compilation unit die passed as argument does not have any child
 */
static int load_globals (Dwarf_Die in_die) {
	int res = DW_DLV_ERROR;
	Dwarf_Die cur_die = in_die;
	Dwarf_Die nextdie = 0;

	res = dwarf_child (cur_die, &nextdie, NULL);
	if (res == DW_DLV_ERROR || res == DW_DLV_NO_ENTRY) {
		if (res == DW_DLV_ERROR) {
			print_error ("load_globals :: dwarf_child", __LINE__);
		}
		dwarf_dealloc (dbg, nextdie, DW_DLA_DIE);
		return res;
	}

	cur_die = nextdie;
	while (true) {
		Dwarf_Half tag = 0;
		nextdie = 0;

		res = dwarf_tag (cur_die, &tag, NULL);
		if (res == DW_DLV_ERROR) {
			print_error ("load_globals :: dwarf_tag", __LINE__);
			goto badres;
		}

		if (tag == DW_TAG_variable && !is_declaration (cur_die)) {
			Dwarf_Locdesc *locdesc = 0;
			Dwarf_Signed lcnt = 0;
			Dwarf_Bool ret = 0;
			Dwarf_Attribute attr = 0;

			res = dwarf_hasattr (cur_die, DW_AT_location, &ret, NULL);
			if (res == DW_DLV_ERROR) {
				print_error ("load_globals :: dwarf_hasattr", __LINE__);
				goto badres;
			}

			if (ret) {
				int i;
				ut64 size;
				int inbits;
				char *diename = NULL;

				res = dwarf_attr (cur_die, DW_AT_location, &attr, NULL);
				if (res != DW_DLV_OK) {
					dwarf_dealloc (dbg, attr, DW_DLA_ATTR);
					goto badres;
				}

				res = dwarf_loclist (attr, &locdesc, &lcnt, NULL);
				if (res != DW_DLV_OK) {
					dwarf_dealloc (dbg, attr, DW_DLA_ATTR);
					print_error ("load_globals :: dwarf_loclist", __LINE__);
					goto badres;
				}

				res = get_dwarf_diename (cur_die, &diename, NULL);
				if (res != DW_DLV_OK) {
					diename = "";
				}

				res = get_size (cur_die, &size, &inbits);
				if (res != DW_DLV_OK) {
					size = 0;
				}

				for (i = 0; i < lcnt; i++) {
					if (locdesc[i].ld_s->lr_atom == DW_OP_addr) {
						r_cons_printf ("f sym.%s %llu @ 0x%llx\n", diename, size, locdesc[i].ld_s->lr_number);
					}
				}

				if (strcmp (diename, "")) {
					dwarf_dealloc (dbg, diename, DW_DLA_STRING);
				}
				dwarf_dealloc (dbg, attr, DW_DLA_ATTR);
			}
		}
	badres:
		res = dwarf_siblingof (dbg, cur_die, &nextdie, NULL);
		if (res == DW_DLV_ERROR) {
			print_error ("load_globals :: dwarf_siblingof", __LINE__);
			break;
		}

		if (res == DW_DLV_NO_ENTRY) {
			res = DW_DLV_OK;
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

	return res;
}

/* load_functions
 * load the funtion name and their address in memory
 * Return Value: (In the current version of code, return value is ignored)
 *   DW_DLV_OK: Success
 *   DW_DLV_ERROR: Error in traversing dwarf file
 *   DW_DLV_NO_ENTRY: compilation unit die passed as argument does not have any child
 */
static int load_functions (Dwarf_Die in_die) {
	int res = DW_DLV_ERROR;
	Dwarf_Die cur_die = in_die;
	Dwarf_Die nextdie = 0;

	res = dwarf_child (cur_die, &nextdie, NULL);
	if (res == DW_DLV_ERROR || res == DW_DLV_NO_ENTRY) {
		if (res == DW_DLV_ERROR) {
			print_error ("load_globals :: dwarf_child", __LINE__);
		}
		dwarf_dealloc (dbg, nextdie, DW_DLA_DIE);
		return res;
	}

	cur_die = nextdie;
	while (true) {
		Dwarf_Half tag = 0;
		nextdie = 0;

		res = dwarf_tag (cur_die, &tag, NULL);
		if (res == DW_DLV_ERROR) {
			print_error ("load_functions :: dwarf_tag", __LINE__);
			goto badres;
		}

		if (tag == DW_TAG_subprogram) {
			Dwarf_Bool ret = 0;
			Dwarf_Attribute attr = 0;

			res = dwarf_hasattr (cur_die, DW_AT_low_pc, &ret, NULL);
			if (res == DW_DLV_ERROR) {
				print_error ("load_functions :: dwarf_hasattr", __LINE__);
				goto badres;
			}

			if (ret) {
				ut64 size = 0;
				char *diename = NULL;
				Dwarf_Addr low_pc = 0;
				Dwarf_Addr high_pc = 0;
				Dwarf_Half attr_form = 0;

				res = get_dwarf_diename (cur_die, &diename, NULL);
				if (res == DW_DLV_ERROR) {
					dwarf_dealloc (dbg, diename, DW_DLA_STRING);
					goto badres;
				} else if (res == DW_DLV_NO_ENTRY) {
					ut64 size = 0;
					Dwarf_Off offset = 0;
					Dwarf_Die offdie = 0;

					res = dwarf_attr (cur_die, DW_AT_abstract_origin, &attr, NULL);
					if (res != DW_DLV_OK) {
						goto out; //// REALLY????
					}

					res = dwarf_global_formref (attr, &offset, NULL);
					dwarf_dealloc (dbg, attr, DW_DLA_ATTR);
					if (res != DW_DLV_OK) {
						print_error (" ", __LINE__);
						goto out; //// REALLY?
					}

					res = dwarf_offdie (dbg, offset, &offdie, NULL);
					if (res != DW_DLV_OK) {
						print_error (" ", __LINE__);
						dwarf_dealloc (dbg, offdie, DW_DLA_DIE);
						goto out; //// REALLY?
					}

					dwarf_dealloc (dbg, diename, DW_DLA_STRING);
					res = get_dwarf_diename (offdie, &diename, NULL);
					if (res != DW_DLV_OK) {
						print_error (" ", __LINE__);
						dwarf_dealloc (dbg, diename, DW_DLA_STRING);
						dwarf_dealloc (dbg, offdie, DW_DLA_DIE);
						goto out;
					}
					dwarf_dealloc (dbg, offdie, DW_DLA_DIE);
					dwarf_dealloc (dbg, attr, DW_DLA_ATTR);

				}

				res = dwarf_attr (cur_die, DW_AT_low_pc, &attr, NULL);
				if (res != DW_DLV_OK) {
					print_error (" ", __LINE__);
					goto out;
				}

				res = dwarf_formaddr (attr, &low_pc, NULL);
				if (res != DW_DLV_OK) {
					print_error (" ", __LINE__);
					goto out;
				}

				//res = dwarf_lowpc (cur_die, &low_pc, NULL);
				//if (res == DW_DLV_ERROR) {
				//	print_error (" ", __LINE__);
				//	goto out;
				//}

				dwarf_dealloc (dbg, attr, DW_DLA_ATTR);

				res = dwarf_attr (cur_die, DW_AT_high_pc, &attr, NULL);
				if (res != DW_DLV_OK) {
					print_error (" ", __LINE__);
					goto out;
				}

				res = dwarf_whatform (attr, &attr_form, NULL);
				if (res != DW_DLV_OK) {
					print_error (" ", __LINE__);
					goto out;
				}

				//res = dwarf_highpc (cur_die, &high_pc, NULL);
				//if (res == DW_DLV_ERROR) {
				//	print_error (" ", __LINE__);
				//	goto out;
				//}

				if (attr_form == DW_FORM_addr) { // if (res == DW_DLV_OK) {
					res = dwarf_formaddr (attr, &high_pc, NULL);
					size = (res != DW_DLV_OK) ? 0 : (high_pc - low_pc);
				} else { //if (res == DW_DLV_NO_ENTRY)
					res = get_num_from_attr (attr, &size, NULL);
					if (res != DW_DLV_OK) {
						size = 0;
					}
				}

				r_cons_printf ("f sym.%s %llu @ 0x%llx\n", diename, size, (ut64) low_pc);
			out:
				dwarf_dealloc (dbg, attr, DW_DLA_ATTR);
				dwarf_dealloc (dbg, diename, DW_DLA_STRING);
			}
		}
	badres:
		res = dwarf_siblingof (dbg, cur_die, &nextdie, NULL);
		if (res == DW_DLV_ERROR) {
			print_error ("load_globals :: dwarf_siblingof", __LINE__);
			break;
		}

		if (res == DW_DLV_NO_ENTRY) {
			res = DW_DLV_OK;
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

	return res;
}

/*
 *
 */
static int print_arr_val (RCore *core, RList *l, Dwarf_Die die, Dwarf_Unsigned *addr, int indentlevel, int type, int idx) {
	int i = 0;
	int res = DW_DLV_ERROR;
	ut64 numelem = * (ut64 *) r_list_get_n (l, idx);
	ut64 typesz = 0;
	Dwarf_Die typedie = NULL;
	int inbits = 0;

	res = get_type_die (die, &typedie, NULL);
	if (res == DW_DLV_ERROR) {
		print_error (" ", __LINE__);
		dwarf_dealloc (dbg, typedie, DW_DLA_DIE);
		return res;
	}

	res = get_size (typedie, &typesz, &inbits);
	if (res == DW_DLV_ERROR) {
		print_error (" ", __LINE__);
		dwarf_dealloc (dbg, typedie, DW_DLA_DIE);
		return res;
	}

	r_cons_printf ("[");
	for (i = 0; i < numelem; i++) {
		if (i > 0) {
			r_cons_printf (",");
		}

		if ((idx + 1) == r_list_length (l)) {
			print_value (core, die, *addr, 0, indentlevel, type, NONE_DEF);
			*addr += (inbits ? (typesz % 8) : typesz); //XXX: Inproper use of inbits
		} else {
			print_arr_val (core, l, die, addr, indentlevel, type, idx + 1);
		}
	}
	r_cons_printf ("]");
}

/*
 *
 */
static int print_value (RCore *core, Dwarf_Die die, Dwarf_Unsigned addr, int baseoff, int indentlevel, int type, int flags) {
	int res = DW_DLV_ERROR;
	Dwarf_Half tag = 0;
	Dwarf_Die typedie = 0;
	ut64 size = 0;
	int inbits = 0;

	res = get_size (die, &size, &inbits);
	if (res == DW_DLV_ERROR) {
		print_error (" ", __LINE__);
		return res;
	}

	res = get_type_tag_and_die (die, &tag, &typedie, NULL);
	if (res == DW_DLV_ERROR) {
		print_error (" ", __LINE__);
		dwarf_dealloc (dbg, typedie, DW_DLA_DIE);
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
				print_error (" ", __LINE__);
				dwarf_dealloc (dbg, typedie, DW_DLA_DIE);
				return res;
			}

			if (type == NRM_FORMAT) {
				r_cons_printf ("{\n");
			}

			if (type == (C_FORMAT | JSON_FORMAT)) {
				if (isStruct) {
					r_cons_printf (",\"struct\":true");
				} else {
					r_cons_printf (",\"union\":true");
				}
				r_cons_printf (",\"members\":[");
			}

			res = print_struct_or_union_die (core, offset, indentlevel + 1, addr, baseoff, isStruct, type, 0, 1); // longlist parametere does not matter here
			if (type == NRM_FORMAT) {
				for (i = 0; i < indentlevel; i++) {
					r_cons_printf ("  ");
				}
				r_cons_printf ("}");
			}

			if (type == (C_FORMAT | JSON_FORMAT)) {
				r_cons_printf ("]");
			}

			break;
		}
	case DW_TAG_typedef:
	case DW_TAG_volatile_type:
	case DW_TAG_const_type:
	    if (type == (C_FORMAT | JSON_FORMAT)) {
			if (tag == DW_TAG_typedef && (flags & TYPEDEF_DEF)) {
				flags |= TYPEDEF_DEF;
				r_cons_printf (",\"typedef\":true", flags);
			} else if (tag == DW_TAG_volatile_type && !(flags & VOLATILE_DEF)) {
				r_cons_printf (",\"volatile\":true");
				flags |= VOLATILE_DEF;
			} else if (tag == DW_TAG_const_type && !(flags & CONST_DEF)) {
				r_cons_printf (",\"const\":true");
				flags |= CONST_DEF;
			}
		}
		res = print_value (core, typedie, addr, baseoff, indentlevel, type, flags);
		break;
	case DW_TAG_base_type:
	case DW_TAG_pointer_type:
	case DW_TAG_enumeration_type:
		res = DW_DLV_OK;
		if (type == NRM_FORMAT || type == JSON_FORMAT) {
			if (type == JSON_FORMAT) {
				r_cons_printf ("\"");
			}

			if (size == 1) {
				r_cons_printf ("0x%hhx", *(ut8 *)(core->block + addr));
			} else if (size == 2) {
				r_cons_printf ("0x%hx", *(ut16 *)(core->block + addr));
			} else if (size == 4) {
				r_cons_printf ("0x%x", *(ut32 *)(core->block + addr));
			} else if (size == 8) {
				r_cons_printf ("0x%"PFMT64x"", *(ut64 *)(core->block + addr));
			} else {
				eprintf ("ERROR: print_value :: size = %llu", size);
			}

			if (type == JSON_FORMAT) {
				r_cons_printf ("\"");
			}
		}

		if (type == (C_FORMAT | JSON_FORMAT)) {
			if (tag == DW_TAG_pointer_type && !(flags & POINTER_DEF)) {
				r_cons_printf (",\"pointer\":true");
				flags |= POINTER_DEF;
			} else if (tag == DW_TAG_enumeration_type && !(flags & ENUM_DEF)) {
				r_cons_printf (",\"enum\":true");
				flags |= ENUM_DEF;
			}
		}

		break;
	case DW_TAG_array_type:
		{
			int i = 0;
			RList *l = r_list_new ();
			RListIter *iter;
			ut64 typesz = 0;
			ut64 totalelem = 1;
			ut64 listlen = 0;
			int in_bits = 0;
			ut64 *num = 0;

			// res = get_size (typedie, &typesz, &in_bits);
			// if (res == DW_DLV_ERROR) {
			//	print_error (" ", __LINE__);
			//	goto out;
			// }

			res = get_array_dimension (typedie, l);
			if (res == DW_DLV_ERROR) {
				print_error (" ", __LINE__);
				r_list_free (l);
				goto out;
			}

			listlen = r_list_length (l);

			if (type == (C_FORMAT | JSON_FORMAT)) {
				r_cons_printf (",\"array\":true,\"dimension\":[");
				iter = r_list_iterator (l);
				num = r_list_iter_get (iter);
				r_cons_printf ("%"PFMT64u, *num);
				while (r_list_iter_next (iter)) {
					num = r_list_iter_get (iter);
					r_cons_printf (",%"PFMT64u, *num);
				}
				r_cons_printf ("]");
			}

			if (type == NRM_FORMAT || type == JSON_FORMAT) {
				print_arr_val (core, l, typedie, &addr, indentlevel, type, 0);
			}
			r_list_free (l);
		}
		break;
	default:
		break;
	}

 out:
	dwarf_dealloc (dbg, typedie, DW_DLA_DIE);
	return res;
}

/*
 *
 */
static int print_struct_or_union_die (RCore *core, Dwarf_Off offset, int indentlevel, Dwarf_Unsigned startaddr, int baseoff, int isStruct, int type, int longlist, int printmemberonly) {
	int i = 0;
	int inside_loop = 0;
	int res = DW_DLV_ERROR;
	Dwarf_Die die = 0;
	Dwarf_Die member = 0;
	Dwarf_Die sibdie = 0;
	Dwarf_Unsigned off = 0;
	char *diename = NULL;

	if (!offset) {
		print_error ("Invalid Offset", __LINE__);
		return DW_DLV_ERROR;
	}

	res = dwarf_offdie (dbg, offset, &die, NULL);
	if (res != DW_DLV_OK) {
		dwarf_dealloc (dbg, die, DW_DLA_DIE);
		return res;
	}

	if (type == JSON_FORMAT) {
		r_cons_printf ("{");
	}

	res = get_dwarf_diename (die, &diename, NULL);

	if (type == C_FORMAT && res != DW_DLV_ERROR) {
		if (isStruct) {
			r_cons_printf ("struct %s {\n", diename);
		} else {
			r_cons_printf ("union %s {\n", diename);
		}

		indentlevel += 1;
	}

	if (type == (C_FORMAT | JSON_FORMAT) && !printmemberonly) {
		ut64 size = 0;
		int inbits = 0;

		if (res == DW_DLV_OK) {
			r_cons_printf ("{\"name\":\"%s\",", diename);
		}

		res = get_size (die, &size, &inbits);
		if (res == DW_DLV_OK) {
			r_cons_printf ("\"size\":%"PFMT64u",\"inbits\":%s,", size, inbits ? "true" : "false");
		}

		if (isStruct) {
			r_cons_printf ("\"struct\":true,");
		} else {
			r_cons_printf ("\"union\":true,");
		}

		r_cons_printf ("\"members\":[");
	}

	dwarf_dealloc (dbg, diename, DW_DLA_STRING);

	res = dwarf_child (die, &member, NULL);
	if (res == DW_DLV_ERROR) {
		print_error (" ", __LINE__);
		dwarf_dealloc (dbg, member, DW_DLA_DIE);
		dwarf_dealloc (dbg, die, DW_DLA_DIE);
		return res;
	}

	while (res != DW_DLV_NO_ENTRY) {
		char *diename = NULL;
		char *typestr = malloc (8);
		ut64 size = 0;
		int inbits = 0;
		Dwarf_Half tag = 0;
		RList *l = NULL;

		if (type == NRM_FORMAT || type == C_FORMAT) {
			for (i = 0; i < indentlevel; i++) {
				r_cons_printf ("  ");
			}
		}

		if ((type & C_FORMAT) == C_FORMAT) {
			memset (typestr, 0, 8);
			res = get_type_in_str (&l, member, &typestr, indentlevel, type, longlist);
		}

		if (type == C_FORMAT) {
			r_cons_printf ("%s", typestr);
			free (typestr);
		}

		res = get_dwarf_diename (member, &diename, NULL);
		if (type == NRM_FORMAT) {
			r_cons_printf ("%s = ", (res == DW_DLV_OK) ? diename : "");
		} else if ((type & JSON_FORMAT) == JSON_FORMAT) {
			if ((type & C_FORMAT) == C_FORMAT) {
				r_cons_printf ("{\"name\":\"%s\"", (res == DW_DLV_OK) ? diename : "");
				r_cons_printf (",\"type\":\"%s\"", typestr);
				free (typestr);
			} else {
				r_cons_printf ("\"%s\":", (res == DW_DLV_OK) ? diename : "");
			}
		} else if (type == C_FORMAT) {
			r_cons_printf ("%s", (res == DW_DLV_OK) ? diename : "");
			if (l) {
				RListIter *iter;
				ut64 *num = 0;
			    r_list_foreach (l, iter, num) {
					r_cons_printf ("[%"PFMT64u"]", *num);
				}
				r_list_free (l);
				l = NULL;
			}
		}
		dwarf_dealloc (dbg, diename, DW_DLA_STRING);

		/*res = get_type_tag_and_die (member, &tag, NULL, NULL);
		/*if (res == DW_DLV_OK && (type == (C_FORMAT | JSON_FORMAT))) {
			if (tag == DW_TAG_structure_type) {
				r_cons_printf (",\"struct\":true");
			} else if (tag == DW_TAG_union_type) {
				r_cons_printf (",\"union\":true");
			}
		}*/

		res = get_size (member, &size, &inbits);
		if (res == DW_DLV_OK) {
			if (((type & C_FORMAT) == C_FORMAT) && ((type & JSON_FORMAT) == JSON_FORMAT)) {
				r_cons_printf (",\"size\":%"PFMT64u, size);
				r_cons_printf (",\"inbits\":%s", (inbits ? "true" : "false"));
			}
		}

		if (isStruct) {
			Dwarf_Attribute attr = 0;

			res = dwarf_attr (member, DW_AT_data_member_location, &attr, NULL);
			if ((res == DW_DLV_ERROR) || (res == DW_DLV_NO_ENTRY)) {
				print_error (" ", __LINE__);
				dwarf_dealloc (dbg, attr, DW_DLA_ATTR);
				dwarf_dealloc (dbg, member, DW_DLA_DIE);
				dwarf_dealloc (dbg, die, DW_DLA_DIE);
				return res; // XXX: REally?
			}

			res = get_num_from_attr (attr, &off, NULL);
			dwarf_dealloc (dbg, attr, DW_DLA_ATTR);
			if (res == DW_DLV_ERROR) {
				dwarf_dealloc (dbg, member, DW_DLA_DIE);
				dwarf_dealloc (dbg, die, DW_DLA_DIE);
				return res; // XXX: Really? Why so harsh?
			}
		}

		if (type == (C_FORMAT | JSON_FORMAT)) {
			r_cons_printf (",\"offset\":%"PFMT64u, off + baseoff);
		}

		if (type != C_FORMAT) {
			print_value (core, member, startaddr + off, baseoff + off, indentlevel, type, NONE_DEF);
		}

		if (type == (JSON_FORMAT | C_FORMAT)) {
			//r_cons_printf ("}");
		}

		res = dwarf_siblingof (dbg, member, &sibdie, NULL);
		if (res == DW_DLV_ERROR) {
			print_error (" ", __LINE__);
			break;
		} else if (res == DW_DLV_NO_ENTRY) {
			if (type == (C_FORMAT | JSON_FORMAT)) {
				r_cons_printf ("}");
			}

			if (type == C_FORMAT) {
				r_cons_printf (";\n");
			}
			break;
		}

		if (type == C_FORMAT) {
			r_cons_printf (";");
		} else if (type == (C_FORMAT | JSON_FORMAT)) {
			r_cons_printf ("},");
		} else {
			r_cons_printf (",");
		}

		if ((type & JSON_FORMAT) != JSON_FORMAT) {
			r_cons_printf ("\n");
		}

		dwarf_dealloc (dbg, member, DW_DLA_DIE);
		member = sibdie;
	}

	if (type == NRM_FORMAT) {
		r_cons_printf ("\n");
	} else if (type == JSON_FORMAT) {
		r_cons_printf ("}");
		if (indentlevel == 0) {
			r_cons_printf ("\n");
		}
	} else if (type == (JSON_FORMAT | C_FORMAT) && !printmemberonly) {
		r_cons_printf ("]}");
		if (indentlevel == 0) {
			r_cons_printf ("\n");
		}
	} else if (type == C_FORMAT) {
		indentlevel -= 1;
		for (i = 0; i < indentlevel; i++) {
			r_cons_printf ("  ");
		}
		r_cons_printf ("}");
	}

	if (indentlevel == 0 && type == C_FORMAT) {
		r_cons_printf (";\n");
	}

	dwarf_dealloc (dbg, die, DW_DLA_DIE);
	dwarf_dealloc (dbg, member, DW_DLA_DIE);
	dwarf_dealloc (dbg, sibdie, DW_DLA_DIE);
	return DW_DLV_OK;
}

static int print_specific_stuff (RCore *core, ut64 offset, Dwarf_Unsigned startaddr, char *remain, int onlyaddr, int type, int longlist) {
	int res = DW_DLV_ERROR;
	Dwarf_Die die = 0;
	Dwarf_Die member = 0;
	ut64 addr;
	ut64 size = 0;
	int inbits = 0;
	ut64 oldoffset = 0;
	ut64 oldblocksize = 0;
	ut64 retoff = 0;

	if (!offset) {
		print_error (" ", __LINE__);
		return DW_DLV_ERROR;
	}

	res = dwarf_offdie (dbg, offset, &die, NULL);
	if (res != DW_DLV_OK) {
		dwarf_dealloc (dbg, die, DW_DLA_DIE);
		return res;
	}

	res = get_address_and_die (core, die, startaddr, remain, &member, &addr, &retoff);
	if (res != DW_DLV_OK) {
		print_error (" ", __LINE__);
		dwarf_dealloc (dbg, die, DW_DLA_DIE);
		dwarf_dealloc (dbg, member, DW_DLA_DIE);
		return res;
	}

	if (onlyaddr) {
		if (type == JSON_FORMAT) {
			r_cons_printf ("{\"addr\":0x%"PFMT64x"}\n", addr);
		} else if (type == NRM_FORMAT) {
			r_cons_printf ("addr = 0x%"PFMT64x"\n", addr);
		}
		dwarf_dealloc (dbg, die, DW_DLA_DIE);
		dwarf_dealloc (dbg, member, DW_DLA_DIE);
		return res;
	}

	res = get_size (member, &size, &inbits);
	if (res == DW_DLV_ERROR) {
		dwarf_dealloc (dbg, die, DW_DLA_DIE);
		dwarf_dealloc (dbg, member, DW_DLA_DIE);
		return res;
	}

	if ((type & C_FORMAT) == C_FORMAT) {
		RList *l = NULL;
		char *name = 0;
		char *typestr = 0;

		res = get_dwarf_diename (member, &name, NULL);
		if (res == DW_DLV_ERROR) {
			print_error (" ", __LINE__);
			dwarf_dealloc (dbg, name, DW_DLA_STRING);
			dwarf_dealloc (dbg, die, DW_DLA_DIE);
			dwarf_dealloc (dbg, member, DW_DLA_DIE);
			return res;
		}

		typestr = malloc (10);
		if (!typestr) {
			print_error (" ", __LINE__);
			dwarf_dealloc (dbg, name, DW_DLA_STRING);
			dwarf_dealloc (dbg, die, DW_DLA_DIE);
			dwarf_dealloc (dbg, member, DW_DLA_DIE);
			return DW_DLV_ERROR;
		}

		*typestr = 0;
		res = get_type_in_str (&l, member, &typestr, 0, type, longlist);
		if (res == DW_DLV_ERROR) {
			print_error (" ", __LINE__);
			free (typestr);
			dwarf_dealloc (dbg, name, DW_DLA_STRING);
			dwarf_dealloc (dbg, die, DW_DLA_DIE);
			dwarf_dealloc (dbg, member, DW_DLA_DIE);
			return res;
		}

		if (type == C_FORMAT) {
			r_cons_printf ("%s%s", typestr, name);
		    if (l) {
				RListIter *iter;
				ut64 *num = 0;
			    r_list_foreach (l, iter, num) {
					r_cons_printf ("[%"PFMT64u"]", *num);
				}
				r_list_free (l);
				l = NULL;
			}
			r_cons_printf ("\n");
		} else {
			Dwarf_Half tag = 0;

			res = dwarf_tag (member, &tag, NULL);
			if (res == DW_DLV_ERROR) {
				print_error (" ", __LINE__);
				free (typestr);
				dwarf_dealloc (dbg, die, DW_DLA_DIE);
				dwarf_dealloc (dbg, member, DW_DLA_DIE);
				dwarf_dealloc (dbg, name, DW_DLA_STRING);
				return res;
			}

		    r_cons_printf ("{\"name\":\"%s\"", name);
			r_cons_printf (",\"type\":\"%s\"", typestr);
			r_cons_printf (",\"size\":\"%"PFMT64u"\"", size);
			r_cons_printf (",\"inbits\":%s", inbits ? "true" : "false");
		    if ((st64)retoff != -1) {
				r_cons_printf (",\"offset\":%"PFMT64u, retoff);
			}
			switch (tag) {
			case DW_TAG_structure_type:
			case DW_TAG_union_type:
				{
					int isStruct = (tag == DW_TAG_structure_type) ? 1 : 0;
					Dwarf_Off off;

					res = dwarf_dieoffset (member, &off, NULL);
					if (res == DW_DLV_ERROR) {
						print_error (" ", __LINE__);
						dwarf_dealloc (dbg, die, DW_DLA_DIE);
						dwarf_dealloc (dbg, member, DW_DLA_DIE);
						dwarf_dealloc (dbg, name, DW_DLA_STRING);
						return res;
					}

					if (isStruct) {
						r_cons_printf (",\"struct\":true");
					} else {
						r_cons_printf (",\"union\":true");
					}
					r_cons_printf (",\"members\":[");
					res = print_struct_or_union_die (core, off, 0, startaddr, retoff, isStruct, type, 0, 1);
					r_cons_printf ("]");
					break;
				}
			case DW_TAG_array_type:
				{
					RListIter *iter;
					ut64 *num;
					r_cons_printf (",\"array\":true,\"dimension\":[");
					iter = r_list_iterator (l);
					num = r_list_iter_get (iter);
					r_cons_printf ("%"PFMT64u, *num);
					while (r_list_iter_next (iter)) {
						num = r_list_iter_get (iter);
						r_cons_printf (",%"PFMT64u, *num);
					}
					r_cons_printf ("]");
					r_list_free (l);
					l = NULL;
					break;
				}
			case DW_TAG_pointer_type:
			case DW_TAG_enumeration_type:
			case DW_TAG_typedef:
			case DW_TAG_volatile_type:
			case DW_TAG_const_type:
			case DW_TAG_member:
				{
					int flags = NONE_DEF;
					if (tag == DW_TAG_typedef && (flags & TYPEDEF_DEF)) {
						flags |= TYPEDEF_DEF;
						r_cons_printf (",\"typedef\":true", flags);
					} else if (tag == DW_TAG_volatile_type && !(flags & VOLATILE_DEF)) {
						r_cons_printf (",\"volatile\":true");
						flags |= VOLATILE_DEF;
					} else if (tag == DW_TAG_const_type && !(flags & CONST_DEF)) {
						r_cons_printf (",\"const\":true");
						flags |= CONST_DEF;
					} else if (tag == DW_TAG_pointer_type && !(flags & POINTER_DEF) ) {
						r_cons_printf (",\"pointer\":true");
						flags |= POINTER_DEF;
					} else if (tag == DW_TAG_enumeration_type && !(flags & ENUM_DEF)) {
						r_cons_printf (",\"enum\":true");
						flags |= ENUM_DEF;
					}

					if (tag != DW_TAG_pointer_type && tag != DW_TAG_enumeration_type) {
						res = print_value (core, member, addr, retoff, 0, C_FORMAT | JSON_FORMAT, flags);
					}
					break;
				}
			case DW_TAG_base_type:
				break;
			default:
				eprintf ("[!] Unhandled tag: %d\n");
			}
			r_cons_printf ("}\n");
		}

		free (typestr);
		dwarf_dealloc (dbg, name, DW_DLA_STRING);
	} else {
		oldoffset = core->offset;
		oldblocksize = core->blocksize;
		if (addr < core->offset || (addr + size) > (core->offset + core->blocksize)) {
			core->offset = addr;
			res = r_core_block_size (core, size);
			if (!res) {
			    dwarf_dealloc (dbg, die, DW_DLA_DIE);
				dwarf_dealloc (dbg, member, DW_DLA_DIE);
				return DW_DLV_ERROR;
			}
		}

		//r_cons_printf ("adfasdgsadgdsgadfhadfhafh\n");
		print_value (core, member, addr - core->offset, 0, 0, type, NONE_DEF);
		r_cons_printf ("\n");
		if (core->offset != oldoffset || core->blocksize != oldblocksize) {
			core->offset = oldoffset;
			core->blocksize = oldblocksize;
			r_core_block_size (core, oldblocksize);
		}
	}

	dwarf_dealloc (dbg, die, DW_DLA_DIE);
	dwarf_dealloc (dbg, member, DW_DLA_DIE);
	return DW_DLV_OK;
}

/*
 *
 */
static int print_type_and_size (RCore *core, ut64 sdboffset, ut64 startaddr, char *remain, int type) {
	int res = DW_DLV_ERROR;
	Dwarf_Die die = 0;
	Dwarf_Die member = 0;
	char *nameref = NULL;
	int inbits;
	ut64 addr;
	RList *l = NULL;
	ut64 retoff = 0;

    res = dwarf_offdie (dbg, sdboffset, &die, NULL);
	if (res != DW_DLV_OK) {
		dwarf_dealloc (dbg, die, DW_DLA_DIE);
		return res;
	}

	res = get_address_and_die (core, die, startaddr, remain, &member, &addr, &retoff);
	if (res != DW_DLV_OK) {
		dwarf_dealloc (dbg, die, DW_DLA_DIE);
		return res;
	}

	dwarf_dealloc (dbg, die, DW_DLA_DIE);
	die = member;

	nameref = malloc (8);
	if (!nameref) {
		print_error ("malloc error", __LINE__);
		return DW_DLV_ERROR;
	}

	memset (nameref, 0, 8);
	res = get_type_in_str (&l, die, &nameref, 0, type, 0);
	if (res == DW_DLV_ERROR) {
		print_error (" ", __LINE__);
		return res;
	}

	addr = 0; // type is used as size now
	res = get_size (die, &addr, &inbits);
	if (res == DW_DLV_ERROR) {
		print_error (" ", __LINE__);
		return res;
	}

	if (type == JSON_FORMAT) {
		r_cons_printf ("{\"type\":\"%s\",\"size\":\"%"PFMT64u"\"}\n", nameref, addr);
	} else if (type == NRM_FORMAT) {
		r_cons_printf ("type : %s\nsize : %"PFMT64u"\n", nameref, addr);
	}
	return DW_DLV_OK;
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

static int read_cu_list (int flag) {
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

		if (flag == 0) {
			first_parse (cu_die);
		} else if (flag == 1) {
			load_globals (cu_die);
		} else if (flag == 2) {
			load_functions (cu_die);
		}
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

	res = read_cu_list (0);
	if (res != 0) {
		close (fd);
		res = dwarf_finish (dbg, NULL);
		return false;
	}

	return true;
}

static int r_cmd_dwarf_call (void *user, const char *input) {
	const char *arg1 = getargpos (input, 1);
	RCore *core = (RCore *) user;
	int res = DW_DLV_ERROR;
	char *structname = NULL;
	char *temp = NULL;
	ut64 sdboffset = 0;
	Dwarf_Die die = 0;
	ut64 size = 0;
	int inbits = 0;
	ut64 oldblocksize = 0;
	int type = NRM_FORMAT;

	if (!strncmp (input, "dwarf", 5)) {
		input += 5;
	} else if (!strncmp (input, "idd", 3)) {
		input += 3;
	} else {
		return false;
	}

	if (strchr (input, ' ') && *(strchr (input, ' ') - 1) == 'j') {
		type = JSON_FORMAT;
	}

	if (arg1) {
		structname = strdup (arg1);
		temp = strchr (structname, ' ');
		if (temp) {
			*temp = 0; // Don't remember if *(temp+1) == 0 is required or not.
		}
		temp = NULL;
	}

	if (s && dbg && arg1) {
		temp = strchr (structname, '.');
		if (temp) {
			*temp = 0;
			temp += 1;
		}

		sdboffset = sdb_num_get (s, structname, 0);
		if ((*input != 't') && sdboffset == 0) {
			printf ("DWARF: invalid offset for struct %s\n", structname);
		    return true;
		}

		res = dwarf_offdie (dbg, sdboffset, &die, NULL);
		if (res != DW_DLV_OK) {
			printf ("ERROR: r_cmd_dwarf_call :: dwarf_offdie :: %d\n", __LINE__);
		    return true;
		}

		res = get_size (die, &size, &inbits);
		if (res != DW_DLV_OK) {
			printf ("ERROR: r_cmd_dwarf_call :: get_size :: %d\n", __LINE__);
		    return true;
		}
	}

	switch (*input) {
	case 'a': // idda: print address
		{
			if (fd == -1 || !dbg || !s) {
				printf ("DWARF: initialise sdb and dbg entries with iddi filename\n");
				break;
			}

			if (!structname) {
				printf ("Usage: idda structname[.member1[.submember.[..]]]\n");
				break;
			}

			oldblocksize = core->blocksize;
			if (r_core_block_size (core, size)) {
				if (temp) {
					res = print_specific_stuff (core, sdboffset, core->offset, temp, 1, type, 0);
				} else {
					res = print_struct_or_union_die (core, sdboffset, 0, 0, 0, 1, type, 0, 0);
				}
				if (res != DW_DLV_OK) {
					dwarf_dealloc (dbg, die, DW_DLA_DIE);
					printf ("ERROR: r_cmd_dwarf_call :: print_specific_stuff :: %d\n", __LINE__);
					break;
				}
			}

			r_core_block_size (core, oldblocksize);
		}
		break;
	case 'd': // iddd: print c type declaration of strut
		{
			int longlist = 0;

			if (fd == -1 || !dbg || !s) {
				printf ("DWARF: initialise sdb and dbg entries with iddi filename\n");
				break;
			}

			if (!structname) {
				printf ("Usage: iddd[l] structname[.member1[.submember.[..]]]\tprint C-type struct declaration\n");
				break;
			}

			longlist = (*(input + 1) == 'l') ? 1 : 0;

			oldblocksize = core->blocksize;
			if (r_core_block_size (core, size)) {
				if (temp) {
					res = print_specific_stuff (core, sdboffset, core->offset, temp, 0, C_FORMAT | type, longlist);
				} else {
					res = print_struct_or_union_die (core, sdboffset, 0, 0, 0, 1, C_FORMAT | type, longlist, 0);
				}
				if (res != DW_DLV_OK) {
					dwarf_dealloc (dbg, die, DW_DLA_DIE);
					printf ("ERROR: r_cmd_dwarf_call :: print_specific_stuff :: %d\n", __LINE__);
					break;
				}
			}

			r_core_block_size (core, oldblocksize);
		}
		break;
	case 'i': // iddi: initialise sdb and dwarf_dbg
		{
			if (fd == -1) {
				if (arg1) {
					return r_cmd_dwarf_init (core, arg1);
				} else {
					printf ("Usage: (iddi | dwarfi) filename\n");
					// return false;
				}
			}
		}
		break;
	case 'l': // iddl*: print global functions or global variables that can be loaded as r2 flags
		{
			if (fd == -1 || !dbg || !s) {
				printf ("DWARF: initialise sdb and dbg entries with iddi filename\n");
				break;
			}

			switch (*(input + 1)) {
			case 'f':
				read_cu_list (2);
				break;
			case 'g':
				read_cu_list (1);
				break;
			default:
				printf ("Usage:\n\tiddlf: load function in r2 flag format\n\tiddlg: load global variables in r2 flag format\n");
				break;
			}
		}
		break;
	case 't':
		{
			if (fd == -1 || !dbg || !s) {
				printf ("DWARF: initialise sdb and dbg entries with iddi filename\n");
				break;
			}

			res = print_type_and_size (core, sdboffset, core->offset, temp, type);
			if (res != DW_DLV_OK) {
				printf ("ERROR: r_cmd_dwarf_call :: print_type_and_size :: %d\n", __LINE__);
				break;
			}
		}
		break;
	case 'v': // iddv: print value //TODO: update the output as "(type) value" instead of just "value"
		{
			if (fd == -1 || !dbg || !s) {
				printf ("DWARF: initialise sdb and dbg entries with iddi filename\n");
				break;
			}

			if (!structname) {
				printf ("Usage: iddv structname[.member1[.submember.[..]]]\n");
				break;
			}

			oldblocksize = core->blocksize;
			if (r_core_block_size (core, size)) {
				if (temp) {
					res = print_specific_stuff (core, sdboffset, core->offset, temp, 0, type, 0);
				} else {
					res = print_struct_or_union_die (core, sdboffset, 0, 0, 0, 1, type, 0, 0);
				}
				if (res != DW_DLV_OK) {
					dwarf_dealloc (dbg, die, DW_DLA_DIE);
					printf ("ERROR: r_cmd_dwarf_call :: print_specific_stuff :: %d\n", __LINE__);
					break;
				}
			}

			r_core_block_size (core, oldblocksize);
		}
		break;
    default:
		if (arg1) {
			if (fd == -1 || !dbg || !s) {
				printf ("DWARF: initialise sdb and dbg entries with iddi filename\n");
				break;
			}

			oldblocksize = core->blocksize;
			if (r_core_block_size (core, size)) {
				if (temp) {
					res = print_specific_stuff (core, sdboffset, core->offset, temp, 1, type, 0);
				} else {
					res = print_struct_or_union_die (core, sdboffset, 0, 0, 0, 1, type, 0, 0);
				}
				if (res != DW_DLV_OK) {
					dwarf_dealloc (dbg, die, DW_DLA_DIE);
					printf ("ERROR: r_cmd_dwarf_call :: print_specific_stuff :: %d\n", __LINE__);
					break;
				}
			}

			r_core_block_size (core, oldblocksize);
		} else {
			return false;
		}
	}

	free (structname);
	if (dbg) {
		dwarf_dealloc (dbg, die, DW_DLA_DIE);
	}

	return true;
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

		fd = -1;
		s = NULL;
		dbg = NULL;
	}
	return true;
}

RCorePlugin r_core_plugin_dwarf = {
	.name = "dwarf",
	.desc = "DWARF parser to analyse various structure and set flags (global variables and function declaration)",
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
