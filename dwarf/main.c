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
//TODO: Refactor the code. Multiple places have repititon :(
//char *data = NULL;

#define NRM_FORMAT  0
#define JSON_FORMAT 1
#define C_FORMAT    2

static int is_declaration (Dwarf_Die die);
static int print_struct_or_union_die (RCore *core, Dwarf_Off offset, int indentlevel, Dwarf_Unsigned startaddr, int isStruct, int type, int longlist);
static int get_size (Dwarf_Die die, Dwarf_Unsigned *size, int *inbits);
static int get_num_from_attr (Dwarf_Attribute attr, Dwarf_Unsigned *val);
static int get_type_die (Dwarf_Die die, Dwarf_Die *typedie, Dwarf_Error *error);
static int get_array_length (Dwarf_Die die, Dwarf_Unsigned *len);
static int get_type_die_offset (Dwarf_Die die, Dwarf_Off *offset, Dwarf_Error *error);
static int get_dwarf_diename (Dwarf_Die die, char **diename, Dwarf_Error *error);

//XXX: try to get rid of this global variable for proper array length printing at the end
static ut64 arrlen = 0;
static int c_format_arrlen_set = 0;

static int get_type_in_str (Dwarf_Die die, char **nameref, int indentlevel, int longlist) {
	int res = DW_DLV_ERROR;
	int typedieres = DW_DLV_ERROR;
	Dwarf_Half tag = 0;
	Dwarf_Die typedie = 0;

	res = dwarf_tag (die, &tag, NULL);
	if (res == DW_DLV_ERROR) {
		printf ("ERROR: get_type_in_str :: dwarf_tag :: %d\n", __LINE__);
		return res;
	}

	typedieres = get_type_die (die, &typedie, NULL);
	if (typedieres == DW_DLV_ERROR) {
		printf ("ERROR: get_type_in_str :: get_type_die :: %d\n", __LINE__);
		return res;
	}

	switch (tag) {
	case DW_TAG_base_type:
	    {
			char *name = NULL;
			res = dwarf_diename (die, &name, NULL);
			if (res == DW_DLV_ERROR) {
				dwarf_dealloc (dbg, name, DW_DLA_STRING);
				printf ("ERROR: get_type_in_str :: dwarf_diename :: %d\n", __LINE__);
				return res;
			} else if (res == DW_DLV_NO_ENTRY) {
				dwarf_dealloc (dbg, name, DW_DLA_STRING);
				*nameref = r_str_concat (*nameref, "void ");
			} else {
				*nameref = r_str_concatf (*nameref, "%s ", name);
				dwarf_dealloc (dbg, name, DW_DLA_STRING);
			}

			if (! *nameref) {
				printf ("ERROR: get_type_in_str :: r_str_concat :: %d\n", __LINE__);
				return DW_DLV_ERROR;
			}
		}
		break;
	case DW_TAG_pointer_type:
		{
			if (typedieres == DW_DLV_ERROR) {
				printf ("ERROR: get_type_in_str :: get_type_die :: %d\n", __LINE__);
				return res;
			} else if (typedieres == DW_DLV_NO_ENTRY) {
				*nameref = r_str_concat (*nameref, "void *");
			} else {
				res = get_type_in_str (typedie, nameref, indentlevel, 0); // longlist == 1 may lead to infinite recursion since pointer to same struct is valid.
				if (res == DW_DLV_ERROR) {
					printf ("ERROR: get_type_in_str :: get_type_in_str :: %d\n", __LINE__);
					return res;
				}

				*nameref = r_str_concat (*nameref, "*");
			}

			if (! *nameref) {
				printf ("ERROR: get_type_in_str :: r_str_concat :: %d\n", __LINE__);
				return DW_DLV_ERROR;
			}
		}
		break;
	case DW_TAG_typedef:
		{
			char *name = NULL;

			res = dwarf_diename (die, &name, NULL);
			if (res == DW_DLV_ERROR) {
				dwarf_dealloc (dbg, name, DW_DLA_STRING);
				printf ("ERROR: get_type_in_str :: dwarf_diename :: %d\n", __LINE__);
				return res;
			} else if (res == DW_DLV_NO_ENTRY) {
				dwarf_dealloc (dbg, name, DW_DLA_STRING);
				if (typedieres == DW_DLV_OK) {
					res = get_type_in_str (typedie, nameref, indentlevel, longlist);
					if (res == DW_DLV_ERROR) {
						printf ("ERROR: get_type_in_str :: get_type_in_str :: %d\n", __LINE__);
						return DW_DLV_ERROR;
					}
				} else {
					*nameref = r_str_concat (*nameref, "void ");
				}
			} else {
				*nameref = r_str_concatf (*nameref, "%s ", name);
				dwarf_dealloc (dbg, name, DW_DLA_STRING);
			}

			if (! *nameref) {
				printf ("ERROR: get_type_in_str :: r_str_concat :: %d\n", __LINE__);
				return DW_DLV_ERROR;
			}
		}
		break;
	case DW_TAG_const_type:
	case DW_TAG_volatile_type:
		{
			if (tag == DW_TAG_const_type) {
				*nameref = r_str_concat (*nameref, "const ");
			} else {
				*nameref = r_str_concat (*nameref, "volatile ");
			}

			if (! *nameref) {
				printf ("ERROR: get_type_in_str :: r_str_concat :: %d\n", __LINE__);
				return DW_DLV_ERROR;
			}

			if (typedieres == DW_DLV_NO_ENTRY) {
				*nameref = r_str_concat (*nameref, "void ");
			    if (! *nameref) {
					printf ("ERROR: get_type_in_str :: r_str_concat :: %d\n", __LINE__);
					return DW_DLV_ERROR;
				}
			} else if (typedieres == DW_DLV_OK) {
				res = get_type_in_str (typedie, nameref, indentlevel, longlist);
				if (res == DW_DLV_ERROR) {
					printf ("ERROR: get_type_in_str :: get_type_in_str :: %d\n", __LINE__);
					return DW_DLV_ERROR;
				}
			}
		}
		break;
	case DW_TAG_structure_type:
	case DW_TAG_union_type:
		{
			char *name = NULL;

		    res = get_dwarf_diename (die, &name, NULL);
			if (res == DW_DLV_ERROR) {
				dwarf_dealloc (dbg, name, DW_DLA_STRING);
				printf ("ERROR: get_type_in_str :: dwarf_diename :: %d\n", __LINE__);
				return res;
			} else if (res == DW_DLV_NO_ENTRY || longlist) {
				int isStruct = (tag == DW_TAG_structure_type) ? 1 : 0;
				Dwarf_Off offset = 0;

				dwarf_dealloc (dbg, name, DW_DLA_STRING);
				res = dwarf_dieoffset (die, &offset, NULL);
				if (res == DW_DLV_ERROR) {
					printf ("ERROR: get_type_in_str :: dwarf_dieoffset :: %d\n", __LINE__);
					return res;
				}
				res = print_struct_or_union_die (NULL, offset, indentlevel, 0, isStruct, C_FORMAT, longlist);
				if (res == DW_DLV_ERROR) {
					printf ("ERROR: get_type_in_str :: print_struct_or_union_die :: %d\n", __LINE__);
					return res;
				}
				printf (" ");
			} else {
				if (tag == DW_TAG_structure_type) {
					*nameref = r_str_concatf (*nameref, "struct %s ", name);
				} else if (tag == DW_TAG_union_type) {
					*nameref = r_str_concatf (*nameref, "union %s ", name);
				}

				if (! *nameref) {
					dwarf_dealloc (dbg, name, DW_DLA_STRING);
					printf ("ERROR: get_type_in_str :: r_str_concat :: %d\n", __LINE__);
					return DW_DLV_ERROR;
				}

				dwarf_dealloc (dbg, name, DW_DLA_STRING);
			}
		}
		break;
	case DW_TAG_array_type:
		{
			char *name = NULL;

			res = dwarf_diename (die, &name, NULL);
			if (res == DW_DLV_ERROR) {
				dwarf_dealloc (dbg, name, DW_DLA_STRING);
				printf ("ERROR: get_type_in_str :: dwarf_diename :: %d\n", __LINE__);
				return res;
			} else if (res == DW_DLV_NO_ENTRY) {
				dwarf_dealloc (dbg, name, DW_DLA_STRING);

				if (typedieres == DW_DLV_NO_ENTRY) {
					*nameref = r_str_concat (*nameref, "void ");
				} else if (typedieres == DW_DLV_OK) {
					res = get_type_in_str (typedie, nameref, indentlevel, longlist);
					if (res == DW_DLV_ERROR) {
						printf ("ERROR: get_type_in_str :: get_type_in_str :: %d\n", __LINE__);
						return DW_DLV_ERROR;
					}
				}
			} else {
				*nameref = r_str_concatf (*nameref, "%s ", name);
				dwarf_dealloc (dbg, name, DW_DLA_STRING);
			}

			if (! *nameref) {
				printf ("ERROR: get_type_in_str :: r_str_concat :: %d\n", __LINE__);
				return DW_DLV_ERROR;
			}

			res = get_array_length (die, &arrlen);
			if (res == DW_DLV_ERROR) {
				printf ("ERROR: %d\n", __LINE__);
				return res;
			}

			c_format_arrlen_set = 1;
		}
		break;
	case DW_TAG_enumeration_type:
		{
			char *name = NULL;
			*nameref = r_str_concat (*nameref, "enum ");
			if (! *nameref) {
				printf ("ERROR: get_type_in_str :: r_str_concat :: %d\n", __LINE__);
				return DW_DLV_ERROR;
			}

			res = dwarf_diename (die, &name, NULL);
			if (res == DW_DLV_ERROR) {
				dwarf_dealloc (dbg, name, DW_DLA_STRING);
				printf ("ERROR: get_type_in_str :: dwarf_diename :: %d\n", __LINE__);
				return res;
			} else if (res == DW_DLV_NO_ENTRY) {
				if (typedieres == DW_DLV_NO_ENTRY) {
					*nameref = r_str_concat (*nameref, "void ");
					if (! *nameref) {
						printf ("ERROR: get_type_in_str :: r_str_concat :: %d\n", __LINE__);
						return DW_DLV_ERROR;
					}
				} else if (typedieres == DW_DLV_OK) {
					res = get_type_in_str (typedie, nameref, indentlevel, longlist);
					if (res == DW_DLV_ERROR) {
						printf ("ERROR: get_type_in_str :: get_type_in_str :: %d\n", __LINE__);
						return DW_DLV_ERROR;
					}
				}
			}
		}
		break;
	case DW_TAG_member:
	case DW_TAG_variable:
		{
			if (typedieres == DW_DLV_NO_ENTRY) {
				*nameref = r_str_concat (*nameref, "void ");
				if (! *nameref) {
					printf ("ERROR: get_type_in_str :: r_str_concat :: %d\n", __LINE__);
					return DW_DLV_ERROR;
				}
			} else if (typedieres == DW_DLV_OK) {
				res = get_type_in_str (typedie, nameref, indentlevel, longlist);
				if (res == DW_DLV_ERROR) {
					printf ("ERROR: get_type_in_str :: get_type_in_str :: %d\n", __LINE__);
					return DW_DLV_ERROR;
				}
			}
		}
		break;
	case DW_TAG_subroutine_type:
		{
			*nameref = r_str_concat (*nameref, "FUNC_PTR ");
		}
		break;
	default:
		printf ("[*] NEW TAG found: get_type_in_str :: %d\n",tag);
	}

	dwarf_dealloc (dbg, typedie, DW_DLA_DIE);
	return DW_DLV_OK;
}

static int load_globals_or_functions (Dwarf_Die in_die, int load_globals) {
	int res = DW_DLV_ERROR;
	Dwarf_Die cur_die = in_die;
	Dwarf_Die nextdie = 0;

	res = dwarf_child (cur_die, &nextdie, NULL);
	if (res == DW_DLV_ERROR) {
		printf ("ERROR: dwarf_child :: %d\n", __LINE__);
		return res;
	} else if (res == DW_DLV_NO_ENTRY) {
		return res;
	}

	cur_die = nextdie;
	while (1) {
		Dwarf_Half tag = 0;
		nextdie = 0;

		res = dwarf_tag (cur_die, &tag, NULL);
		if (res == DW_DLV_ERROR) {
			printf ("ERROR: load_globals :: %d\n", __LINE__);
			return res;
		}

		if (load_globals) { // Load Globals
			if (tag == DW_TAG_variable && !is_declaration (cur_die)) {
				Dwarf_Locdesc *locdesc = 0;
				Dwarf_Signed lcnt = 0;
				Dwarf_Bool ret = 0;
				Dwarf_Attribute attr = 0;

				res = dwarf_hasattr (cur_die, DW_AT_location, &ret, NULL);
				if (res == DW_DLV_ERROR) {
					printf ("ERROR: load_globals_or_functions :: dwarf_hasattr :: %d\n", __LINE__);
					return res;
				}

				if (ret) {
					int i;
					ut64 size;
					int inbits;
					char *diename = NULL;
					Dwarf_Die typedie = 0;

					res = dwarf_attr (cur_die, DW_AT_location, &attr, NULL);
					if (res != DW_DLV_OK) {
						dwarf_dealloc (dbg, attr, DW_DLA_ATTR);
						return res;
					}

					res = dwarf_loclist (attr, &locdesc, &lcnt, NULL);
					if (res != DW_DLV_OK) {
						printf ("ERROR: load_globals_or_functions :: dwarf_loclist :: %d\n", __LINE__);
						dwarf_dealloc (dbg, attr, DW_DLA_ATTR);
						return res;
					}

					res = dwarf_diename (cur_die, &diename, NULL);
					if (res != DW_DLV_OK) {
						diename = "";
						//return res;
					}

					res = get_type_die (cur_die, &typedie, NULL);
					if (res == DW_DLV_OK) {
						res = get_size (typedie, &size, &inbits);
						if (res != DW_DLV_OK) {
							size = 0;
						}
					} else {
						size = 0;
					}

					for (i = 0; i < lcnt; i++) {
						if (locdesc[i].ld_s->lr_atom == DW_OP_addr) {
							r_cons_printf ("f sym.%s %llu @ 0x%llx\n", diename, size, locdesc[i].ld_s->lr_number);
						}
					}

					dwarf_dealloc (dbg, typedie, DW_DLA_DIE);
					dwarf_dealloc (dbg, attr, DW_DLA_ATTR);
				}
			}
		} else { // Load Functions
			if (tag == DW_TAG_subprogram) {
				Dwarf_Bool ret = 0;
				Dwarf_Attribute attr = 0;
				Dwarf_Addr low_pc = 0;
				Dwarf_Addr high_pc = 0;
				Dwarf_Half attr_form = 0;
				ut64 size = 0;

				res = dwarf_hasattr (cur_die, DW_AT_low_pc, &ret, NULL);
				if (res == DW_DLV_ERROR) {
					printf ("ERROR: load_globals_or_functions :: dwarf_hasattr :: %d\n", __LINE__);
					return res;
				}

				if (ret) {
					char *diename = NULL;
					res = dwarf_diename (cur_die, &diename, NULL);
					if (res == DW_DLV_ERROR) {
					    goto next;
					} else if (res == DW_DLV_NO_ENTRY) {
						// There occurs some repitition of flags with same name but different addr.
						// 622 flags with same name and 29685 unique
						res = dwarf_attr (cur_die, DW_AT_abstract_origin, &attr, NULL);
						if (res != DW_DLV_OK) {
							dwarf_dealloc (dbg, attr, DW_DLA_ATTR);
							goto next;
						} else {
							Dwarf_Off offset = 0;
							Dwarf_Die offdie = 0;

							res = dwarf_global_formref (attr, &offset, NULL);
							dwarf_dealloc (dbg, attr, DW_DLA_ATTR);
							if (res == DW_DLV_OK) {
								res = dwarf_offdie (dbg, offset, &offdie, NULL);
								if (res == DW_DLV_OK) {
									res = dwarf_diename (offdie, &diename, NULL);
									dwarf_dealloc (dbg, offdie, DW_DLA_DIE);
									if (res != DW_DLV_OK) {
									    goto next;
									}
								} else {
									goto next;
								}
							} else {
								goto next;
							}
						}
					}

					res = dwarf_attr (cur_die, DW_AT_low_pc, &attr, NULL);
					if (res != DW_DLV_OK) {
						dwarf_dealloc (dbg, attr, DW_DLA_ATTR);
						printf ("ERROR: %d\n", __LINE__);
						return res;
					}

					res = dwarf_formaddr (attr, &low_pc, NULL);
					if (res != DW_DLV_OK) {
						printf ("ERROR: load_globals_or_functions :: dwarf_formaddr :: %d\n", __LINE__);
						return res;
					}

					dwarf_dealloc (dbg, attr, DW_DLA_ATTR);
					res = dwarf_attr (cur_die, DW_AT_high_pc, &attr, NULL);
					if (res != DW_DLV_OK) {
						dwarf_dealloc (dbg, attr, DW_DLA_ATTR);
						printf ("ERROR: %d\n", __LINE__);
						return res;
					}

					res = dwarf_whatform (attr, &attr_form, NULL);
					if (res != DW_DLV_OK) {
						dwarf_dealloc (dbg, attr, DW_DLA_ATTR);
						printf ("ERROR: %d\n", __LINE__);
						return res;
					}

					if (attr_form == DW_FORM_addr) {
						res = dwarf_formaddr (attr, &high_pc, NULL);
						if (res != DW_DLV_OK) {
							size = 0;
						} else {
							size = high_pc - low_pc;
						}
					} else {
						res = get_num_from_attr (attr, &size);
						if (res != DW_DLV_OK) {
							size = 0;
						}
					}

					r_cons_printf ("f sym.%s %llu @ 0x%llx\n", diename, size, (ut64) low_pc);
					dwarf_dealloc (dbg, attr, DW_DLA_ATTR);
					dwarf_dealloc (dbg, diename, DW_DLA_STRING);
				}
			}
		}

	next:
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
	return res;
}

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
	Dwarf_Half tag;
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
			}
			res = print_struct_or_union_die (core, offset, indentlevel + 1, addr, isStruct, type, 0); //longlist parameter does not matter here
			if (type == NRM_FORMAT) {
				for (i = 0; i < indentlevel; i++) {
					printf ("  ");
				}
				printf ("}");
			} else if (type == JSON_FORMAT) {
				//printf ("}");
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
		printf ("[*] NEW TAG found: print_value :: %d\n",tag);
		break;
	}
	return res;
}

static int print_member_name (Dwarf_Die die, int type) {
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
		if (membername && strlen (membername) > 0) {
			printf ("%s", membername);
		}
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
static int print_struct_or_union_die (RCore *core, Dwarf_Off offset, int indentlevel, Dwarf_Unsigned startaddr, int isStruct, int type, int longlist) {
	int i = 0;
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

	if (type == JSON_FORMAT) {
		printf ("{");
	} else if (type == C_FORMAT) {
		char *diename = NULL;

		res = dwarf_diename (die, &diename, NULL);
		if (res == DW_DLV_ERROR) {
			dwarf_dealloc (dbg, diename, DW_DLA_STRING);
			printf ("ERROR: print_struct_or_union_die :: dwarf_diename :: %d\n", __LINE__);
			return res;
		} else if (res == DW_DLV_NO_ENTRY) {
			dwarf_dealloc (dbg, diename, DW_DLA_STRING);
			diename = "";
		}

		if (isStruct) {
			printf ("struct %s {\n", diename);
		} else {
			printf ("union %s {\n", diename);
		}

		indentlevel += 1;
		if (strcmp (diename, "")) {
			dwarf_dealloc (dbg, diename, DW_DLA_STRING);
		}
	}

	res = dwarf_child (die, &member, NULL);
	if (res == DW_DLV_ERROR) {
		printf ("ERROR: print_struct_die :: dwarf_child\n");
		dwarf_dealloc (dbg, die, DW_DLA_DIE);
		dwarf_dealloc (dbg, member, DW_DLA_DIE);
		return res;
	}

	while (res != DW_DLV_NO_ENTRY) {
		if (type == NRM_FORMAT || type == C_FORMAT) {
			for (i = 0; i < indentlevel; i++) {
				printf ("  ");
			}
		}

		if (type == C_FORMAT) {
			char *typestr = malloc (8);
			memset (typestr, 0, 8);
			res = get_type_in_str (member, &typestr, indentlevel, longlist);
			if (res == DW_DLV_ERROR) {
				printf ("ERROR: print_struct_or_union_die :: get_type_in_str :: %d\n", __LINE__);
				return res;
			}

			printf ("%s", typestr);
			free (typestr);
		}

		print_member_name (member, type);
		if (type == NRM_FORMAT) {
			printf (" = ");
		} else if (type == JSON_FORMAT) {
			printf (":");
		} else if (type == C_FORMAT && c_format_arrlen_set) {
			c_format_arrlen_set = 0;
			printf (" [%"PFMT64u"]", arrlen);
		}

		if (type != C_FORMAT) {
			Dwarf_Unsigned off = 0;
			Dwarf_Attribute attr = 0;
			ut64 size = 0;
			int inbits = 0;
			res = get_size (member, &size, &inbits);
			if (res == DW_DLV_ERROR) {
				printf ("ERROR: print_struct_or_union_die :: get_size :: %d\n", __LINE__);
				return res;
			}

			if (isStruct) {
				//Get data_member_location (byte offset from start)
				res = dwarf_attr (member, DW_AT_data_member_location, &attr, NULL);
				if (res == DW_DLV_ERROR || res == DW_DLV_NO_ENTRY) {
					printf ("ERROR: print_struct_or_union_die :: dwarf_attr :: %d\n", __LINE__);
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

		if (type == C_FORMAT) {
			printf (";");
		} else {
			printf (",");
		}

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
	} else if (type == C_FORMAT) {
		indentlevel -= 1;
		printf (";\n");
		for (i = 0; i < indentlevel; i++) {
			printf ("  ");
		}
		printf ("}");
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
			{
				Dwarf_Bool ret = 0;
				Dwarf_Die typedie = 0;
				Dwarf_Unsigned off = 0;
				Dwarf_Attribute attr = 0;
				ut64 ptraddress = 0;
				ut64 typesize = 0;
				int inbits = 0;

				res = get_type_die (die, &typedie, NULL);
				if (res == DW_DLV_ERROR) {
					printf ("ERROR: get_address_and_die :: get_type_die :: %d\n", __LINE__);
					dwarf_dealloc (dbg, typedie, DW_DLA_DIE);
					return res;
				}

				res = get_size (typedie, &typesize, &inbits);
				if (res == DW_DLV_ERROR) {
					printf ("ERROR: get_address_and_die :: get_size :: %d\n", __LINE__);
					dwarf_dealloc (dbg, typedie, DW_DLA_DIE);
					return res;
				}

#if 0
				res = dwarf_hasattr (die, DW_AT_data_member_location, &ret, NULL);
				if (res == DW_DLV_ERROR) {
					printf ("ERROR: dwarf_hasattr :: %d\n", __LINE__);
					return res;
				}

				if (ret) {
					res = dwarf_attr (die, DW_AT_data_member_location, &attr, NULL);
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
#endif

				if (typesize == 2) {
					ptraddress = (ut64)*((ut16 *)(core->block + startaddr + off - core->offset));
				} else if (typesize == 4) {
					ptraddress = (ut64)*((ut32 *)(core->block + startaddr + off - core->offset));
				} else if (typesize == 8) {
					ptraddress = (ut64)*((ut64 *)(core->block + startaddr + off - core->offset));
				}

				while (tag == DW_TAG_pointer_type || tag == DW_TAG_const_type ||
						 tag == DW_TAG_volatile_type || tag == DW_TAG_typedef) {
					Dwarf_Die tmpdie = 0;

					res = get_type_die (typedie, &tmpdie, NULL);
					if (res == DW_DLV_ERROR) {
						printf ("ERROR: get_address_and_die :: get_type_die :: %d\n", __LINE__);
						dwarf_dealloc (dbg, typedie, DW_DLA_DIE);
						return res;
					}

					dwarf_dealloc (dbg, typedie, DW_DLA_DIE);
					typedie = tmpdie;

					res = dwarf_tag (typedie, &tag, NULL);
					if (res == DW_DLV_ERROR) {
						printf ("ERROR: get_address_and_die :: dwarf_tag :: %d\n", __LINE__);
						dwarf_dealloc (dbg, typedie, DW_DLA_DIE);
						return res;
					}
				}

				res = get_address_and_die (core, typedie, ptraddress, remain, retdie, retaddr);
				if (res != DW_DLV_OK) {
					printf ("ERROR | NO_ENTRY: get_address_and_die :: get_address_and_die :: %d\n", __LINE__);
				}

				if (typedie != *retdie) {
					dwarf_dealloc (dbg, typedie, DW_DLA_DIE);
				}
				return res;
			}
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
static int print_specific_stuff (RCore *core, ut64 offset, Dwarf_Unsigned startaddr, char *remain, int onlyaddr, int type, int longlist) {
	int res = DW_DLV_ERROR;
	Dwarf_Die die = 0;
	Dwarf_Die member = 0;
	ut64 addr;
	ut64 size = 0;
	int inbits = 0;
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

	res = get_address_and_die (core, die, startaddr, remain, &member, &addr);
	if (res != DW_DLV_OK) {
		printf ("ERROR: print_specific_stuff :: get_address_and_die :: %d\n", __LINE__);
		return res;
	}

	if (onlyaddr) {
		printf ("0x%"PFMT64x"\n", addr);
		return res;
	}

	if (type == C_FORMAT) {
		char *name = 0;
		char *nameref = 0;

		res = dwarf_diename (member, &name, NULL);
		if (res == DW_DLV_ERROR) {
			printf ("ERROR: print_specific_stuff :: dwarf_diename :: %d\n", __LINE__);
			return res;
		}

		nameref = malloc (10);
		if (!nameref) {
			printf("ERROR: print_specific_stuff :: malloc :: %d\n", __LINE__);
			return DW_DLV_ERROR;
		}
		*nameref = 0;
		res = get_type_in_str (member, &nameref, 0, longlist);
		if (res == DW_DLV_ERROR) {
			printf ("ERROR: print_specific_stuff :: get_type_in_str :: %d\n", __LINE__);
			return res;
		}

		printf ("%s%s", nameref, name);
		if (c_format_arrlen_set) {
			c_format_arrlen_set = 0;
			printf (" [%"PFMT64u"];\n", arrlen);
		} else {
			printf (";\n");
		}
		dwarf_dealloc (dbg, name, DW_DLA_STRING);
		free (nameref);
	} else {
		res = get_size (member, &size, &inbits);
		if (res == DW_DLV_ERROR) {
			printf ("ERROR: print_specific_stuff :: get_size::%d\n", __LINE__);
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

		print_value (core, member, addr - core->offset, 0, size, type);
		printf ("\n");
		if (core->offset != oldoffset || core->blocksize != oldblocksize) {
			core->offset = oldoffset;
			core->blocksize = oldblocksize;
			r_core_block_size (core, oldblocksize);
		}
	}
	return 0;
}

static int print_type_and_size (RCore *core, ut64 sdboffset, ut64 startaddr, char *remain) {
	int res = DW_DLV_ERROR;
	Dwarf_Die die = 0;
	Dwarf_Die member = 0;
	char *nameref = NULL;
	int inbits;
	ut64 addr;

	if (sdboffset == 0) {
		printf ("TODO: implemente iddt for variables\n");
		return DW_DLV_ERROR;
	} else {
		res = dwarf_offdie (dbg, sdboffset, &die, NULL);
		if (res != DW_DLV_OK) {
			dwarf_dealloc (dbg, die, DW_DLA_DIE);
			return res;
		}

		res = get_address_and_die (core, die, startaddr, remain, &member, &addr);
		if (res != DW_DLV_OK) {
			printf ("ERROR: print_specific_stuff :: get_address_and_die :: %d\n", __LINE__);
			return res;
		}
	}

	dwarf_dealloc (dbg, die, DW_DLA_DIE);
	die = member;

	nameref = malloc (10);
	if (!nameref) {
		printf("ERROR: print_type_and_size :: malloc :: %d\n", __LINE__);
		return DW_DLV_ERROR;
	}

	*nameref = 0;
	res = get_type_in_str (die, &nameref, 0, 0);
	if (res == DW_DLV_ERROR) {
		printf ("ERROR: print_type_and_size :: get_type_in_str :: %d\n", __LINE__);
		return res;
	}

	addr = 0; //use it as size
	res = get_size (die, &addr, &inbits);
	if (res == DW_DLV_ERROR) {
		printf ("ERROR: print_specific_stuff :: get_size::%d\n", __LINE__);
		return res;
	}

	printf ("%s - %"PFMT64u"\n", nameref, addr);
	return DW_DLV_OK;
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
			load_globals_or_functions (cu_die, 1);
		} else if (flag == 2) {
			load_globals_or_functions (cu_die, 0);
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
					res = print_struct_or_union_die (core, sdboffset, 0, 0, 1, type, 0);
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
					res = print_specific_stuff (core, sdboffset, core->offset, temp, 0, C_FORMAT, longlist);
				} else {
					res = print_struct_or_union_die (core, sdboffset, 0, 0, 1, C_FORMAT, longlist);
					printf (";\n"); // TODO: fix this extra statement
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

			res = print_type_and_size (core, sdboffset, core->offset, temp);
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
					res = print_struct_or_union_die (core, sdboffset, 0, 0, 1, type, 0);
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
					res = print_struct_or_union_die (core, sdboffset, 0, 0, 1, type, 0);
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
