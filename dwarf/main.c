#ifdef HAVE_STDAFX_H
#include "stdafx.h"
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <libdwarf.h>
//#include <r_util.h>
#include "dwarf.h"
#include "libdwarf.h"

typedef struct {
	size_t bufsize;
	char *buffer;
} strng;

strng empty;
static int read_cu_list(Dwarf_Debug dbg);
static void print_die_data(Dwarf_Debug dbg, Dwarf_Die print_me, int level);
static int get_die_and_siblings(Dwarf_Debug dbg, Dwarf_Die in_die, int in_level);
static void strngcat (strng *dst, strng src1, strng src2, char *delim);
static int get_type_tag (Dwarf_Debug dbg, Dwarf_Die die, Dwarf_Half *tag);
static int get_number (Dwarf_Attribute attr, Dwarf_Unsigned *val);
void make_padding_array (int, int, int*, int);
void indent_output (int level);
static int print_struct_type(Dwarf_Debug dbg, Dwarf_Die die, strng *output);

static void strngcat(strng *dst, strng src1, strng src2, char *delim) {
	size_t dstlen = strlen (src1.buffer) + strlen (src2.buffer) + strlen(delim);
	int flag1 = 0;
	int flag2 = 0;
	char *tmp_buf = NULL;
	if (dst->buffer == src1.buffer) {
		flag1 = 1;
	}
	if (dst->buffer == src2.buffer) {
		flag2 = 1;
	}
	if (dstlen >= dst->bufsize) {
		if (flag2) {
			tmp_buf = strdup (src2.buffer);
		}
		dst->buffer = realloc (dst->buffer, 2*dstlen); //to ammortize extensions
	}

	if (flag1) {
		strcat (dst->buffer, delim);
		strcat (dst->buffer, src2.buffer);
	} else if (flag2) {
		if (!tmp_buf) {
			tmp_buf = strdup (src2.buffer);
		}
		strcpy (dst->buffer, src1.buffer);
		strcat (dst->buffer, delim);
		strcat (dst->buffer, tmp_buf);
	} else {
		strcpy (dst->buffer, src1.buffer);
		strcat (dst->buffer, delim);
		strcat (dst->buffer, src2.buffer);
	}
	free (tmp_buf);
}

static strng* strng_new(char *buf) {
	strng *result = malloc(sizeof(strng));
	result->bufsize = 2*strlen(buf);
	result->buffer = malloc (result->bufsize);
	strcpy (result->buffer, buf);
	return result;
}

static void strng_free(strng *str) {
	free (str->buffer);
	free (str);
}

int main(int argc, char **argv) {
	empty.bufsize = 0;
	empty.buffer = NULL;
	Dwarf_Debug dbg = 0;
	int fd = -1;
	int res = DW_DLV_ERROR;
	Dwarf_Error error = 0;
	Dwarf_Handler errhand = 0;
	Dwarf_Ptr errarg = 0;

	if (argc < 2) {
		return -1;
	}
	fd = open(argv[1], O_RDONLY);
	if (fd < 0) {
		return -1;
	}
	res = dwarf_init (fd, DW_DLC_READ, errhand, errarg, &dbg, &error);
	if (res != DW_DLV_OK) {
		return -1;
	}
	res = read_cu_list(dbg);
	if (res != 0) {
		return -1;
	}
	dwarf_dealloc(dbg, error, DW_DLA_ERROR);
	res = dwarf_finish(dbg, &error);
	if (res != DW_DLV_OK) {
		printf ("dwarf_finish failed\n");
	}
	close (fd);
	return 0;
}

static int read_cu_list(Dwarf_Debug dbg) {
	Dwarf_Unsigned cu_header_length = 0;
	Dwarf_Half version_stamp = 0;
	Dwarf_Unsigned abbrev_offset = 0;
	Dwarf_Half address_size = 0;
	Dwarf_Unsigned next_cu_header = 0;
	Dwarf_Error error;
	
	for (;;) {
		Dwarf_Die cu_die = 0;
		int res = DW_DLV_ERROR;

		res = dwarf_next_cu_header (dbg, &cu_header_length, &version_stamp, &abbrev_offset, &address_size, &next_cu_header, &error);
		if (res == DW_DLV_ERROR) {
			continue;
		}
		if (res == DW_DLV_NO_ENTRY) {
			return 0;
		}

		res = dwarf_siblingof (dbg, NULL, &cu_die, &error);
		if (res == DW_DLV_ERROR) {
			printf ("Error in dwarf_siblingof on CU die\n");
		    return 1;
		}
		if (res == DW_DLV_NO_ENTRY) {
			/* Impossible case. */
			printf ("no entry! in dwarf_siblingof on CU die.\n");
		    return -1;
		}
		get_die_and_siblings (dbg, cu_die, 0);//error handling??
		dwarf_dealloc (dbg, cu_die, DW_DLA_DIE);
	}
}

static int get_die_and_siblings(Dwarf_Debug dbg, Dwarf_Die in_die, int in_level) {
	Dwarf_Die cur_die = in_die;
	Dwarf_Die child = 0;
	Dwarf_Error error = 0;
	int res = DW_DLV_ERROR;

	print_die_data (dbg, in_die, in_level);

	for (;;) {
		Dwarf_Die sib_die = 0;
		res = dwarf_child (cur_die, &child, &error);
		if (res == DW_DLV_ERROR) {
			printf ("error in dwarf_child, level %d\n", in_level);
			return -1;
		}
		if (res == DW_DLV_OK) {
			get_die_and_siblings (dbg, child, in_level+1);
		}
		//dwarf_dealloc (dbg, child, DW_DLA_DIE);

		res = dwarf_siblingof (dbg, cur_die, &sib_die, &error);
		if (res == DW_DLV_ERROR) {
			printf ("ERROR: Error in dwarf_siblingof, level %d\n", in_level);
		    return -1;
		}
		if (res == DW_DLV_NO_ENTRY) {
			break;
		}

		if (cur_die != in_die) {
			dwarf_dealloc (dbg, cur_die, DW_DLA_DIE);
		}
		cur_die = sib_die;
		print_die_data (dbg, cur_die, in_level);
	}
	if (cur_die != in_die) {
		dwarf_dealloc (dbg, cur_die, DW_DLA_DIE);
	}
	dwarf_dealloc (dbg, error, DW_DLA_ERROR);
	return 0;
}

#if 0
static int get_type_name(Dwarf_Debug dbg, Dwarf_Die die, char **name) {
	Dwarf_Attribute attr = 0;
	Dwarf_Die typedie = 0;
	Dwarf_Error error = 0;
	int res = DW_DLV_ERROR;
	int offset = 0;
	res = dwarf_attr (die, DW_AT_type, &attr, &error);
	if (res == DW_DLV_ERROR) {
		exit(1);
	}
	if (res == DW_DLV_NO_ENTRY) {
	    res = DW_DLV_ERROR;
		goto ret;
	}
	res = dwarf_global_formref (attr, &offset, &error);
	if (res == DW_DLV_ERROR) {
	    goto ret;
	}
	res = dwarf_offdie (dbg, offset, &typedie, &error);
	if (res != DW_DLV_OK) {
	    res = DW_DLV_ERROR;
		goto ret;
	}
	res = dwarf_diename (typedie, name, &error);
	if (res != DW_DLV_OK && res != DW_DLV_NO_ENTRY) {
	    res = DW_DLV_ERROR;
	}
ret:
	dwarf_dealloc (dbg, attr, DW_DLA_ATTR);
	dwarf_dealloc (dbg, typedie, DW_DLA_DIE);
	dwarf_dealloc (dbg, error, DW_DLA_ERROR);
	return res;
}
#endif

static int get_type_die(Dwarf_Debug dbg, Dwarf_Die die, Dwarf_Die *typedie) {
	Dwarf_Attribute attr = 0;
	Dwarf_Off offset;
	Dwarf_Error error = 0;
	int res = 0;

	res = dwarf_attr (die, DW_AT_type, &attr, &error);
	if (res == DW_DLV_ERROR || res == DW_DLV_NO_ENTRY) {
		goto ret;
	}

	res = dwarf_global_formref (attr, &offset, &error);
	if (res == DW_DLV_ERROR) {
		goto ret;
	}

	res = dwarf_offdie (dbg, offset, typedie, &error);
 ret:
	dwarf_dealloc (dbg, attr, DW_DLA_ATTR);
	dwarf_dealloc (dbg, error, DW_DLA_ERROR);
	return res;
}

static int get_type_name(Dwarf_Debug dbg, Dwarf_Die die, char **name) {
	int res;
	Dwarf_Die typedie = 0;
	Dwarf_Error error = 0;

	res = get_type_die (dbg, die, &typedie);
	if (res == DW_DLV_OK) {
		res = dwarf_diename (typedie, name, &error);
	}
	dwarf_dealloc (dbg, typedie, DW_DLA_DIE);
	dwarf_dealloc (dbg, error, DW_DLA_ERROR);
	return res;
}

static int get_type_tag(Dwarf_Debug dbg, Dwarf_Die die, Dwarf_Half *tag) {
	Dwarf_Die typedie = 0;
	Dwarf_Error error = 0;
	int res;

	res = get_type_die (dbg, die, &typedie);
	if (res == DW_DLV_ERROR || res == DW_DLV_NO_ENTRY) {
	    goto ret;
	}
	res = dwarf_tag (typedie, tag, &error);
	if (res != DW_DLV_OK) {
		res = DW_DLA_ERROR;
		goto ret;
	}
 ret:
	dwarf_dealloc (dbg, typedie, DW_DLA_DIE);
	dwarf_dealloc (dbg, error, DW_DLA_ERROR);
	return res;
}

static int get_number(Dwarf_Attribute attr, Dwarf_Unsigned *val) {
	int res = DW_DLV_ERROR;
	Dwarf_Signed sval = 0;
	Dwarf_Unsigned uval = 0;
	Dwarf_Error error = 0;
	res = dwarf_formudata (attr, &uval, &error);
	if (res == DW_DLV_OK) {
		*val = uval;
		return 0;
	}
	res = dwarf_formsdata (attr, &sval, &error);
	if (res == DW_DLV_OK) {
		*val = sval;
		return 0;
	}
	return -1;
}

static int get_array_length(Dwarf_Debug dbg, Dwarf_Die die, unsigned int *len) {
	Dwarf_Attribute attr = 0;
	Dwarf_Error error = 0;
	Dwarf_Half tag = 0;
	Dwarf_Unsigned bound = 0;
	int res = DW_DLV_ERROR;

	res = dwarf_tag (die, &tag, &error);
	if (res != DW_DLV_OK) {
		printf ("error in getting tag for child of DW_TAG_array_type\n");
		return -1;
	}
	if (tag == DW_TAG_subrange_type) {
		res = dwarf_attr (die, DW_AT_upper_bound, &attr, &error);
		if (res == DW_DLV_ERROR) {
			printf ("Error in DW_AT_upper_bound entry\n");
			return -1;
		}
		if (res == DW_DLV_NO_ENTRY) {
			dwarf_dealloc (dbg, error, DW_DLA_ERROR);
			dwarf_dealloc (dbg, attr, DW_DLA_ATTR);
			*len = 0;
			return -1;
		}
		res = get_number (attr, &bound);
		if (res == 0) {
			*len = bound + 1;
		} else {
			*len = 0;
			res = -1;
		}
		dwarf_dealloc (dbg, error, DW_DLA_ERROR);
		dwarf_dealloc (dbg, attr, DW_DLA_ATTR);
		return res;
	}
	dwarf_dealloc (dbg, attr, DW_DLA_ATTR);
	dwarf_dealloc (dbg, error, DW_DLA_ERROR);
	return -1;
}

int print_type(Dwarf_Debug dbg, Dwarf_Die die, strng *p_name) {
	Dwarf_Attribute attr = 0;
	Dwarf_Off offset;
	Dwarf_Die typedie = 0;
	char *typename = 0;
	int localtype = 0;
	Dwarf_Error error = 0;
	int res = DW_DLV_ERROR;
	Dwarf_Half tag = 0;

	//TODO: before commiting check for function:: dwarf_dietype_offset might reduce few lines from this code
	res = dwarf_attr (die, DW_AT_type, &attr, &error);
	if (res == DW_DLV_ERROR) {
		printf ("lol, error in dwarf_attr in print_type\n");
		dwarf_dealloc (dbg, error, DW_DLA_ERROR);
		return -1;//exit(1);
	}
	if (res == DW_DLV_NO_ENTRY) {
		dwarf_dealloc (dbg, attr, DW_DLA_ATTR);
		dwarf_dealloc (dbg, error, DW_DLA_ERROR);
		strng *tmpstring = strng_new ("void");
		strngcat (p_name, *tmpstring, *p_name, " ");
		strng_free (tmpstring);
		return -1;//return;
	}

	res = dwarf_global_formref (attr, &offset, &error);
	if (res == DW_DLV_ERROR) {
		dwarf_dealloc (dbg, attr, DW_DLA_ATTR);
		dwarf_dealloc (dbg, error, DW_DLA_ERROR);
		return -1;//exit(1);
	}

	res = dwarf_offdie (dbg, offset, &typedie, &error);
	if (res != DW_DLV_OK) {
		dwarf_dealloc (dbg, attr, DW_DLA_ATTR);
		dwarf_dealloc (dbg, error, DW_DLA_ERROR);
		printf ("Error in type dwarf_offdie\n");
		return -1;//exit(1);
	}

	res = dwarf_tag (typedie, &tag, &error);
	if (res != DW_DLV_OK) {
		return -1;//exit(1);
	}

	switch (tag) {
	case DW_TAG_base_type: {
		res = dwarf_diename (typedie, &typename, &error);
		if (res == DW_DLV_ERROR) {
			printf ("Error in type dwarf_diename\n");
			return -1;//exit(1);
		}
		if (res == DW_DLV_NO_ENTRY) {
			typename = "<no DW_AT_name attr>";
			localtype = 1;
		}
		strng *tmpstring = strng_new (typename);
		strngcat(p_name, *tmpstring, *p_name, " ");
		strng_free (tmpstring);
		break;
	}
	case DW_TAG_typedef: {
		res = print_type (dbg, typedie, p_name);
		if (res == -1) {
			res = dwarf_diename (typedie, &typename, &error);
			if (res == DW_DLV_ERROR) {
				break;
			}
			if (res == DW_DLV_NO_ENTRY) {
				typename = "<no DW_AT_name attr>";
				localtype = 1;
			}
			strng *tmpstring = strng_new (typename);
			strngcat (p_name, *tmpstring, *p_name, " ");
			strng_free (tmpstring);
		}
		break;
	}
	case DW_TAG_pointer_type: {
		strng *string1 = strng_new ("*");
		strngcat (p_name, *string1, *p_name, "");
		print_type (dbg, typedie, p_name);
		strng_free (string1);
		break;
	}
	case DW_TAG_structure_type: {
		res = dwarf_diename (typedie, &typename, &error);
		strng *string1;
		strng *string2;
		if (res == DW_DLV_NO_ENTRY) {
			printf ("The thing I fear the most is here\n"); //TODO: FIX it before it gets merged. No harm with pf output. Might create trouble in C output directly from .dwarf_info
			return -1;
		}
		string1 = strng_new ("struct");
		if (res != DW_DLV_OK) {
			string2 = strng_new ("");
			print_type (dbg, typedie, string2);
		} else {
			string2 = strng_new (typename);
		}
		strngcat (string1, *string1, *string2, " ");
		strngcat (p_name, *string1, *p_name, " ");
		strng_free (string1);
		strng_free (string2);
		//dwarf_dealloc (dbg, name, DW_DLA_STRING);
		break;
	}
	case DW_TAG_enumeration_type: {
		strng *string1;
		strng *string2;
		res = dwarf_diename (typedie, &typename, &error);
		if (res == DW_DLV_NO_ENTRY) {
		    return -1;
		}
		string1 = strng_new ("enum");
		if (res != DW_DLV_OK) {
			string2 = strng_new ("");
			print_type (dbg, typedie, string2);
		} else {
		    string2 = strng_new (typename);
		}
		strngcat (string1, *string1, *string2, " ");
		strngcat (p_name, *string1, *p_name, " ");
		strng_free (string1);
		strng_free (string2);
		break;
	}
	case DW_TAG_const_type: {
		print_type (dbg, typedie, p_name);
		strng *string1 = strng_new ("const");
		strngcat (p_name, *string1, *p_name, " ");
		strng_free (string1);
		break;
	}
	case DW_TAG_volatile_type: {
		print_type (dbg, typedie, p_name);
		strng *string1 = strng_new ("volatile");
		strngcat (p_name, *string1, *p_name, " ");
		strng_free (string1);
		break;
	}
	case DW_TAG_union_type: {
		char *name = 0;
		res = dwarf_diename (typedie, &name, &error);
		strng *string1 = strng_new ("union");
		strng *string2;
		if (res == DW_DLV_NO_ENTRY) {
			printf ("lol, not again! :'("); //TODO: FIX IT before it gets merged.
			return -1;
		}
	    if (res != DW_DLV_OK) {
			//string2 = strng_new ("<no DW_AT_name attr>");
			string2 = strng_new ("");
			print_type (dbg, typedie, string2);
		} else {
			string2 = strng_new (name);
		}
		strngcat (string1, *string1, *string2, " ");
		strngcat (p_name, *string1, *p_name, " ");
		strng_free (string1);
		strng_free (string2);
		dwarf_dealloc (dbg, name, DW_DLA_STRING);
		break;
	}
	case DW_TAG_array_type: {
		print_type (dbg, typedie, p_name);
		Dwarf_Die child = 0;
		Dwarf_Die sib = 0;
		res = dwarf_child (typedie, &child, &error);
		if (res == DW_DLV_ERROR) {
			printf ("Error in getting child of DW_TAG_array_type\n");
			dwarf_dealloc (dbg, attr, DW_DLA_ATTR);
			dwarf_dealloc (dbg, error, DW_DLA_ERROR);
			return -1;//exit(1);
		}
		if (res == DW_DLV_NO_ENTRY) {
			printf ("No child entry\n");
			dwarf_dealloc (dbg, attr, DW_DLA_ATTR);
			dwarf_dealloc (dbg, error, DW_DLA_ERROR);
			return -1;//exit(1);
		}

		while (res != DW_DLV_NO_ENTRY) {
			res = dwarf_tag (child, &tag, &error);
			if (res != DW_DLV_OK) {
				printf ("Error in getting tag for child of DW_TAG_array_type\n");
				return -1;//exit(1);
			}
			strng *string1;
			if (tag == DW_TAG_subrange_type) {
				unsigned int arr_len;
				res = get_array_length (dbg, child, &arr_len);
				if (res == -1) {
					string1 = strng_new("[]");
				} else {
					char tmparr[25];
					sprintf (tmparr, "[%u]", arr_len);
					string1 = strng_new (tmparr);
				}
				strngcat (p_name, *p_name, *string1, "");
				strng_free (string1);
			}
			res = dwarf_siblingof (dbg, child, &sib, &error);
			//dwarf_dealloc (dbg, child, DW_DLA_DIE);
			child = sib;
		}
		//dwarf_dealloc (dbg, child, DW_DLA_DIE);
		//dwarf_dealloc (dbg, sib, DW_DLA_DIE);
		break;
	}
	case DW_TAG_subroutine_type: {
		print_type (dbg, typedie, p_name);
		Dwarf_Die child = 0;
		Dwarf_Die sib = 0;
		Dwarf_Half tag = 0;
		res = dwarf_child (typedie, &child, &error);
		if (res == DW_DLV_ERROR) {
			printf ("Error in getting child of subroutine_type\n");
			return -1;//exit(1);
		}
		if (res == DW_DLV_OK) {
			strng *tmpstring = strng_new ("(");
			strng *comstring = strng_new (",");
			strngcat (p_name, *p_name, *tmpstring, " ");
			strng_free (tmpstring);
			while (res != DW_DLV_NO_ENTRY) {
				strng *tmptype = strng_new ("");
				res = dwarf_tag (child, &tag, &error);
				if (res != DW_DLV_OK) {
					printf ("Error in getting tag\n");
					return -1;//exit(1);
				}
				if (tag == DW_TAG_formal_parameter) {
					print_type (dbg, child, tmptype);
					strngcat (p_name, *p_name, *tmptype, "");
					strngcat (p_name, *p_name, *comstring, "");
				}
				res = dwarf_siblingof (dbg, child, &sib, &error);
				if (res == DW_DLV_ERROR) {
					printf ("Error in getting sibling of DW_AT_formal_parameter\n");
					return -1;//exit(1);
				}
				dwarf_dealloc (dbg, child, DW_DLA_DIE);
				child = sib;
				strng_free (tmptype);
			}
			strng_free (comstring);
			tmpstring = strng_new (")");
			strngcat (p_name, *p_name, *tmpstring, "");
			strng_free (tmpstring);
		}
		break;
	}
	default:
		//printf ("\nNOT IMPLEMENTED.\n");
		return tag;//exit(1); Return Tag
	}
	if (!localtype) {
		dwarf_dealloc (dbg, typename, DW_DLA_STRING);
	}
	dwarf_dealloc (dbg, error, DW_DLA_ERROR);
	dwarf_dealloc (dbg, typedie, DW_DLA_DIE);
	dwarf_dealloc (dbg, attr, DW_DLA_ATTR);
	return 0;
}

int get_size (Dwarf_Debug dbg, Dwarf_Die die, unsigned int *size) {
	Dwarf_Unsigned sz = 0;
	Dwarf_Error error = 0;
	Dwarf_Half tag = 0;
	int res = DW_DLV_ERROR;

	res = dwarf_tag (die, &tag, &error);
	if (res != DW_DLV_OK) {
		exit(1);
	}

	switch (tag) {
	case DW_TAG_array_type:
		{
			Dwarf_Die child = 0;
			Dwarf_Die sib_die = 0;
		    int arr_len = 0;
			sz = 1;
			res = dwarf_child (die, &child, &error);
			if (res == DW_DLV_ERROR) {
				printf("either error in getting child entry or there is no entry\n");
				exit(1);
			}
			while (res != DW_DLV_NO_ENTRY) {
				res = dwarf_tag (child, &tag, &error);
				if (res != DW_DLV_OK) {
					printf ("This should not have happened\n");
					exit(1);
				}
			    if (tag == DW_TAG_subrange_type) {
					res = get_array_length (dbg, child, &arr_len);
					if (res == -1) {
						arr_len = 1; //XXX: seems wrong way to do :/
					} else {
						sz *= arr_len;
					}
				}
				res = dwarf_siblingof (dbg, child, &sib_die, &error);
				dwarf_dealloc (dbg, child, DW_DLA_DIE);
				child = sib_die;
			}
			break;
		}
	default:
		res = dwarf_bytesize (die, &sz, &error);
		if (res == DW_DLV_ERROR) {
			exit(1);
		} else if (res == DW_DLV_NO_ENTRY) {
			return -1;
		}
		break;
	}
	*size = sz;
	dwarf_dealloc (dbg, error, DW_DLA_ERROR);
	return 0;
}

//Add this to get_size??? If the die does not have DW_AT_byte_size attribute, then check for type size
int get_type_size (Dwarf_Debug dbg, Dwarf_Die die, unsigned int *size) {
	Dwarf_Attribute attr = 0;
	Dwarf_Off offset;
	Dwarf_Die typedie = 0;
	Dwarf_Error error = 0;
	Dwarf_Unsigned sz = 0;
	int res = DW_DLV_ERROR;
	Dwarf_Half tag = 0;

	res = get_type_die (dbg, die, &typedie);
	if (res != DW_DLV_OK) {
		exit(1);
	}

	res = dwarf_tag (typedie, &tag, &error);
	if (res != DW_DLV_OK) {
		exit(1);
	}

	switch (tag) {
	case DW_TAG_base_type:
	case DW_TAG_pointer_type:
	case DW_TAG_structure_type:
	case DW_TAG_enumeration_type:
	case DW_TAG_union_type:
		//return DW_AT_byte_size
		res = dwarf_bytesize (typedie, &sz, &error);
		if (res == DW_DLV_ERROR) {
			exit(1);
		}
		if (res == DW_DLV_NO_ENTRY) {
			//TODO: should I check for DW_AT_bit_size?? or is it for bitflags?
			dwarf_dealloc (dbg, attr, DW_DLA_ATTR);
			dwarf_dealloc (dbg, error, DW_DLA_ERROR);
			*size = 0;
			exit(1);
			//return -1;
		}
		if (res == DW_DLV_OK)
			*size = sz;
		break;
	case DW_TAG_array_type: //returns total length. e.g. for [3] -> 3 but for [3][2] -> 6
		{
			Dwarf_Die child = 0;
			Dwarf_Die sib_die = 0;
		    int arr_len = 0;
			sz = 1;
			res = dwarf_child (typedie, &child, &error);
			if (res == DW_DLV_ERROR) {
				printf("either error in getting child entry or there is no entry\n");
				exit(1);
			}
			while (res != DW_DLV_NO_ENTRY) {
				res = dwarf_tag (child, &tag, &error);
				if (res != DW_DLV_OK) {
					printf ("This should not have happened\n");
					exit(1);
				}
			    if (tag == DW_TAG_subrange_type) {
					res = get_array_length (dbg, child, &arr_len);
					if (res == -1) {
						arr_len = 1; //XXX: seems wrong way to do :/
					} else {
						sz *= arr_len;
					}
				}
				res = dwarf_siblingof (dbg, child, &sib_die, &error);
				dwarf_dealloc (dbg, child, DW_DLA_DIE);
				child = sib_die;
			}
			*size = sz;
		}
		break;
	case DW_TAG_typedef:
	case DW_TAG_const_type:
	case DW_TAG_volatile_type:
		get_type_size (dbg, typedie, size);
		break;
	case DW_TAG_subroutine_type:
		//TODO: I don't know what todo :/
		break;
	default:
		break;
	}

	dwarf_dealloc (dbg, attr, DW_DLA_ATTR);
	dwarf_dealloc (dbg, error, DW_DLA_ERROR);
	return 0;
}

//Make a patch in libdwarf.h??? similar to dwarf_bytesize in dwarf_query.c
int get_member_location(Dwarf_Debug dbg, Dwarf_Die die, int *off) {
	Dwarf_Attribute attr = 0;
	Dwarf_Error error = 0;
	Dwarf_Unsigned offset = 0;
    int res = DW_DLV_ERROR;

	res = dwarf_attr (die, DW_AT_data_member_location, &attr, &error);
	if (res == DW_DLV_ERROR) {
		printf ("Error:: RED ALERT");
		goto ret;
	}
#if 0
	if (res == DW_DLV_NO_ENTRY) {
		printf ("Are you crazy??\n");
		*off = -1;
		return DW_DLV_ERROR;
	}
#endif

	res = get_number (attr, &offset);
	if (res) {
		*off = -1;
		res = DW_DLV_ERROR;
	} else {
		*off = offset;
		res = DW_DLV_OK;
	}
 ret:
	dwarf_dealloc (dbg, error, DW_DLA_ERROR);
	dwarf_dealloc (dbg, attr, DW_DLA_ATTR);
	return res;
}

static void print_die_data(Dwarf_Debug dbg, Dwarf_Die print_me, int level) {
	char *name = 0;
	Dwarf_Error error = 0;
	Dwarf_Half tag = 0;
	const char *tagname = 0;
	int localname = 0;
	int res = DW_DLV_ERROR;
	strng *typename = 0;

	res = dwarf_diename (print_me, &name, &error);
	if (res == DW_DLV_ERROR) {
		printf ("Error in dwarf_diename, level: %d\n", level);
		return;//exit(1);
	}
	if (res == DW_DLV_NO_ENTRY) {
		dwarf_dealloc (dbg, name, DW_DLA_STRING);
		name = "<no DW_AT_name attr>"; // point to const string
		localname = 1;
		//return;//localname = 1;
	}

	res = dwarf_tag (print_me, &tag, &error);
	if (res != DW_DLV_OK) {
		printf ("Error in dwarf_tag, level %d\n", level);
		return;//exit(1);
	}
	res = dwarf_get_TAG_name (tag, &tagname);
	if (res != DW_DLV_OK) {
		printf ("Error in dawrf_get_TAG_name, level %d\n", level);
		return;//exit(1);
	}
	//#if 0
	//printf ("tag = %s\n", tagname);
	if (tag == DW_TAG_structure_type) {
		//print_c_output (dbg, print_me, NULL, 0);
		typename = strng_new ("");
		print_struct_type (dbg, print_me, typename);
		printf ("%s\n", typename->buffer);
		strng_free (typename);
	}
#if 0

	//printf ("<%d> tag: %d %s name: \"%s\"", level, tag, tagname, name);
	if (!localname)
		dwarf_dealloc (dbg, name, DW_DLA_STRING);
	localname = 1;
	name = "";
	typename = strng_new (name);
	res = print_type (dbg, print_me, typename);
	if (res == 0) {
		printf (" type = %s\n", typename->buffer);
	} else if (res > 0) {
		char ores = res;
		res = dwarf_get_TAG_name (ores, &tagname);
		if (res == 0)
			printf ("type: Type printing for %s is not implemented.\n",tagname);
		else
			printf ("type: Type printing for tag id %d is no implemented.\n", ores);
		exit(1);
	}
	strng_free (typename);
#endif
	//dwarf_dealloc (dbg, , DW_DLA_STRING);
	dwarf_dealloc (dbg, error, DW_DLA_ERROR);
	if (!localname)
		dwarf_dealloc (dbg, name, DW_DLA_STRING);
}


//WIP as of now
//Benefit is that the output is C like, not much work in outputting as get_type function
//get typename in C format.
//problem might come during analysis, might make user uncomfortable looking at the value
//of bytes used for padding. 
int print_c_output(Dwarf_Debug dbg, Dwarf_Die die, char *varname, int level) {
	Dwarf_Half tag = 0;
	Dwarf_Half parent_tag = 0;
	int res = DW_DLV_ERROR;
	char *name;
	Dwarf_Die child = 0;
	Dwarf_Die sib_die = 0;
	Dwarf_Error error = 0;
	int offset = 0;
	int global_size = 0;
	int temp_val = 0;
	int size = 0;
	int i, ret = 0;

	strng *typename;

	//To print only struct
	res = dwarf_tag (die, &tag, &error);
	if (res != DW_DLV_OK) {
		exit(1);//return -1;
	}
	parent_tag = tag;

	if (tag != DW_TAG_structure_type) {
		Dwarf_Die typedie = 0;
		Dwarf_Attribute attr = 0;
		Dwarf_Off off = 0;
	get_type:
		res = dwarf_attr (die, DW_AT_type, &attr, &error);
		if (res == DW_DLV_ERROR || res == DW_DLV_NO_ENTRY) {
			//printf ("");
			dwarf_dealloc (dbg, attr, DW_DLA_ATTR);
			dwarf_dealloc (dbg, error, DW_DLA_ERROR);
			return -1;
		}

		res = dwarf_global_formref (attr, &offset, &error);
		if (res != DW_DLV_OK) {
			dwarf_dealloc (dbg, attr, DW_DLA_ATTR);
			dwarf_dealloc (dbg, error, DW_DLA_ERROR);
			return -1;
		}

		res = dwarf_offdie (dbg, offset, &typedie, &error);
		if (res != DW_DLV_OK) {
			dwarf_dealloc (dbg, attr, DW_DLA_ATTR);
			dwarf_dealloc (dbg, error, DW_DLA_ERROR);
			return -1;
		}
		res = dwarf_tag (typedie, &tag, &error);
		if (res != DW_DLV_OK) {
			return -1;
		}
		switch (tag) {
		case DW_TAG_typedef:
			goto get_type;
			break;
		case DW_TAG_structure_type:
			break;
		default:
			return -1;
		}

		res = dwarf_diename (die, &name, &error);
		if (res == DW_DLV_ERROR) {
			//return -1;
			exit(1); //For the moment to check if the code works properly.
		}
		if (res == DW_DLV_NO_ENTRY && parent_tag == DW_TAG_structure_type) {
			return -1; // come back if struct is used as type from a variable name
		}

		dwarf_dealloc (dbg, typedie, DW_DLA_DIE);
		dwarf_dealloc (dbg, attr, DW_DLA_ATTR);
	}

	//	res = dwarf_diename (die, &name, &error);
	//	if (res == DW_DLV_ERROR) {
	//		//return -1;
	//		exit(1); //For the moment to check if the code works properly.
	//	}

	if (res == DW_DLV_NO_ENTRY) {
		/*
		  struct {		| 	typedef struct {
		  	//members	| 		//members
		  } var_name;   | 	} type_name
		 */

		// maybe return -1 for now and check for each variable if the type if either of typedef struct or struct directly.
		name = "";
		ret = 1;
	}

    indent_output (level);
	printf ("struct %s {\n", name);
	dwarf_dealloc (dbg, name, DW_DLA_STRING);
	//print members
	res = dwarf_child (die, &child, &error);
	if (res == DW_DLV_ERROR) {
		exit(1);
		//return -1;
	}

	for (;;) {
		if (get_type_size (dbg, child, &size)) {
			//TODO: Error handling required
			printf ("size error\n");
			exit(1);
		}
		get_member_location (dbg, child, &offset); //Error handling again
		if (global_size < offset) {
			make_padding_array (offset, global_size, &temp_val, level+1);
		}
		global_size = offset + size;
		res = dwarf_diename (child, &name, &error);
		if (res == DW_DLV_ERROR) {
			exit(1); //Error handling required with proper care here
		}

		typename = strng_new (name);
		res = print_type (dbg, child, typename);
		if (res == -1) {
			//void or unknown type?;
		}

	    indent_output (level+1);
		//print type
		printf ("%s;\n", typename->buffer);

		strng_free (typename);
		dwarf_dealloc (dbg, name, DW_DLA_STRING);

		//change child to next sib
		res = dwarf_siblingof (dbg, child, &sib_die, &error);
		if (res == DW_DLV_ERROR) {
			exit(1);
		}

		if (res == DW_DLV_NO_ENTRY) {
			break;
		}
		dwarf_dealloc (dbg, child, DW_DLA_DIE);
		child = sib_die;
	}
	if (get_size (dbg, die, &size)) {
		printf ("size error\n");
	}
	if (size > global_size) {
		int diff = size - global_size;
		make_padding_array (size, global_size, &temp_val, level+1);
	}

	printf ("};\n");
	dwarf_dealloc (dbg, child, DW_DLA_DIE);
	/*
	  return: 0 = struct name {} don't care;
	  return: 1 = struct {} don't care;
	 */
	return ret;
}

void make_padding_array (int expected, int actual, int* var_val, int level) {
	int diff = expected - actual;
	if (diff/8 != 0) {
		indent_output (level);
		printf ("ut64 temp%d[%d];\n", *var_val, diff/8);
		*var_val = *var_val + 1;
		diff = diff % 8;
	}
	if (diff/4 != 0) {
		indent_output (level);
		printf ("ut32 temp%d[%d];\n", *var_val, diff/4);
		*var_val = *var_val + 1;
		diff = diff % 4;
	}
	if (diff/2 != 0) {
		indent_output (level);
		printf ("ut16 temp%d[%d];\n", *var_val, diff/2);
		*var_val = *var_val + 1;
		diff = diff % 2;
	}
	if (diff != 0) {
		indent_output (level);
		printf ("ut8 temp%d[%d];\n", *var_val, diff);
		*var_val = *var_val + 1;
	}
	return;
}

void indent_output(int level) {
	int i;
	for (i = 0; i < level; i++) {
		printf ("\t");
	}
}

void add_skip_bytes (int expected, int actual, strng *format) {
	int diff = expected - actual;
	char *skipbytes = malloc (25);
	if (diff > 0) {
		if (diff / 4) {
			if (diff / 4 == 1) {
				sprintf (skipbytes, "");
			} else {
				sprintf (skipbytes, "[%d]", diff/4);
			}
			strng *t = strng_new (":");
			strngcat (format, *format, *t, skipbytes);
			strng_free (t);
		}
		if (diff % 4) {
			if (diff % 4 == 1) {
				sprintf (skipbytes, "");
			} else {
				sprintf (skipbytes, "[%d]", diff%4);
			}
			strng *t = strng_new (".");
			strngcat (format, *format, *t, skipbytes);
			strng_free (t);
		}
	}
	free (skipbytes);
}

static int print_struct_type(Dwarf_Debug dbg, Dwarf_Die die, strng *output) {
	Dwarf_Half tag = 0;
	int res;
	char *name = 0;
	Dwarf_Die child = 0;
	Dwarf_Die sib_die = 0;
	Dwarf_Error error = 0;
	int member_offset = 0;
	int global_size = 0;
	int temp_val = 0;
	int size = 0;
	int arr_size = 0;
	char *arr_str = malloc (25);
	int prev_void = 0;
	int prev_member_offset = 0;

	strng *out = strng_new ("pf");
	strng *format = NULL;
	strng *nm = 0;
	strng *arr_strng = 0;

	res = dwarf_diename (die, &name, &error);
	if (res != DW_DLV_NO_ENTRY && res != DW_DLV_OK) {
		printf ("%d\n",__LINE__);
		exit (1);
	} else if (res == DW_DLV_OK) {
		nm = strng_new (name);
	    strngcat (out, *out, *nm, ".");
		strng_free (nm);
	}
	nm = strng_new ("");
	dwarf_dealloc (dbg, name, DW_DLA_STRING);

	res = dwarf_tag (die, &tag, &error);
	if (res != DW_DLV_OK) {
		printf ("%d\n",__LINE__);
		exit (1);
	}
	if (tag == DW_TAG_union_type) {
		format = strng_new ("0");
	} else {
		format = strng_new ("");
	}

	res = dwarf_child (die, &child, &error);
	if (res == DW_DLV_ERROR) {
		printf ("%d\n",__LINE__);
		return -1;
	}

	if (res == DW_DLV_OK) {
		while (res != DW_DLV_NO_ENTRY) {
			strng *namestring;
			Dwarf_Half type_tag;
			Dwarf_Die typedie;
			arr_size = 1;

			//GET_MEMBER_TYPE_AND_TYPE_TAG **start**
			res = get_type_die (dbg, child, &typedie);
			if (res == DW_DLV_NO_ENTRY) {
				printf ("%d\n",__LINE__);
				//exit (1); //void?
			} else if (res == DW_DLV_OK) {
				res = dwarf_tag (typedie, &tag, &error);
				if (res == DW_DLV_ERROR) {
					printf ("%d\n",__LINE__);
					exit(1);
				}
				if (res == DW_DLV_NO_ENTRY) {
					//VOID??
					printf ("%d\n",__LINE__);
					//exit(1);
				}
			} else {
				exit (1);
			}
			//GET_MEMBER_AND_TYPE_TAG **end**

			//FIX_TAG **start**
			Dwarf_Die tmp_die = 0;
			while (tag == DW_TAG_typedef || tag == DW_TAG_volatile_type || tag == DW_TAG_const_type || tag == DW_TAG_array_type) {
			    if (tag == DW_TAG_array_type) {
					if (get_size (dbg, typedie, &size)) {
						printf ("%d\n",__LINE__);
						printf ("size error\n");
						exit(11);
					}
					arr_size *= size;
				}
				res = get_type_die (dbg, typedie, &tmp_die);
				if (res == DW_DLV_ERROR) {
					printf ("%d\n",__LINE__);
					exit (1);
				} else if (res == DW_DLV_NO_ENTRY) {
					printf ("%d\n",__LINE__);
					//break;
					return -1;
					//exit (1); //TODO: void?? ==> YUP
				}
				res = dwarf_tag (tmp_die, &tag, &error);
				if (res != DW_DLV_OK) {
					printf ("%d\n",__LINE__);
					exit(1);
				}

				dwarf_dealloc (dbg, typedie, DW_DLA_DIE);
				typedie = tmp_die;
			}
			//FIX_TAG **end**

			//SET SKIP BYTES **start**
			if (get_type_size (dbg, child, &size)) { //WRONG USAGE BUT RIGHT FUNCTIONALITY :D. FIX THIS
				printf ("%d\n",__LINE__);
				printf ("size error\n");
				exit (1);
			}
			res = get_member_location (dbg, child, &member_offset);
			//if (res != DW_DLV_OK) {
			//	printf ("%d\n",__LINE__);
			//	exit(1);
			//}
			add_skip_bytes (member_offset, global_size, format);
			global_size = member_offset + size * arr_size;
			//SET SKIP BYTES **end**

			if (arr_size > 1) {
				sprintf (arr_str, "[%d]", arr_size);
				arr_strng = strng_new (arr_str);
			}

			//APPEND_FORMAT **start**
			switch (tag) {
#define FS(P) ((size == 1) ? P"1" : ((size == 2) ? P"2" : ((size == 4) ? P"4" : P"8")))
			case DW_TAG_base_type:
				{
					char *typename = 0;
					strng *t_format = 0;
					res = dwarf_diename (typedie, &typename, &error);
					//FIX THIS: better idea is to go by DW_AT_encoding instead of name
					//7: Unsigned and 5: Signed
					if (res == DW_DLV_OK) {
						if (!strncmp (typename, "unsigned", 8) ||
							!strcmp (typename, "long unsigned int") ||
							!strcmp (typename, "short unsigned int") ||
							!strcmp (typename, "long long unsigned int") ||
							!strcmp (typename, "_Bool")) { //or maybe this should be in else to have unsigned or damn, hex??
							t_format = strng_new (FS("N"));
						} else if (!strcmp (typename, "float") ||
								   !strcmp (typename, "double")) {
							t_format = strng_new ((size == 8) ? "q" : "f");
						} else if (!strncmp (typename, "signed", 6) ||
								   !strcmp (typename, "int") ||
								   !strcmp (typename, "char") ||
								   !strcmp (typename, "long long") ||
								   !strcmp (typename, "long long int") ||
								   !strcmp (typename, "long int") ||
								   !strcmp (typename, "short") ||
								   !strcmp (typename, "short int")) {
							t_format = strng_new (FS("n"));
						} else {
							printf ("LOL: this is something new = %s\n", typename);
						}
					} else {
						printf ("%d\n",__LINE__);
						exit (1); //base type without name?? :O
					}
					if (arr_size > 1) {
						strngcat (format, *format, *arr_strng, "");
					}
					strngcat (format, *format, *t_format, "");
					strng_free (t_format);
					dwarf_dealloc (dbg, typename, DW_DLA_STRING);
					break;
				}
			case DW_TAG_pointer_type:
			case DW_TAG_subroutine_type:
				{
					strng *t_format = strng_new (FS("p"));
					if (arr_size > 1) {
						strngcat (format, *format, *arr_strng, "");
					}
					strngcat (format, *format, *t_format, "");
					strng_free (t_format);
					break;
				}
			case DW_TAG_structure_type:
			case DW_TAG_union_type:
				{
					strng *t_format = strng_new ("?");
					if (arr_size > 1) {
						strngcat (format, *format, *arr_strng, "");
					}
					strngcat (format, *format, *t_format, "");
					strng_free (t_format);
					break;
				}
			case DW_TAG_enumeration_type:
				{
					strng *t_format = strng_new (FS("N"));
					if (arr_size > 1) {
						strngcat (format, *format, *arr_strng, "");
					}
					strngcat (format, *format, *t_format, "");
					strng_free (t_format);
					break;
				}
			default:
				break;
#undef FS
			}

			if (arr_size > 1 && arr_strng) {
				strng_free (arr_strng);
			}
			//APPEND_FORMAT **end**

			//APPEND_ARGS **start**
			res = dwarf_diename (child, &name, &error);
			if (res == DW_DLV_ERROR) { //XXX: this might mess pf completely if res == DW_DLV_NO_ENTRY.
				printf ("%d\n",__LINE__);
				exit(1);
			}
			if (res == DW_DLV_NO_ENTRY) {
				namestring = strng_new ("");
			} else {
				namestring = strng_new (name);
			}

			switch (tag) {
			//NAMING OF ANON STRUCT **start**
			case DW_TAG_structure_type:
			case DW_TAG_union_type:
				{
					char *datastruct = 0;

					strng *tmp_string = strng_new ("");
					Dwarf_Die tmp_typedie = 0;
					int ret = 0;

					print_struct_type (dbg, typedie, tmp_string);
					strngcat (namestring, *tmp_string, *namestring, ")");

					strngcat (nm, *nm, *namestring, " (");

					dwarf_dealloc (dbg, tmp_typedie, DW_DLA_DIE);
					dwarf_dealloc (dbg, datastruct, DW_DLA_STRING);
					break;
				}
		    //NAMING OF ANON STRUCT **end**
			default:
				strngcat (nm, *nm, *namestring, " ");
				break;
			}

			strng_free (namestring);
			dwarf_dealloc (dbg, name, DW_DLA_STRING);
			//APPEND_ARGS **end**

			//GET_NEXT_SIBLING **start**
			res = dwarf_siblingof (dbg, child, &sib_die, &error);
			if (res == DW_DLV_ERROR) {
				printf ("%d\n",__LINE__);
				exit (1);
			}
			if (res == DW_DLV_NO_ENTRY) {
				break;
			}

			dwarf_dealloc (dbg, child, DW_DLA_DIE);
			child = sib_die;
			//GET_NEXT_SIBLING **end**
		}

		//ADD_NEXT_SKIP_BYTES **start**
		res = get_size (dbg, die, &size);
#if 0
		//All structure don't have size field
		if (res != 0) {
			printf ("%d\n",__LINE__);
			printf ("size error\n");
			exit(1);
		}
#endif
		add_skip_bytes (size, global_size, format);
		//ADD_NEXT_SKIP_BYTES **end**
	}

	//strngcat (output, *output, *out, "");
	strngcat (output, *out, *format, " ");
	strngcat (output, *output, *nm, " ");
	strng_free (format);
	strng_free (nm);
	strng_free (out);

	dwarf_dealloc (dbg, sib_die, DW_DLA_DIE);
	//dwarf_dealloc (dbg, child, DW_DLA_DIE);
	dwarf_dealloc (dbg, error, DW_DLA_ERROR);
	return 0;
}
