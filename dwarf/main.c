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
static Dwarf_Half get_type_tag (Dwarf_Debug dbg, Dwarf_Die die);
static int get_number (Dwarf_Attribute attr, Dwarf_Unsigned *val);
void indent_output (int level);

static void strngcat (strng *dst, strng src1, strng src2, char *delim) {
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
		if (flag2)
			tmp_buf = strdup (src2.buffer);
		dst->buffer = realloc (dst->buffer, 2*dstlen); //to ammortize extensions
	}

	if (flag1) {
		if (strcmp (src2.buffer, "")) { //strcmp (dst->buffer, ""))
			if (strcmp (dst->buffer, ""))
				strcat (dst->buffer, delim);
			strcat (dst->buffer, src2.buffer);
		}
	} else if (flag2) {
		if (!tmp_buf)
			tmp_buf = strdup (src2.buffer);
		strcpy (dst->buffer, src1.buffer);
		if (strcmp (tmp_buf, "")) {
			if (strcmp (dst->buffer, ""))
				strcat (dst->buffer, delim);
			strcat (dst->buffer, tmp_buf);
		}
	} else {
		strcpy (dst->buffer, src1.buffer);
		if (strcmp (tmp_buf, "")) {
			if (strcmp (dst->buffer, ""))
				strcat (dst->buffer, delim);
			strcat (dst->buffer, src2.buffer);
		}
	}
	if (tmp_buf)
		free (tmp_buf);
}

strng* strng_new (char *buf) {
	strng *result = malloc(sizeof(strng));
	result->bufsize = 2*strlen(buf);
	result->buffer = malloc (2*strlen(buf));
	strcpy (result->buffer, buf);
	return result;
}

void strng_free (strng *str) {
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

	if (argc < 2)
		return -1;
	fd = open(argv[1], O_RDONLY);
	if (fd < 0)
		return -1;
	res = dwarf_init (fd, DW_DLC_READ, errhand, errarg, &dbg, &error);
	if (res != DW_DLV_OK)
		return -1;
	res = read_cu_list(dbg);
	if (res != 0)
		return -1;
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

		if (cur_die != in_die)
			dwarf_dealloc (dbg, cur_die, DW_DLA_DIE);
		cur_die = sib_die;
		print_die_data (dbg, cur_die, in_level);
	}
	if (cur_die != in_die)
		dwarf_dealloc (dbg, cur_die, DW_DLA_DIE);
	dwarf_dealloc (dbg, error, DW_DLA_ERROR);
	return 0;
}

#if 0
// Use and improve this if output in pf.xyz format is required.
//Benefit of this is during analysis: since format contains . or : for padding bytes,
//it ignores it and the output is similar to the one that a struct would look like
//(without any random values in between)
//Problem is it might be reimplementation of some stuff and having nested struct/union declaration
static int print_struct_type (Dwarf_Debug dbg, Dwarf_Die die, strng *jsonoutput) {
	Dwarf_Half tag = 0;
	int res = DW_DLV_ERROR;
	char *name;
	Dwarf_Die child = 0;
	Dwarf_Die sib_die = 0;
	Dwarf_Error error = 0;
	int offset = 0;
	int global_size = 0;
	int temp_val = 0;

	strng *out = strng_new("pf.");
    strng *format = strng_new("");
	strng *nm;
	
	res = dwarf_diename (die, &name, &error);
    nm = strng_new(name);
	strngcat (out, *out, *nm, "");
	strng_free (nm);
	nm = strng_new ("");

	res = dwarf_child (die, &child, &error);
	if (res == DW_DLV_ERROR) {
		return -1;
	}

	if (res == DW_DLV_OK) {
		while (res != DW_DLV_NO_ENTRY) {
			tag = get_type_tag (dbg, child);
			int size = 0;
			if (get_type_size (dbg, child, &size)) {
				//TODO: error handling for type_size. Might be based on difference in offset
				printf ("size error\n");
				exit(1);
			}
			get_member_location (dbg, child, &offset);
			if (global_size < offset) {
				int diff = offset - global_size;
				int i;
				strng *skip4 = strng_new (":");
				strng *skip1 = strng_new (".");
				for (i = 0; i < diff/4; i++) {
					strngcat (format, *format, *skip4, "");
				}
				for (i = 0; i < diff%4; i++) {
					strngcat (format, *format, *skip1, "");
				}
				strng_free (skip4);
				strng_free (skip1);
			}
			global_size = offset + size;
			switch (tag) {
			case DW_TAG_base_type:
				{
					strng *typename = strng_new ("");
					res = print_type (dbg, child, typename);
					if (!res) {
						strng *t_format;
						if (size == 8) {
							t_format = strng_new ("q");
							strngcat (format, *format, *t_format, "");
						}
						if (!strcmp (typename->buffer,"int") ||
							!strcmp (typename->buffer, "signed int")) {
							t_format = strng_new ("i");
							strngcat (format, *format, *t_format, "");
						} else if (!strcmp (typename->buffer, "char") ||
								   !strcmp (typename->buffer, "signed char")) {
						    t_format = strng_new ("c");
							strngcat (format, *format, *t_format, "");
							//strng_free (t_format);
						} else if (!strcmp (typename->buffer, "unsigned char")) {
							t_format = strng_new ("b");
							strngcat (format, *format, *t_format, "");
						} else if (!strcmp (typename->buffer, "float")) {
							t_format = strng_new ("f");
							strngcat (format, *format, *t_format, "");
						} else if (!strcmp (typename->buffer, "unsigned int") ||
								   !strcmp (typename->buffer, "unsigned")) {
							t_format = strng_new ("x");
							strngcat (format, *format, *t_format, "");
						} else {
							printf ("NONONO: %s\n", typename->buffer);
							exit(1);
						}
						strng_free (t_format);
					}
					strng_free (typename);
				}
				break;
			case DW_TAG_pointer_type:
				{
				    strng *t_format = strng_new ("p");
					strngcat (format, *format, *t_format, "");
					strng_free (t_format);
				}
				break;
			case DW_TAG_structure_type:
				{
					strng *t_format = strng_new ("");
					
					strng_free (t_format);
				}
				break;
			default:
			    //TODO: not implemented yet.
				printf("Lol!! WTF are you doing?? Get your ass back here and fix my implementation");
				exit(1);
			}

			char *name = 0;
			strng *namestring;
			res = dwarf_diename (child, &name, &error);
			if (res == DW_DLV_ERROR) {
				exit(1);
			}
			if (res == DW_DLV_NO_ENTRY) {
				exit(1);
			}
			namestring = strng_new (name);
			strngcat (nm, *nm, *namestring, " ");
			strng_free (namestring);
			dwarf_dealloc (dbg, name, DW_DLA_STRING);

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
	}

	strngcat (jsonoutput, *jsonoutput, *out, "");
	strngcat (jsonoutput, *jsonoutput, *format, " ");
	strngcat (jsonoutput, *jsonoutput, *nm, " ");
	return 0;
}
#endif

//The following function was supposed to be used with print_struct_type
static Dwarf_Half get_type_tag (Dwarf_Debug dbg, Dwarf_Die die) {
	int res = DW_DLV_ERROR;
	Dwarf_Half tag = 0;
	Dwarf_Error error = 0;
	Dwarf_Die typedie = 0;
	Dwarf_Attribute attr = 0;
	Dwarf_Off offset = 0;

	res = dwarf_attr (die, DW_AT_type, &attr, &error);
	if (res == DW_DLV_ERROR) {
		res = -1;
		printf ("error");
		goto ret;
	}
	if (res == DW_DLV_NO_ENTRY) {
		res = -1;
		printf ("error");
		goto ret;
	}

	res = dwarf_global_formref (attr, &offset, &error);
	if (res == DW_DLV_ERROR) {
		res = -1;
		printf ("error");
		goto ret;
	}

	res = dwarf_offdie (dbg, offset, &typedie, &error);
	if (res != DW_DLV_OK) {
		res = -1;
		printf ("error");
		goto ret;
	}

	res = dwarf_tag (typedie, &tag, &error);
	if (res != DW_DLV_OK) {
		res = -1;
		printf ("error");
		goto ret;
	}
	res = tag;

 ret:
	dwarf_dealloc (dbg, attr, DW_DLA_ATTR);
	dwarf_dealloc (dbg, error, DW_DLA_ERROR);
	dwarf_dealloc (dbg, typedie, DW_DLA_DIE);
	return res;
}

static int get_number (Dwarf_Attribute attr, Dwarf_Unsigned *val) {
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
	    if (res == 0){
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

int print_type (Dwarf_Debug dbg, Dwarf_Die die, strng *p_name) {
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
			printf ("The thing I fear the most is here\n"); //TODO: FIX it before it gets merged
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

int get_type_size (Dwarf_Debug dbg, Dwarf_Die die, unsigned int *size) {
	Dwarf_Attribute attr = 0;
	Dwarf_Off offset;
	Dwarf_Die typedie = 0;
    Dwarf_Error error = 0;
	Dwarf_Unsigned sz = 0;
	int res = DW_DLV_ERROR;
	Dwarf_Half tag = 0;

	res = dwarf_attr (die, DW_AT_type, &attr, &error);
	if (res == DW_DLV_ERROR) {
		dwarf_dealloc (dbg, error, DW_DLA_ERROR);
		exit(1);
	}
	if (res == DW_DLV_NO_ENTRY) {
		*size = 0;
		return -1;
	}

	res = dwarf_global_formref (attr, &offset, &error);
	if (res == DW_DLV_ERROR) {
		*size = 0;
		exit(1);
	}

	res = dwarf_offdie (dbg, offset, &typedie, &error);
	if (res != DW_DLV_OK) {
		dwarf_dealloc (dbg, attr, DW_DLA_ATTR);
		dwarf_dealloc (dbg, error, DW_DLA_ERROR);
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
	case DW_TAG_array_type:
		//TODO
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
	}
	if (res == DW_DLV_NO_ENTRY) {
		printf ("Are you crazy??\n");
		*off = -1;
		return -1;
	}

	res = get_number (attr, &offset);
	if (res) {
		*off = -1;
		res = -1;
	} else {
		*off = offset;
	}
	dwarf_dealloc (dbg, error, DW_DLA_ERROR);
	dwarf_dealloc (dbg, attr, DW_DLA_ATTR);
	return res;
}

static void print_die_data (Dwarf_Debug dbg, Dwarf_Die print_me, int level) {
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
		return;//localname = 1;
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
	if (tag == DW_TAG_structure_type) {
		print_c_output (dbg, print_me, NULL, 0);
		//typename = strng_new ("");
		//print_struct_type (dbg, print_me, typename);
		//printf ("%s\n", typename->buffer);
		//strng_free (typename);
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
	dwarf_dealloc (dbg, error, DW_DLA_STRING);
	dwarf_dealloc (dbg, error, DW_DLA_ERROR);
	if (!localname)
		dwarf_dealloc (dbg, name, DW_DLA_STRING);
}


//WIP as of now
//Benefit is that the output is C like, not much work in outputting as get_type function
//get typename in C format.
//problem might come during analysis, might make user uncomfortable looking at the value
//of bytes used for padding. 
int print_c_output (Dwarf_Debug dbg, Dwarf_Die die, char *varname, int level) {
	Dwarf_Half tag = 0;
	int res = DW_DLV_ERROR;
	char *name;
	Dwarf_Die child = 0;
	Dwarf_Die sib_die = 0;
	Dwarf_Error error = 0;
	int offset = 0;
	int global_size = 0;
	int temp_val = 0;
	int size = 0;
	int i;

	strng *typename;

	res = dwarf_diename (die, &name, &error);
	if (res == DW_DLV_ERROR) {
		//return -1;
		exit(1); //For the moment to check if the code works properly.
	}

	if (res == DW_DLV_NO_ENTRY) {
		/*
		  struct {		| 	typedef struct {
		  	//members	| 		//members
		  } var_name;   | 	} type_name
		 */

		// maybe return -1 for now and check for each variable if the type if either of typedef struct or struct directly.
		name = "";
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
			int diff = offset - global_size;
			if (diff/8 != 0) {
				indent_output (level+1);
				printf ("ut64 temp%d[%d];\n", temp_val++, diff/8);
				diff = diff % 8;
			}
			if (diff/4 != 0) {
				indent_output (level+1);
				printf ("ut32 temp%d[%d];\n", temp_val++, diff/4);
				diff = diff % 4;
			}
			if (diff/2 != 0) {
				indent_output (level+1);
				printf ("ut16 temp%d[%d];\n", temp_val++, diff/2);
				diff = diff % 2;
			}
		    if (diff != 0) {
				indent_output (level+1);
				printf ("ut8 temp%d[%d];\n", temp_val++, diff);
			}
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
	printf ("};\n");
	return 0;
}

void indent_output (int level) {
	int i;
	for (i = 0; i < level; i++) {
		printf ("\t");
	}
}
