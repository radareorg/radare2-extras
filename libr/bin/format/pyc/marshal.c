/* radare - LGPL3 - Copyright 2016 - Matthieu (c0riolis) Tardy */

#include <r_io.h>
#include <r_bin.h>
#include "marshal.h"

static RList *refs = NULL;

static pyc_object *get_object(RBuffer *buffer);
static pyc_object *copy_object(pyc_object *object);
static void free_object(pyc_object *object);

static ut8 get_ut8(RBuffer *buffer, bool *error) {
	ut8 ret = 0;
	int size = r_buf_read (buffer, &ret, sizeof (ret));
	if (size < sizeof (ret))
		*error = true;
	return ret;
}

static ut32 get_ut32(RBuffer *buffer, bool *error) {
	ut32 ret = 0;
	int size = r_buf_read (buffer, (ut8*)&ret, sizeof (ret));
	if (size < sizeof (ret))
		*error = true;
	return ret;
}

static ut8 *get_bytes(RBuffer *buffer, ut32 size) {
	ut8 *ret = R_NEWS0 (ut8, size + 1);
	if (!ret)
		return NULL;
	if (r_buf_read (buffer, ret, size) < size) {
		free (ret);
		return NULL;
	}
	return ret;
}

static pyc_object *get_none_object(void) {
	pyc_object *ret = R_NEW0 (pyc_object);
	if (!ret)
		return NULL;
	ret->type = TYPE_NONE;
	ret->data = strdup ("None");
	if (!ret->data)
		R_FREE (ret);
	return ret;
}

static pyc_object *get_false_object(void) {
	pyc_object *ret = R_NEW0 (pyc_object);
	if (!ret)
		return NULL;
	ret->type = TYPE_FALSE;
	ret->data = strdup ("False");
	if (!ret->data)
		R_FREE (ret);
	return ret;
}

static pyc_object *get_true_object(void) {
	pyc_object *ret = R_NEW0 (pyc_object);
	if (!ret)
		return NULL;
	ret->type = TYPE_TRUE;
	ret->data = strdup ("True");
	if (!ret->data)
		R_FREE (ret);
	return ret;
}

static pyc_object *get_int_object(RBuffer *buffer) {
	bool error = false;
	ut32 i = get_ut32 (buffer, &error);
	pyc_object *ret = R_NEW0 (pyc_object);
	if (!ret || error) {
		free (ret);
		return NULL;
	}
	ret->type = TYPE_INT;
	ret->data = r_str_newf ("%lu", i);
	if (!ret->data)
		R_FREE (ret);
	return ret;
}

static pyc_object *get_string_object(RBuffer *buffer) {
	bool error = false;
	ut32 size = get_ut32 (buffer, &error);
	pyc_object *ret = R_NEW0 (pyc_object);
	if (!ret || error) {
		free (ret);
		return NULL;
	}
	ret->type = TYPE_STRING;
	ret->data = get_bytes (buffer, size);
	if (!ret->data)
		R_FREE (ret);
	return ret;
}

static pyc_object *get_tuple_object_generic(RBuffer *buffer, ut32 size) {
	pyc_object *ret = R_NEW0 (pyc_object);
	if (!ret)
		return NULL;
	ret->type = TYPE_TUPLE;
	ret->data = r_list_new ();
	if (!ret->data) {
		free (ret);
		return NULL;
	}
	for (ut32 i = 0; i < size; ++i) {
		pyc_object *tmp = get_object (buffer);
		if (!tmp) {
			r_list_free (ret->data);
			R_FREE (ret);
			break;
		}
		if (!r_list_append (ret->data, tmp)) {
			free (tmp);
			r_list_free (ret->data);
			break;
		}
	}
	return ret;
}

static pyc_object *get_small_tuple_object(RBuffer *buffer) {
	bool error = false;
	ut8 size = get_ut8 (buffer, &error);
	if (error)
		return NULL;
	return get_tuple_object_generic (buffer, size);
}

static pyc_object *get_tuple_object(RBuffer *buffer) {
	bool error = false;
	ut32 size = get_ut32 (buffer, &error);
	if (error)
		return NULL;
	return get_tuple_object_generic (buffer, size);
}

static pyc_object *get_ascii_object_generic(RBuffer *buffer, ut32 size,
		bool interned) {
	pyc_object *ret = R_NEW0 (pyc_object);
	if (!ret)
		return NULL;
	ret->type = TYPE_ASCII;
	ret->data = get_bytes (buffer, size);
	if (!ret->data)
		R_FREE (ret);
	return ret;
}

static pyc_object *get_ascii_object(RBuffer *buffer) {
	bool error = false;
	ut32 size = get_ut32 (buffer, &error);
	if (error)
		return NULL;
	return get_ascii_object_generic (buffer, size, true);
}

static pyc_object *get_ascii_interned_object(RBuffer *buffer) {
	bool error = false;
	ut32 size = get_ut32 (buffer, &error);
	if (error)
		return NULL;
	return get_ascii_object_generic (buffer, size, true);
}

static pyc_object *get_short_ascii_object(RBuffer *buffer) {
	bool error = false;
	ut8 size = get_ut8 (buffer, &error);
	if (error)
		return NULL;
	return get_ascii_object_generic (buffer, size, false);
}

static pyc_object *get_short_ascii_interned_object(RBuffer *buffer) {
	bool error = false;
	ut8 size = get_ut8 (buffer, &error);
	if (error)
		return NULL;
	return get_ascii_object_generic (buffer, size, true);
}

static pyc_object *get_ref_object(RBuffer *buffer) {
	pyc_object *ret;
	pyc_object *obj;
	bool error = false;
	ut32 index = get_ut32 (buffer, &error);
	if (error || index >= r_list_length (refs))
		return NULL;
	obj = r_list_get_n (refs, index);
	if (!obj)
		return NULL;
	ret = copy_object (obj);
	if (!ret)
		free (obj);
	return ret;
}

void free_object(pyc_object *object) {
	if (!object)
		return;
	switch (object->type) {
	case TYPE_SMALL_TUPLE:
	case TYPE_TUPLE:
		r_list_free (object->data);
		break;
	case TYPE_STRING:
	case TYPE_TRUE:
	case TYPE_FALSE:
	case TYPE_INT:
	case TYPE_NONE:
	case TYPE_NULL:
	case TYPE_ASCII_INTERNED:
	case TYPE_SHORT_ASCII:
	case TYPE_ASCII:
	case TYPE_SHORT_ASCII_INTERNED:
		free (object->data);
		break;
	case TYPE_CODE_v1:
		{
			pyc_code_object *cobj = object->data;
			free_object (cobj->code);
			free_object (cobj->consts);
			free_object (cobj->names);
			free_object (cobj->varnames);
			free_object (cobj->freevars);
			free_object (cobj->cellvars);
			free_object (cobj->filename);
			free_object (cobj->name);
			free_object (cobj->lnotab);
			free (object->data);
		}
		break;
	case TYPE_REF:
		free_object (object->data);
		break;
	case TYPE_ELLIPSIS:
	case TYPE_STOPITER:
	case TYPE_BINARY_COMPLEX:
	case TYPE_BINARY_FLOAT:
	case TYPE_CODE_v0:
	case TYPE_COMPLEX:
	case TYPE_STRINGREF:
	case TYPE_DICT:
	case TYPE_FLOAT:
	case TYPE_FROZENSET:
	case TYPE_INT64:
	case TYPE_INTERNED:
	case TYPE_LIST:
	case TYPE_LONG:
	case TYPE_SET:
	case TYPE_UNICODE:
	case TYPE_UNKNOWN:
		eprintf ("Free not implemented for type %x\n", object->type);
		return;
	default:
		eprintf ("Undefined type in free_object (%x)\n", object->type);
		return;
	}
	free (object);
}

pyc_object *copy_object(pyc_object *object) {
	pyc_object *copy = R_NEW0 (pyc_object);
	if (!copy || !object) {
		free (copy);
		return NULL;
	}
	copy->type = object->type;
	switch (object->type) {
	case TYPE_NULL:
		break;
	case TYPE_TUPLE:
	case TYPE_SMALL_TUPLE:
		copy->data = r_list_clone (object->data);
		break;
	case TYPE_INT:
	case TYPE_NONE:
	case TYPE_TRUE:
	case TYPE_FALSE:
	case TYPE_STRING:
	case TYPE_ASCII:
	case TYPE_SHORT_ASCII:
	case TYPE_ASCII_INTERNED:
	case TYPE_SHORT_ASCII_INTERNED:
		copy->data = strdup (object->data);
		break;
	case TYPE_CODE_v1:
		{
			pyc_code_object *src = object->data;
			pyc_code_object *dst = R_NEW0 (pyc_code_object);
			if (!dst)
				break;
			memcpy (dst, src, sizeof (*dst));
			dst->code = copy_object (src->code);
			dst->consts = copy_object (src->consts);
			dst->names = copy_object (src->names);
			dst->varnames = copy_object (src->varnames);
			dst->freevars = copy_object (src->freevars);
			dst->cellvars = copy_object (src->cellvars);
			dst->filename = copy_object (src->filename);
			dst->name = copy_object (src->name);
			dst->lnotab = copy_object (src->lnotab);
			copy->data = dst;
		}
		break;
	case TYPE_REF:
		copy->data = copy_object (object->data);
		break;
	case TYPE_ELLIPSIS:
	case TYPE_STOPITER:
	case TYPE_BINARY_COMPLEX:
	case TYPE_BINARY_FLOAT:
	case TYPE_CODE_v0:
	case TYPE_COMPLEX:
	case TYPE_STRINGREF:
	case TYPE_DICT:
	case TYPE_FLOAT:
	case TYPE_FROZENSET:
	case TYPE_INT64:
	case TYPE_INTERNED:
	case TYPE_LIST:
	case TYPE_LONG:
	case TYPE_SET:
	case TYPE_UNICODE:
	case TYPE_UNKNOWN:
		eprintf ("Copy not implemented for type %x\n", object->type);
		return NULL;
	default:
		eprintf ("Undefined type in copy_object (%x)\n", object->type);
		return NULL;
	}
	if (!copy->data)
		R_FREE (copy);
	return copy;
}

static pyc_object *get_code_object(RBuffer *buffer) {
	bool error = false;
	pyc_object *ret = R_NEW0 (pyc_object);
	pyc_code_object *cobj = R_NEW0 (pyc_code_object);
	if (!ret || !cobj) {
		free (ret);
		free (cobj);
		return NULL;
	}
	ret->type = TYPE_CODE_v1;
	ret->data = cobj;
	cobj->argcount = get_ut32 (buffer, &error);
	cobj->kwonlyargcount = get_ut32 (buffer, &error);
	cobj->nlocals = get_ut32 (buffer, &error);
	cobj->stacksize = get_ut32 (buffer, &error);
	cobj->flags = get_ut32 (buffer, &error);
	cobj->code = get_object (buffer);
	cobj->consts = get_object (buffer);
	cobj->names = get_object (buffer);
	cobj->varnames = get_object (buffer);
	cobj->freevars = get_object (buffer);
	cobj->cellvars = get_object (buffer);
	cobj->filename = get_object (buffer);
	cobj->name = get_object (buffer);
	cobj->firstlineno = get_ut32 (buffer, &error);
	cobj->lnotab = get_object (buffer);
	if (error) {
		free_object (cobj->code);
		free_object (cobj->consts);
		free_object (cobj->names);
		free_object (cobj->varnames);
		free_object (cobj->freevars);
		free_object (cobj->cellvars);
		free_object (cobj->filename);
		free_object (cobj->name);
		free_object (cobj->lnotab);
		free (cobj);
		R_FREE (ret);
	}
	return ret;
}

static pyc_object *get_object(RBuffer *buffer) {
	RListIter *ref_idx;
	bool error = false;
	pyc_object *ret = NULL;
	ut8 code = get_ut8 (buffer, &error);
	ut8 flag = code & FLAG_REF;
	ut8 type = code & ~FLAG_REF;

	if (error)
		return NULL;
	if (flag) {
		ret = get_none_object ();
		if (!ret)
			return NULL;
		ref_idx = r_list_append (refs, ret);
		if (!ref_idx) {
			free (ret);
			return NULL;
		}
	}
	switch (type) {
	case TYPE_NULL:
		return NULL;
	case TYPE_TRUE:
		return get_true_object ();
	case TYPE_FALSE:
		return get_false_object ();
	case TYPE_NONE:
		return get_none_object ();
	case TYPE_REF:
		return get_ref_object (buffer);
	case TYPE_SMALL_TUPLE:
		ret = get_small_tuple_object (buffer);
		break;
	case TYPE_TUPLE:
		ret = get_tuple_object (buffer);
		break;
	case TYPE_STRING:
		ret = get_string_object (buffer);
		break;
	case TYPE_CODE_v1:
		ret = get_code_object (buffer);
		break;
	case TYPE_INT:
		ret = get_int_object (buffer);
		break;
	case TYPE_ASCII_INTERNED:
		ret = get_ascii_interned_object (buffer);
		break;
	case TYPE_SHORT_ASCII:
		ret = get_short_ascii_object (buffer);
		break;
	case TYPE_ASCII:
		ret = get_ascii_object (buffer);
		break;
	case TYPE_SHORT_ASCII_INTERNED:
		ret = get_short_ascii_interned_object (buffer);
		break;
	case TYPE_BINARY_COMPLEX:
	case TYPE_ELLIPSIS:
	case TYPE_BINARY_FLOAT:
	case TYPE_CODE_v0:
	case TYPE_COMPLEX:
	case TYPE_STRINGREF:
	case TYPE_DICT:
	case TYPE_FLOAT:
	case TYPE_FROZENSET:
	case TYPE_STOPITER:
	case TYPE_INT64:
	case TYPE_INTERNED:
	case TYPE_LIST:
	case TYPE_LONG:
	case TYPE_SET:
	case TYPE_UNICODE:
	case TYPE_UNKNOWN:
		eprintf ("Get not implemented for type %x\n", type);
		return NULL;
	default:
		eprintf ("Undefined type in get_object (%x)\n", type);
		return NULL;
	}
	if (flag) {
		free_object (ref_idx->data);
		ref_idx->data = copy_object (ret);
	}
	return ret;
}

static bool extract_sections(pyc_object *obj, RList *sections, char *prefix) {
	RListIter *i;
	pyc_code_object *cobj;
	RBinSection *section;

	if (!obj || (obj->type != TYPE_CODE_v1))
		return false;
	cobj = obj->data;
	if (!cobj || !cobj->name)
		return false;
	if (cobj->name->type != TYPE_ASCII && cobj->name->type != TYPE_STRING)
		return false;
	if (!cobj->name->data)
		return false;
	section = R_NEW0 (RBinSection);
	prefix = r_str_newf ("%s%s%s", prefix ? prefix : "",
				prefix ? "." : "", cobj->name->data);
	if (!prefix || !section)
		goto fail;
	if (!strncpy ((char*)&section->name, prefix, R_BIN_SIZEOF_STRINGS))
		goto fail;
	if (!r_list_append (sections, section))
		goto fail;
	if (cobj->consts->type != TYPE_TUPLE)
		return false;
	r_list_foreach (((RList*)(cobj->consts->data)), i, obj)
		extract_sections (obj, sections, prefix);
	free (prefix);
	return true;
fail:
	free (section);
	free (prefix);
	return false;
}

bool get_sections_from_code_objects(RBuffer *buffer, RList *sections) {
	bool ret;
	refs = r_list_new ();
	refs->free = (RListFree)free_object;
	ret = extract_sections (get_object (buffer), sections, NULL);
	r_list_free (refs);
	return ret;
}
