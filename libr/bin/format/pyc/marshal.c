/* radare - LGPL3 - Copyright 2016 - Matthieu (c0riolis) Tardy */

#include <r_io.h>
#include <r_bin.h>
#include <gmp.h>
#include "marshal.h"

#define SIZE32_MAX  0x7FFFFFFF

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

static ut16 get_ut16(RBuffer *buffer, bool *error) {
    ut16 ret = 0;

    int size = r_buf_read(buffer, (ut8*)&ret, sizeof(ret));
    if (size != sizeof(ret))
        *error = true;
    return ret;
}

static ut32 get_ut32(RBuffer *buffer, bool *error) {
    ut32 ret = 0;
    int size = r_buf_read (buffer, (ut8*)&ret, sizeof (ret));
    if (size != sizeof (ret))
        *error = true;
    return ret;
}

static st32 get_st32(RBuffer *buffer, bool *error) {
    st32 ret = 0;
    int size = r_buf_read (buffer, (ut8*)&ret, sizeof (ret));
    if (size < sizeof (ret))
        *error = true;
    return ret;
}

static st64 get_st64(RBuffer *buffer, bool *error) {
    st64 ret = 0;
    int size = r_buf_read(buffer, (ut8 *)&ret, sizeof (ret));
    if ( size < sizeof(ret) )
        *error  = true;
    return ret;
}

static double get_float64(RBuffer *buffer, bool *error) {
    double ret = 0;
    int size = r_buf_read(buffer, (ut8*)&ret, sizeof(ret));
    if ( size < sizeof(ret) )
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
    pyc_object *ret;

    ret = R_NEW0 (pyc_object);
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
    st32 i = get_st32 (buffer, &error);
    if (error) 
        return NULL;
    pyc_object *ret = R_NEW0 (pyc_object);
    if (!ret) 
        return NULL;
    ret->type = TYPE_INT;
    ret->data = r_str_newf ("%d", i);
    if (!ret->data)
        R_FREE (ret);
    return ret;
}

static pyc_object *get_int64_object(RBuffer *buffer) {
    bool error = false;
    st64 i = get_st64(buffer, &error);
    if (error) 
        return NULL;
    pyc_object *ret = R_NEW0 (pyc_object);
    if (!ret) 
        return NULL;
    ret->type = TYPE_INT64;
    ret->data = r_str_newf ("%lld", i);
    if (!ret->data) 
        R_FREE (ret);
    return ret;
}

//long is used when the number is > MAX_INT64
static pyc_object *get_long_object(RBuffer *buffer) {
    pyc_object *ret;
    bool error = false;
    bool neg = false;
    ut16 base = 32768;
    mpz_t pow, N, s;
    int i;

    st32 ndigits = get_st32 (buffer, &error);
    if (ndigits < -SIZE32_MAX || ndigits > SIZE32_MAX) {
        eprintf("bad marshal data (long size out of range)");
        return NULL;
    }
    if (error) 
        return NULL;
    ret = R_NEW0 (pyc_object);
    if (!ret) 
        return NULL;
    ret->type = TYPE_LONG;
    if (ndigits < 0) {
        ndigits = -ndigits;
        neg = true;
    }
    mpz_init (pow);
    mpz_init (N);
    mpz_init (s);
    mpz_set_ui (pow, 1);
    //N += digits[i]*(pow); pow *= base
    for (i = 0; i < ndigits; i++) {
        mpz_mul_ui(s, pow, get_ut16(buffer, &error));
        mpz_add(N, N, s);
        mpz_mul_ui(pow, pow, base);
        mpz_set_ui(s, 0);
    }
    if (neg) 
        mpz_neg(N, N);
    char *buf = malloc (mpz_sizeinbase(N, 10) + 2);
    mpz_get_str (buf, 10, N);
    ret->data = buf;
    ret->type = TYPE_LONG;
    mpz_clear (pow);
    mpz_clear (N);
    mpz_clear (s);
    return ret;
}

static pyc_object *get_stringref_object(RBuffer *buffer) {
    pyc_object *ret;
    bool error = false;
    st32 n;

    n = get_st32 (buffer, &error);
    if (error) 
        return NULL;
    ret = R_NEW0 (pyc_object);
    if (!ret) 
        return NULL;
    ret->type = TYPE_INT;
    ret->data = r_str_newf ("%lu", n);
    if (!ret->data)
        R_FREE (ret);
    return ret;
}

static pyc_object *get_float_object(RBuffer *buffer) {
    bool error = false;
    pyc_object *ret;
    ut32 size;
    ut8 n;
    n = get_ut8 (buffer, &error);
    if (error) 
        return NULL;
    ret = R_NEW0 (pyc_object);
    if (!ret) 
        return NULL;
    ut8 *s = malloc (n);
    if (!s) 
        return NULL;
    size = r_buf_read (buffer, s, n);
    if (size != n) {
        R_FREE (s);
        R_FREE (ret);
        return NULL;
    }
    s[n] = '\x00';
    ret->type = TYPE_FLOAT;
    ret->data = s;
    return ret;
}

static pyc_object *get_binary_float_object(RBuffer *buffer) {
    bool error = false;
    pyc_object *ret;
    double f;
    
    f = get_float64 (buffer, &error);
    if (error) 
        return NULL;
    ret = R_NEW0 (pyc_object);
    if (!ret) 
        return NULL;
    ret->type = TYPE_FLOAT;
    ret->data = r_str_newf ("%.15g", f);
    if (!ret->data) {
        R_FREE (ret);
        return NULL;
    }
    return ret;
}

static pyc_object *get_complex_object(RBuffer *buffer) {
    bool error = false;
    pyc_object *ret;
    ut32 size;
    ut8 *buf;
    ut8 n;

    n = get_ut8 (buffer, &error);
    if (error) 
        return NULL;
    buf = (ut8 *)malloc (256);
    size = r_buf_read (buffer, buf, n);
    if (size != n) 
        return NULL;
    buf[n] = '\0'; //=> python convert this string to internal complex object's imag
    ret = R_NEW0 (pyc_object);
    if (!ret) {
        free (buf);
        return NULL;
    }
    ret->type = TYPE_COMPLEX;
    return ret;
}

static pyc_object *get_binary_complex_object(RBuffer *buffer) {
    bool error = false;
    pyc_object *ret;
    double a, b;

    //b+aj
    b = get_float64 (buffer, &error);
    a = get_float64 (buffer, &error);
    if (error) 
        return NULL;
    ret = R_NEW0 (pyc_object);
    if (!ret) 
        return NULL;
    ret->type = TYPE_BINARY_COMPLEX;
    ret->data = r_str_newf ("%.15g+%.15gj", a, b);
    if (!ret->data) {
        R_FREE (ret);
        return NULL;
    }
    return ret;
}

static pyc_object *get_string_object(RBuffer *buffer) {
    bool error = false;
    pyc_object *ret;
    ut32 n;

    n = get_ut32 (buffer, &error);
    if (n < 0 || n > SIZE32_MAX) {
        eprintf("bad marshal data (string size out of range)");
        return NULL;
    }
    if (error) 
        return NULL;
    ret = R_NEW0 (pyc_object);
    if (!ret) 
        return NULL;
    ret->type = TYPE_STRING;
    ret->data = get_bytes (buffer, n);
    if (!ret->data) {
        R_FREE (ret);
        return NULL;
    }
    return ret;
}

static pyc_object *get_unicode_object(RBuffer *buffer) {
    bool error = false;
    pyc_object *ret;
    ut32 n;
    n = get_ut32 (buffer, &error);
    if (n < 0 || n > SIZE32_MAX) {
        eprintf("bad marshal data (unicode size out of range)");
        return NULL;
    }
    if (error) 
        return NULL;
    ret = R_NEW0 (pyc_object);
    ret->type = TYPE_UNICODE;
    ret->data = get_bytes (buffer, n);
    if (!ret->data) {
        R_FREE (ret);
        return NULL;
    }
    return ret;
}

static pyc_object *get_interned_object(RBuffer *buffer) {
    bool error = false;
    pyc_object *ret;
    ut32 n;

    n = get_ut32 (buffer, &error);
    if (error) 
        return NULL;
    ret = R_NEW0 (pyc_object);
    if (!ret) 
        return NULL;
    ret->type = TYPE_STRING;
    ret->data = get_bytes (buffer, n);
    if (!ret->data)
        R_FREE (ret);
    return ret;
}

static pyc_object *get_array_object_generic(RBuffer *buffer, ut32 size) {
    pyc_object *tmp = NULL;
    pyc_object *ret;
    int i;

    ret = R_NEW0 (pyc_object);
    if (!ret) 
        return NULL;
    ret->data = r_list_new ();
    if (!ret->data) {
        free (ret);
        return NULL;
    }
    for (i = 0; i < size; i++) {
        tmp = get_object (buffer);
        if (!tmp) {
            r_list_free (ret->data);
            R_FREE (ret);
            return NULL;
            break;
        }
        if (!r_list_append (ret->data, tmp)) {
            free (tmp);
            r_list_free (ret->data);
            return NULL;
            break;
        }
    }
    return ret;
}

static pyc_object *get_small_tuple_object(RBuffer *buffer) {
    bool error = false;
    pyc_object *ret;
    ut8 n;

    n = get_ut8 (buffer, &error);
    if (error) 
        return NULL;
    ret = get_array_object_generic (buffer, n);
    if (ret) {
        ret->type = TYPE_SMALL_TUPLE;
        return ret;
    }
    return NULL;
}

static pyc_object *get_tuple_object(RBuffer *buffer) {
    bool error = false;
    pyc_object *ret;
    ut32 n;

    n = get_ut32 (buffer, &error);
    if (error) 
        return NULL;
    ret = get_array_object_generic (buffer, n);
    if (ret) {
        ret->type = TYPE_TUPLE;
        return ret;
    }
    return NULL;
}

static pyc_object *get_list_object(RBuffer *buffer) {
    bool error = false;
    pyc_object* ret; 
    ut32 n;

    n = get_ut32 (buffer, &error);
    if (n < 0 || n > SIZE32_MAX) {
        eprintf("bad marshal data (tuple size out of range)");
        return NULL;
    }
    if (error) 
        return NULL;
    ret = get_array_object_generic (buffer, n);
    ret->type = TYPE_LIST;
    return ret;
}

static pyc_object *get_dict_object(RBuffer *buffer) {
    pyc_object *ret, *key, *val;

    ret = R_NEW0 (pyc_object);
    if (!ret) 
        return NULL;
    ret->data = r_list_new ();
    if (!ret->data) {
        R_FREE (ret);
        return NULL;
    }
    for(;;) {
        key = get_object (buffer);
        if (key == NULL) 
            break;
        if (!r_list_append (ret->data, key)) {
            r_list_free (ret->data);
            R_FREE (ret);
            R_FREE (key);
            return NULL;
        }
        val = get_object (buffer);
        r_list_append (ret->data, val);
        if (val == NULL) 
            break;
    }
    ret->type = TYPE_DICT;
    return ret;
}

static pyc_object *get_set_object(RBuffer *buffer) {
    bool error = false;
    pyc_object *ret;
    ut32 n;
    
    n = get_ut32 (buffer, &error);
    if (error) {
        return NULL;
    }
    ret = get_array_object_generic (buffer, n);
    if (!ret) 
        return NULL;
    ret->type = TYPE_SET;
    return ret;
}

static pyc_object *get_ascii_object_generic(RBuffer *buffer, ut32 size, bool interned) {
    pyc_object *ret;

    ret = R_NEW0 (pyc_object);
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
    ut32 n;

    n = get_ut32 (buffer, &error);
    if (error)
        return NULL;
    return get_ascii_object_generic (buffer, n, true);
}

static pyc_object *get_ascii_interned_object(RBuffer *buffer) {
    bool error = false;
    ut32 n;

    n = get_ut32 (buffer, &error);
    if (error)
        return NULL;
    return get_ascii_object_generic (buffer, n, true);
}

static pyc_object *get_short_ascii_object(RBuffer *buffer) {
    bool error = false;
    ut8 n;

    n = get_ut8 (buffer, &error);
    if (error)
        return NULL;
    return get_ascii_object_generic (buffer, n, false);
}

static pyc_object *get_short_ascii_interned_object(RBuffer *buffer) {
    bool error = false;
    ut8 n;
    
    n = get_ut8 (buffer, &error);
    if (error)
        return NULL;
    return get_ascii_object_generic (buffer, n, true);
}

static pyc_object *get_ref_object(RBuffer *buffer) {
    bool error = false;
    pyc_object *ret;
    pyc_object *obj;
    ut32 index;

    index = get_ut32 (buffer, &error);
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
    case TYPE_SET:
    case TYPE_FROZENSET:
    case TYPE_ELLIPSIS:
    case TYPE_STOPITER:
    case TYPE_BINARY_COMPLEX:
    case TYPE_BINARY_FLOAT:
    case TYPE_CODE_v0:
    case TYPE_COMPLEX:
    case TYPE_STRINGREF:
    case TYPE_DICT:
    case TYPE_FLOAT:
    case TYPE_INT64:
    case TYPE_INTERNED:
    case TYPE_LIST:
    case TYPE_LONG:
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
    //cobj->kwonlyargcount = get_ut32 (buffer, &error);
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
    case TYPE_INT64:
        ret = get_int64_object(buffer);
        break;
    case TYPE_INTERNED:
        ret = get_interned_object(buffer);
        break;
    case TYPE_STRINGREF:
        ret = get_stringref_object(buffer);
        break;
    case TYPE_FLOAT:
        ret = get_float_object(buffer);
        break;
    case TYPE_BINARY_FLOAT:
        ret = get_binary_float_object(buffer);
        break;
    case TYPE_COMPLEX:
        ret = get_complex_object(buffer);
        break;
    case TYPE_BINARY_COMPLEX:
        ret = get_binary_complex_object(buffer);
        break;
    case TYPE_LIST:
        ret = get_list_object(buffer);
        break;
    case TYPE_LONG:
        ret = get_long_object(buffer);
        break;
    case TYPE_UNICODE:
        ret = get_unicode_object(buffer);
        break;
    case TYPE_DICT:
        ret = get_dict_object(buffer);
        break;
    case TYPE_FROZENSET:
    case TYPE_SET:
        ret = get_set_object(buffer);
        break;
    case TYPE_STOPITER:
        ret = R_NEW0(pyc_object);
        break;
    case TYPE_ELLIPSIS:
        ret = R_NEW0(pyc_object);
        break;
    case TYPE_CODE_v0: 
    case TYPE_UNKNOWN:
        eprintf ("Get not implemented for type 0x%x\n", type);
        return NULL;
    default:
        eprintf ("Undefined type in get_object (0x%x)\n", type);
        return NULL;
    }

    /*
    if (ret == NULL) {
        printf("***%c***\n", type);
    }
    */

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
    //each code object is a section
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
