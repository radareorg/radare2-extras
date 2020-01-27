#include "pyc_dis.h"

void init_opname_table () {
    int i;

    for(i = 0; i < 0xff+1; i++)
        op_name[i] = NULL;

    op_name[STOP_CODE] = "STOP_CODE";
    op_name[POP_TOP] = "POP_TOP";
    op_name[ROT_TWO] = "ROT_TWO";
    op_name[ROT_THREE] = "ROT_THREE";
    op_name[DUP_TOP] = "DUP_TOP";
    op_name[ROT_FOUR] = "ROT_FOUR";
    op_name[NOP] = "NOP";
    op_name[UNARY_POSITIVE] = "UNARY_POSITIVE";
    op_name[UNARY_NEGATIVE] = "UNARY_NEGATIVE";
    op_name[UNARY_NOT] = "UNARY_NOT";
    op_name[UNARY_CONVERT] = "UNARY_CONVERT";
    op_name[UNARY_INVERT] = "UNARY_INVERT";
    op_name[BINARY_POWER] = "BINARY_POWER";
    op_name[BINARY_MULTIPLY] = "BINARY_MULTIPLY";
    op_name[BINARY_DIVIDE] = "BINARY_DIVIDE";
    op_name[BINARY_MODULO] = "BINARY_MODULO";
    op_name[BINARY_ADD] = "BINARY_ADD";
    op_name[BINARY_SUBTRACT] = "BINARY_SUBTRACT";
    op_name[BINARY_SUBSCR] = "BINARY_SUBSCR";
    op_name[BINARY_FLOOR_DIVIDE] = "BINARY_FLOOR_DIVIDE";
    op_name[BINARY_TRUE_DIVIDE] = "BINARY_TRUE_DIVIDE";
    op_name[INPLACE_FLOOR_DIVIDE] = "INPLACE_FLOOR_DIVIDE";
    op_name[INPLACE_TRUE_DIVIDE] = "INPLACE_TRUE_DIVIDE";
    op_name[SLICE] = "SLICE";
    op_name[SLICE_1] = "SLICE_1";
    op_name[SLICE_2] = "SLICE_2";
    op_name[SLICE_3] = "SLICE_3";
    op_name[STORE_SLICE] = "STORE_SLICE";
    op_name[STORE_SLICE_1] = "STORE_SLICE_1";
    op_name[STORE_SLICE_2] = "STORE_SLICE_2";
    op_name[STORE_SLICE_3] = "STORE_SLICE_3";
    op_name[DELETE_SLICE] = "DELETE_SLICE";
    op_name[DELETE_SLICE_1] = "DELETE_SLICE_1";
    op_name[DELETE_SLICE_2] = "DELETE_SLICE_2";
    op_name[DELETE_SLICE_3] = "DELETE_SLICE_3";
    op_name[STORE_MAP] = "STORE_MAP";
    op_name[INPLACE_ADD] = "INPLACE_ADD";
    op_name[INPLACE_SUBTRACT] = "INPLACE_SUBTRACT";
    op_name[INPLACE_MULTIPLY] = "INPLACE_MULTIPLY";
    op_name[INPLACE_DIVIDE] = "INPLACE_DIVIDE";
    op_name[INPLACE_MODULO] = "INPLACE_MODULO";
    op_name[STORE_SUBSCR] = "STORE_SUBSCR";
    op_name[DELETE_SUBSCR] = "DELETE_SUBSCR";
    op_name[BINARY_LSHIFT] = "BINARY_LSHIFT";
    op_name[BINARY_RSHIFT] = "BINARY_RSHIFT";
    op_name[BINARY_AND] = "BINARY_AND";
    op_name[BINARY_XOR] = "BINARY_XOR";
    op_name[BINARY_OR] = "BINARY_OR";
    op_name[INPLACE_POWER] = "INPLACE_POWER";
    op_name[GET_ITER] = "GET_ITER";
    op_name[PRINT_EXPR] = "PRINT_EXPR";
    op_name[PRINT_ITEM] = "PRINT_ITEM";
    op_name[PRINT_NEWLINE] = "PRINT_NEWLINE";
    op_name[PRINT_ITEM_TO] = "PRINT_ITEM_TO";
    op_name[PRINT_NEWLINE_TO] = "PRINT_NEWLINE_TO";
    op_name[INPLACE_LSHIFT] = "INPLACE_LSHIFT";
    op_name[INPLACE_RSHIFT] = "INPLACE_RSHIFT";
    op_name[INPLACE_AND] = "INPLACE_AND";
    op_name[INPLACE_XOR] = "INPLACE_XOR";
    op_name[INPLACE_OR] = "INPLACE_OR";
    op_name[BREAK_LOOP] = "BREAK_LOOP";
    op_name[WITH_CLEANUP] = "WITH_CLEANUP";
    op_name[LOAD_LOCALS] = "LOAD_LOCALS";
    op_name[RETURN_VALUE] = "RETURN_VALUE";
    op_name[IMPORT_STAR] = "IMPORT_STAR";
    op_name[EXEC_STMT] = "EXEC_STMT";
    op_name[YIELD_VALUE] = "YIELD_VALUE";
    op_name[POP_BLOCK] = "POP_BLOCK";
    op_name[END_FINALLY] = "END_FINALLY";
    op_name[BUILD_CLASS] = "BUILD_CLASS";
    op_name[HAVE_ARGUMENT] = "HAVE_ARGUMENT";
    op_name[STORE_NAME] = "STORE_NAME";
    op_name[DELETE_NAME] = "DELETE_NAME";
    op_name[UNPACK_SEQUENCE] = "UNPACK_SEQUENCE";
    op_name[FOR_ITER] = "FOR_ITER";
    op_name[LIST_APPEND] = "LIST_APPEND";
    op_name[STORE_ATTR] = "STORE_ATTR";
    op_name[DELETE_ATTR] = "DELETE_ATTR";
    op_name[STORE_GLOBAL] = "STORE_GLOBAL";
    op_name[DELETE_GLOBAL] = "DELETE_GLOBAL";
    op_name[DUP_TOPX] = "DUP_TOPX";
    op_name[LOAD_CONST] = "LOAD_CONST";
    op_name[LOAD_NAME] = "LOAD_NAME";
    op_name[BUILD_TUPLE] = "BUILD_TUPLE";
    op_name[BUILD_LIST] = "BUILD_LIST";
    op_name[BUILD_SET] = "BUILD_SET";
    op_name[BUILD_MAP] = "BUILD_MAP";
    op_name[LOAD_ATTR] = "LOAD_ATTR";
    op_name[COMPARE_OP] = "COMPARE_OP";
    op_name[IMPORT_NAME] = "IMPORT_NAME";
    op_name[IMPORT_FROM] = "IMPORT_FROM";
    op_name[JUMP_FORWARD] = "JUMP_FORWARD";
    op_name[JUMP_IF_FALSE_OR_POP] = "JUMP_IF_FALSE_OR_POP";
    op_name[JUMP_IF_TRUE_OR_POP] = "JUMP_IF_TRUE_OR_POP";
    op_name[JUMP_ABSOLUTE] = "JUMP_ABSOLUTE";
    op_name[POP_JUMP_IF_FALSE] = "POP_JUMP_IF_FALSE";
    op_name[POP_JUMP_IF_TRUE] = "POP_JUMP_IF_TRUE";
    op_name[LOAD_GLOBAL] = "LOAD_GLOBAL";
    op_name[CONTINUE_LOOP] = "CONTINUE_LOOP";
    op_name[SETUP_LOOP] = "SETUP_LOOP";
    op_name[SETUP_EXCEPT] = "SETUP_EXCEPT";
    op_name[SETUP_FINALLY] = "SETUP_FINALLY";
    op_name[LOAD_FAST] = "LOAD_FAST";
    op_name[STORE_FAST] = "STORE_FAST";
    op_name[DELETE_FAST] = "DELETE_FAST";
    op_name[RAISE_VARARGS] = "RAISE_VARARGS";
    op_name[CALL_FUNCTION] = "CALL_FUNCTION";
    op_name[MAKE_FUNCTION] = "MAKE_FUNCTION";
    op_name[BUILD_SLICE] = "BUILD_SLICE";
    op_name[MAKE_CLOSURE] = "MAKE_CLOSURE";
    op_name[LOAD_CLOSURE] = "LOAD_CLOSURE";
    op_name[LOAD_DEREF] = "LOAD_DEREF";
    op_name[STORE_DEREF] = "STORE_DEREF";
    op_name[CALL_FUNCTION_VAR] = "CALL_FUNCTION_VAR";
    op_name[CALL_FUNCTION_KW] = "CALL_FUNCTION_KW";
    op_name[CALL_FUNCTION_VAR_KW] = "CALL_FUNCTION_VAR_KW";
    op_name[SETUP_WITH] = "SETUP_WITH";
    op_name[EXTENDED_ARG] = "EXTENDED_ARG";
    op_name[SET_ADD] = "SET_ADD";
    op_name[MAP_ADD] = "MAP_ADD";
}

int r_pyc_disasm (RAsmOp *opstruct, const ut8 *code, RList *cobjs, RList *interned_table, ut64 pc) {
    pyc_code_object *cobj = NULL, *t = NULL;
    ut32 extended_arg = 0, i = 0, oparg;
    st64 start_offset, end_offset;
    RListIter *iter = NULL;

    char *name = NULL;
    char *arg = NULL;
    RList *varnames;
    RList *consts;
    RList *names;
    ut8 op;
  
    r_list_foreach (cobjs, iter, t) {
        start_offset = t->start_offset;
        end_offset = t->end_offset;
        if (pc > start_offset && pc < end_offset) {
            cobj = t;
            break;
        }   
    }

    if (cobj != NULL) {
        /* TODO: adding line number and offset */
        varnames = cobj->varnames->data;
        consts = cobj->consts->data;
        names = cobj->names->data;

        op = code[i];
        i += 1;
        name = op_name[op];
        r_strbuf_set (&opstruct->buf_asm, name);
        if (name == NULL) {
            return 0;
        }
        if (op >= HAVE_ARGUMENT) {
            oparg = code[i] + code[i+1]*256 + extended_arg;
            extended_arg = 0;
            i += 2;
            if (op == EXTENDED_ARG)
                  extended_arg = oparg*65536;
              arg = parse_arg (op, oparg, names, consts, varnames, interned_table);
            if (arg != NULL) {
                r_strbuf_appendf (&opstruct->buf_asm, "%20s", arg);
            }   
        }       
        return i;
    }
    return 0;
}

char *parse_arg (ut8 op, ut32 oparg, RList *names, RList *consts, RList *varnames, RList *interned_table) {
    pyc_object *t = NULL;
    char *arg = NULL;

    switch (op) {
    case DUP_TOPX:
    case UNPACK_SEQUENCE:
    case BUILD_TUPLE:
    case BUILD_LIST: //checked
    case BUILD_SET:
    case JUMP_FORWARD:
    case CONTINUE_LOOP:
    case SETUP_LOOP:
    case BUILD_SLICE:
    case CALL_FUNCTION:
    case POP_JUMP_IF_FALSE:
    case POP_JUMP_IF_TRUE:
    case JUMP_ABSOLUTE:
    case JUMP_IF_TRUE_OR_POP:
    case JUMP_IF_FALSE_OR_POP:
    case LOAD_CLOSURE:
    case LOAD_DEREF:
    case CALL_FUNCTION_KW:
        arg = r_str_newf ("%u", oparg);
    break;
    case LOAD_FAST:
    case STORE_FAST:
    case DELETE_FAST:
        t = (pyc_object*)r_list_get_n (varnames, oparg);
        if (t == NULL)
            return NULL;
        arg = t->data;
    break;
    case LOAD_CONST:
        t = (pyc_object*)r_list_get_n (consts, oparg);
        if (t == NULL)
            return NULL;
        switch (t->type) {
        case TYPE_CODE_v1:
            arg = strdup("CodeObject");
        break;
        case TYPE_TUPLE:
            arg = generic_array_obj_to_string (t->data);
        break;
        case TYPE_STRING:
        case TYPE_INTERNED:
        case TYPE_STRINGREF:
            arg = r_str_newf ("'%s'", t->data);
        break;
        default:
            arg = t->data;
        }
    break;
    case STORE_NAME:
    case STORE_ATTR:
    case LOAD_NAME:
    case LOAD_ATTR:
    case IMPORT_NAME:
    case IMPORT_FROM:
    case LOAD_GLOBAL:
        t = (pyc_object*)r_list_get_n (names, oparg);
        if (t == NULL)
            return NULL;
        arg = t->data;
    break;
    }
    return arg;
}

/* for debugging purpose */
void dump (RList *l) {
    RListIter *it;
    pyc_object *e = NULL;

    r_list_foreach (l, it, e) {
        if (e->type == TYPE_TUPLE) {
            eprintf ("[TYPE_TUPLE] %s\n", generic_array_obj_to_string(e->data));
            return;
        }
        eprintf("[DATA] %s\n", (char *)e->data);
    }
}

char *generic_array_obj_to_string (RList *l) {
    RListIter *iter = NULL;
    pyc_object *e = NULL;
    ut32 size = 256, used = 0;
    char *r = NULL, *buf = NULL;

    // add good enough space
    buf = (char*)calloc (size+10, 1);
    r_list_foreach (l, iter, e) {
        while ( !(strlen (e->data) < size) ) {
            size *= 2;
            buf = realloc (buf, used + size);
            if (!buf) {
                eprintf ("generic_array_obj_to_string cannot request more memory");
                return NULL;
            }
        }
        strcat (buf, e->data);
        strcat (buf, ",");
        size -= strlen (e->data) + 1;
        used += strlen (e->data) + 1;
    }
    /* remove last , */
    buf[ strlen(buf)-1 ] = '\0';
    r = r_str_newf ("(%s)", buf);
    free(buf);
    return r;
}

void dump_cobj (pyc_code_object *c) {
    eprintf("[DUMP]\n");
    eprintf("name: %s\n", (char *)c->name->data);
    eprintf("const_start\n");
    dump(c->consts->data);
    eprintf("consts_end\n");

    eprintf("names_start\n");
    dump(c->names->data);
    eprintf("names_end\n");

    eprintf("varnames_start\n");
    dump(c->varnames->data);
    eprintf("varnames_end\n");
}
