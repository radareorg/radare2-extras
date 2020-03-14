#include "opcode.h"

pyc_opcodes *get_opcode_by_version(char *version) {
	if(!strcmp("1.0.1", version))     return opcode_10();
	if(!strcmp("1.1", version))       return opcode_11();
	if(!strcmp("1.2", version))       return opcode_12();
	if(!strcmp("1.3b1", version))     return opcode_13();
	if(!strcmp("1.4", version))       return opcode_14();
	if(!strcmp("1.4b1", version))     return opcode_14();
	if(!strcmp("1.5a1", version))     return opcode_15();
	if(!strcmp("1.6a2", version))     return opcode_16();
	if(!strcmp("2.0b1", version))     return opcode_20();
	if(!strcmp("2.1a1", version))     return opcode_21();
	if(!strcmp("2.1a2", version))     return opcode_21();
	if(!strcmp("2.2a0", version))     return opcode_22();
	if(!strcmp("2.2a1", version))     return opcode_22();
	if(!strcmp("2.3a0", version))     return opcode_23();
	if(!strcmp("2.4a0", version))     return opcode_24();
	if(!strcmp("2.4a2", version))     return opcode_24();
	if(!strcmp("2.4a3", version))     return opcode_24();
	if(!strcmp("2.5a0", version))     return opcode_25();
	if(!strcmp("2.5b2", version))     return opcode_25();
	if(!strcmp("2.5c3", version))     return opcode_25();
	if(!strcmp("2.6a0", version))     return opcode_26();
	if(!strcmp("2.6a1+", version))    return opcode_26();
	if(!strcmp("2.7a0", version))     return opcode_27();
	if(!strcmp("2.7a2+", version))    return opcode_27();
	if(!strcmp("3.0a1", version))     return opcode_30();
	if(!strcmp("3.0a1+", version))    return opcode_30();
	if(!strcmp("3.0a2", version))     return opcode_30();
	if(!strcmp("3.0a2+", version))    return opcode_30();
	if(!strcmp("3.0a3+", version))    return opcode_30();
	if(!strcmp("3.0a5+", version))    return opcode_30();
	if(!strcmp("3.0x", version))      return opcode_30();
	if(!strcmp("3.1a0", version))     return opcode_31();
	if(!strcmp("3.2a0", version))     return opcode_32();
	if(!strcmp("3.2a1+", version))    return opcode_32();
	if(!strcmp("3.2a2+", version))    return opcode_33();
	if(!strcmp("3.3.0a0", version))   return opcode_33();
	if(!strcmp("3.3.0a1+", version))  return opcode_33();
	if(!strcmp("3.3.0a3+", version))  return opcode_33();
	if(!strcmp("3.3a0", version))     return opcode_33();
	if(!strcmp("3.4.0a0", version))   return opcode_34();
	if(!strcmp("3.4.0a3+", version))  return opcode_34();
	if(!strcmp("3.4.0rc1+", version)) return opcode_34();
	if(!strcmp("3.5.0a0", version))   return opcode_35();
	if(!strcmp("3.5.0a4+", version))  return opcode_35();
	if(!strcmp("3.5.0b1+", version))  return opcode_35();
	if(!strcmp("3.5.0b2+", version))  return opcode_35();
	if(!strcmp("3.6.0a0", version))   return opcode_36();
	if(!strcmp("v3.6.0", version))    return opcode_36();
	if(!strcmp("v3.6.0a2", version))  return opcode_36();
	if(!strcmp("v3.6.0a3", version))  return opcode_36();
	if(!strcmp("v3.6.0a4", version))  return opcode_36();
	if(!strcmp("v3.6.0b1", version))  return opcode_36();
	if(!strcmp("v3.6.0b2", version))  return opcode_36();
	if(!strcmp("v3.6.0b3", version))  return opcode_36();
	if(!strcmp("v3.6.0b4", version))  return opcode_36();
	if(!strcmp("v3.6.0rc1", version)) return opcode_36();
	if(!strcmp("v3.6.0rc2", version)) return opcode_36();
	if(!strcmp("v3.6.1", version))    return opcode_36();
	if(!strcmp("v3.6.10", version))   return opcode_36();
	if(!strcmp("v3.6.10rc", version)) return opcode_36();
	if(!strcmp("v3.6.1rc1", version)) return opcode_36();
	if(!strcmp("v3.6.2", version))    return opcode_36();
	if(!strcmp("v3.6.2rc1", version)) return opcode_36();
	if(!strcmp("v3.6.2rc2", version)) return opcode_36();
	if(!strcmp("v3.6.3", version))    return opcode_36();
	if(!strcmp("v3.6.3rc1", version)) return opcode_36();
	if(!strcmp("v3.6.4", version))    return opcode_36();
	if(!strcmp("v3.6.4rc1", version)) return opcode_36();
	if(!strcmp("v3.6.5", version))    return opcode_36();
	if(!strcmp("v3.6.5rc1", version)) return opcode_36();
	if(!strcmp("v3.6.6", version))    return opcode_36();
	if(!strcmp("v3.6.6rc1", version)) return opcode_36();
	if(!strcmp("v3.6.7", version))    return opcode_36();
	if(!strcmp("v3.6.7rc1", version)) return opcode_36();
	if(!strcmp("v3.6.7rc2", version)) return opcode_36();
	if(!strcmp("v3.6.8", version))    return opcode_36();
	if(!strcmp("v3.6.8rc1", version)) return opcode_36();
	if(!strcmp("v3.6.9", version))    return opcode_36();
	if(!strcmp("v3.6.9rc1", version)) return opcode_36();
	if(!strcmp("v3.7.0", version))    return opcode_37();
	if(!strcmp("v3.7.0a1", version))  return opcode_37();
	if(!strcmp("v3.7.0a2", version))  return opcode_37();
	if(!strcmp("v3.7.0a3", version))  return opcode_37();
	if(!strcmp("v3.7.0a4", version))  return opcode_37();
	if(!strcmp("v3.7.0b1", version))  return opcode_37();
	if(!strcmp("v3.7.0b2", version))  return opcode_37();
	if(!strcmp("v3.7.0b3", version))  return opcode_37();
	if(!strcmp("v3.7.0b4", version))  return opcode_37();
	if(!strcmp("v3.7.0b5", version))  return opcode_37();
	if(!strcmp("v3.7.0rc1", version)) return opcode_37();
	if(!strcmp("v3.7.1", version))    return opcode_37();
	if(!strcmp("v3.7.1rc1", version)) return opcode_37();
	if(!strcmp("v3.7.1rc2", version)) return opcode_37();
	if(!strcmp("v3.7.2", version))    return opcode_37();
	if(!strcmp("v3.7.2rc1", version)) return opcode_37();
	if(!strcmp("v3.7.3", version))    return opcode_37();
	if(!strcmp("v3.7.3rc1", version)) return opcode_37();
	if(!strcmp("v3.7.4", version))    return opcode_37();
	if(!strcmp("v3.7.4rc1", version)) return opcode_37();
	if(!strcmp("v3.7.4rc2", version)) return opcode_37();
	if(!strcmp("v3.7.5", version))    return opcode_37();
	if(!strcmp("v3.7.5rc1", version)) return opcode_37();
	if(!strcmp("v3.7.6", version))    return opcode_37();
	if(!strcmp("v3.7.6rc1", version)) return opcode_37();
	if(!strcmp("v3.8.0", version))    return opcode_38();
	if(!strcmp("v3.8.0a1", version))  return opcode_38();
	if(!strcmp("v3.8.0a2", version))  return opcode_38();
	if(!strcmp("v3.8.0a3", version))  return opcode_38();
	if(!strcmp("v3.8.0a4", version))  return opcode_38();
	if(!strcmp("v3.8.0b1", version))  return opcode_38();
	if(!strcmp("v3.8.0b2", version))  return opcode_38();
	if(!strcmp("v3.8.0b3", version))  return opcode_38();
	if(!strcmp("v3.8.0b4", version))  return opcode_38();
	if(!strcmp("v3.8.0rc1", version)) return opcode_38();
	if(!strcmp("v3.8.1", version))    return opcode_38();
	if(!strcmp("v3.8.1rc1", version)) return opcode_38();
	if(!strcmp("v3.9.0a1", version))  return opcode_39();
	if(!strcmp("v3.9.0a2", version))  return opcode_39();
	if(!strcmp("v3.9.0a3", version))  return opcode_39();
	return 0; // No match version
}

pyc_opcodes *new_pyc_opcodes() {
	pyc_opcodes *ret = R_NEW0 (pyc_opcodes);
	if (!ret) {
		return NULL;
    }
	ret->have_argument = 90;
	ret->opcodes = malloc (sizeof(pyc_opcode_object) * 256);
	if (!ret->opcodes) {
		R_FREE (ret);
		return NULL;
	}
	ut16 i = 0;
	for (i = 0; i < 256; i++) {
        ret->opcodes[i].op_name = r_str_newf ("<%u>", i);
        if (!ret->opcodes[i].op_name) {
            for (ut8 j = 0; j < i; j++) {
                free (ret->opcodes[j].op_name);
            }
		    free (ret->opcodes);
		    R_FREE(ret);
		    return NULL;
        }
		ret->opcodes[i].type = 0;
		ret->opcodes[i].op_code = i;
		ret->opcodes[i].op_push = 0;
		ret->opcodes[i].op_pop = 0;
	}

	ret->opcode_arg_fmt = r_list_new ();
	return ret;
}

void free_opcode(pyc_opcodes *opcodes) {
	for(ut16 i = 0; i < 256; i++)
		free (opcodes->opcodes[i].op_name);
	free (opcodes->opcodes);
	r_list_free (opcodes->opcode_arg_fmt);
	R_FREE (opcodes);
}

void add_arg_fmt(pyc_opcodes *ret, const char *op_name, const char *(*formatter) (ut32 oparg)) {
	pyc_arg_fmt *fmt = R_NEW0 (pyc_arg_fmt); 
	fmt->op_name = op_name;
	fmt->formatter = formatter;
	r_list_append (ret->opcode_arg_fmt, fmt);
}

void (def_op) (struct op_parameter par) {
	free (par.op_obj[par.op_code].op_name);
	par.op_obj[par.op_code].op_name = strdup (par.op_name);
	par.op_obj[par.op_code].op_code = par.op_code;
	par.op_obj[par.op_code].op_pop = par.pop;
	par.op_obj[par.op_code].op_push = par.push;
	if (par.fallthrough) {
		par.op_obj[par.op_code].type |= NOFOLLOW;
    }
}

void (name_op) (struct op_parameter par) {
	def_op(.op_obj = par.op_obj, .op_name = par.op_name, .op_code = par.op_code, .pop = par.pop, .push = par.push);
	par.op_obj[par.op_code].type |= HASNAME;
}

void (local_op) (struct op_parameter par) {
	def_op(.op_obj = par.op_obj, .op_name = par.op_name, .op_code = par.op_code, .pop = par.pop, .push = par.push);
	par.op_obj[par.op_code].type |= HASLOCAL;
}

void (free_op) (struct op_parameter par) {
	def_op(.op_obj = par.op_obj, .op_name = par.op_name, .op_code = par.op_code, .pop = par.pop, .push = par.push);
	par.op_obj[par.op_code].type |= HASFREE;
}

void (store_op) (struct op_parameter par) {
	switch (par.func) {
	case NAME_OP:
			name_op (.op_obj = par.op_obj, .op_name = par.op_name, .op_code = par.op_code, .pop = par.pop, .push = par.push);
			break;
	case LOCAL_OP:
			local_op (.op_obj = par.op_obj, .op_name = par.op_name, .op_code = par.op_code, .pop = par.pop, .push = par.push);
			break;
	case FREE_OP:
			free_op (.op_obj = par.op_obj, .op_name = par.op_name, .op_code = par.op_code, .pop = par.pop, .push = par.push);
			break;
	case DEF_OP:
			def_op (.op_obj = par.op_obj, .op_name = par.op_name, .op_code = par.op_code, .pop = par.pop, .push = par.push);
			break;
	default:
            eprintf ("Error in store_op in opcode.c, call function %u.\n", par.func);
			return ;
	}
	par.op_obj[par.op_code].type |= HASSTORE;
}

void (varargs_op) (struct op_parameter par) {
	def_op(.op_obj = par.op_obj, .op_name = par.op_name, .op_code = par.op_code, .pop = par.pop, .push = par.push);
	par.op_obj[par.op_code].type |= HASVARGS;
}

void (const_op) (struct op_parameter par) {
	def_op(.op_obj = par.op_obj, .op_name = par.op_name, .op_code = par.op_code, .pop = par.pop, .push = par.push);
	par.op_obj[par.op_code].type |= HASCONST;
}

void (compare_op) (struct op_parameter par) {
	def_op(.op_obj = par.op_obj, .op_name = par.op_name, .op_code = par.op_code, .pop = par.pop, .push = par.push);
	par.op_obj[par.op_code].type |= HASCOMPARE;
}

void (jabs_op) (struct op_parameter par) {
	def_op(.op_obj = par.op_obj, .op_name = par.op_name, .op_code = par.op_code, .pop = par.pop, .push = par.push, .fallthrough = par.fallthrough);
	par.op_obj[par.op_code].type |= HASJABS;
	if (par.conditional) {
		par.op_obj[par.op_code].type |= HASCONDITION;
    }
}

void (jrel_op) (struct op_parameter par) {
	def_op(.op_obj = par.op_obj, .op_name = par.op_name, .op_code = par.op_code, .pop = par.pop, .push = par.push, .fallthrough = par.fallthrough);
	par.op_obj[par.op_code].type |= HASJREL;
	if (par.conditional) {
		par.op_obj[par.op_code].type |= HASCONDITION;
    }
}

void (nargs_op) (struct op_parameter par) {
	def_op(.op_obj = par.op_obj, .op_name = par.op_name, .op_code = par.op_code, .pop = par.pop, .push = par.push);
	par.op_obj[par.op_code].type |= HASNARGS;
}

void (rm_op) (struct op_parameter par) {
	pyc_opcode_object *op_obj = &par.op_obj[par.op_code];
	if (op_obj->op_code == par.op_code && !strcmp(op_obj->op_name, par.op_name)) {
		free (op_obj->op_name);
		op_obj->op_name = malloc (sizeof(char) * 6);
		snprintf (op_obj->op_name, 6, "<%u>", par.op_code);
		op_obj->type = op_obj->op_pop = op_obj->op_push = 0;
	} else {
		eprintf("Error in rm_op() while constructing opcodes for .pyc file: \n .op_code = %u, .op_name = %s", par.op_code, par.op_name);
	}
}
