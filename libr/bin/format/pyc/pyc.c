/* radare - LGPL3 - Copyright 2016-2020 - c0riolis, x0urc3 */

#include "pyc.h"
#include "marshal.h"

bool pyc_get_sections(RList *sections, RList *cobjs, RBuffer *buf, ut32 magic) {
	return get_sections_from_code_objects (buf, sections, cobjs);
}

bool pyc_is_object(ut8 b, pyc_marshal_type type) {
    bool ret = false;
	if (b == type) {
        ret = true;
    }
    return ret;
}

bool pyc_is_code(ut8 b) {
    if (pyc_is_object((b & ~FLAG_REF), TYPE_CODE_v1)) {
        return true;
    }
    return false;
}
