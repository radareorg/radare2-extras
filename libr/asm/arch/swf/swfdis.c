/* radare - LGPL3 - Copyright 2016-2017 - xarkes */

#include "swfdis.h"
#include "swf_op.h"

swf_op_t r_asm_swf_getop(ut8 opCode) {
	int i;
	for (i = 0; swf_op[i].name != NULL; i++) {
		if (opCode == swf_op[i].op) {
			return swf_op[i];
		}
	}
	return SWF_OP_UNKNOWN;
}

swf_tag_t r_asm_swf_gettag(ut16 tagCode) {
	int i;
	for (i = 0; swf_tag[i].name != NULL; i++) {
		if (tagCode == swf_tag[i].tag) {
			return swf_tag[i];
		}
	}
	return SWF_TAG_UNKNOWN;
}

int r_asm_swf_disass(RBinObject *obj, char* buf_asm, const ut8* buf, int len, ut64 pc) {
	ut8 isTag = false;
	int dlen = 0;
	RListIter *it;
	RBinSection *sect;

	r_list_foreach(obj->sections, it, sect) {
		if (pc == sect->vaddr) {
			isTag = true;
			break;
		}
	}

	if (isTag && len > 1) {
		dlen = 2;
		ut16 tagCodeAndLength = 0;
		ut16 tagCode = 0;
		ut32 tagLength;
		tagCodeAndLength = buf[0] + (buf[1] << 8);

		tagCode = tagCodeAndLength >> 6;
		tagLength = tagCodeAndLength & 0x3f;

		if (tagLength >= 0x3f) {
			dlen = 6;
		}
		swf_tag_t tag = r_asm_swf_gettag (tagCode);

		switch (tagCode) {
		case TAG_SETBACKGROUNDCOLOR: {
			ut8 red = buf[2];
			ut8 green = buf[3];
			ut8 blue = buf[4];
			sprintf (buf_asm, "Color(%u,%u,%u)", red, green, blue);
			dlen = 5;
			break;
		}
		default:
			strcpy (buf_asm, tag.name);
			break;

		}

	} else {
		swf_op_t op = r_asm_swf_getop (buf[0]);
		switch (op.op) {
		case SWFACTION_PUSH: {
			ut16 len;
			ut8 pushtype;
			len = r_mem_get_num (buf+1, 2);

			ut8 i = 3; // Buffer index
			ut8 l = 0; // String index
			ut8 strsize = 20; // Max size of a push name
			ut8 max = strsize*(len/2); // Max size of the whole opcode name
			char* name = malloc(strsize);
			char* type = malloc(max);
			while (i < len+2) {
				eprintf ("%d, %d\n", i, len+2);
				pushtype = buf[i];
				i += 1;

				switch (pushtype) {
				case 0: { /* String */
					char* str = (char*) (buf+i);
					i += strlen (str);
					snprintf (name,strsize, "str: \"%s\"", str);
					break;
				}
				case 1: { /* Floating point */
					float f = r_mem_get_num (buf+i, 4);
					i += 4;
					sprintf (name, "float: %lf", f);
					break;
				}
				case 2: { /* Null */
					strcpy (name, "null");
					break;
				}
				case 3: { /* Undefined */
					strcpy (name, "undefined");
					break;
				}
				case 4: { /* Register */
					ut8 reg = buf[i];
					sprintf (name, "reg:%u", reg);
					i++;
					break;
				}
				case 5: { /* Boolean */
					sprintf (name, "bool: %s", 
						buf[i] > 0 ? "true" : "false");
					i++;
					break;
				}
				case 6: { /* Double */
					double d = r_mem_get_num (buf+i, 8);
					sprintf (name, "double:%f", d);
					i += 8;
					break;
				}
				case 7: { /* Integer */
					int integer = r_mem_get_num (buf+i, 4);
					sprintf (name, "int:0x%x", integer);
					i += 4;
					break;
				}
				case 8: { /* Constant8 */
					sprintf (name, "const:%u", buf[i]);
					i += 1;
					break;
				}
				case 9: { /* Constant16 */
					ut16 c = r_mem_get_num (buf+i, 2);
					sprintf (name, "const:%u", c);
					i += 2;
					break;
				}
				default:
					strcpy(name, "unknown");
					type = name;
					break;
				}
				if (i < len+2) strcat (name, ", ");
				strncpy (type+l, name, max-l);
				l += strlen(name);
			}
			dlen = 2 + len + 1;
			sprintf (buf_asm, "%s %s", op.name, type);
			break;
		}
		case SWFACTION_GOTOFRAME: {
			ut16 frame = r_mem_get_num (buf+1, 2);
			sprintf (buf_asm, "%s %u", op.name, frame);
			dlen = 3;
			break;
		}
		case SWFACTION_GETURL: {
			char* url = (char*) buf+1;
			snprintf (buf_asm, 1024,"%s %s", op.name, url);
			dlen = strlen (url) + 2;
			break;
		}
		case SWFACTION_JUMP:
		case SWFACTION_BRANCHIFTRUE: {
			short offset = r_mem_get_num (buf+1, 2);
			sprintf (buf_asm, "%s %d", op.name, offset);
			break;
		}
		case SWFACTION_GETURL2: {
			ut8 method = buf[1];
			char* m = malloc (5);
			switch (method) {
			case 1:
				strcpy (m, "GET");
				break;
			case 2:
				strcpy (m, "POST");
				break;
			default:
				strcpy (m, "None");
				break;
			}
			sprintf (buf_asm, "%s %s", op.name, m);
			dlen = 2;
			break;
		}
		case SWFACTION_GOTOFRAME2: {
			dlen = 8;
			ut8 biasFlag = buf[7];
			ut8 playFlag = buf[8];
			if (biasFlag == 1) {
				//ut16 bias = r_mem_get_num (buf+9, 2);
				dlen += 2;
			}
			sprintf (buf_asm, "%s %u %u", op.name, biasFlag, playFlag);
			break;
		}
		case SWFACTION_SETTARGET: {
			char* target = (char*) buf+1;
			sprintf (buf_asm, 1024,"%s %s", op.name, target);
			dlen = 1;
			break;
		}
		case SWFACTION_CONSTANTPOOL: {
			ut16 size = r_mem_get_num (buf+1, 2);
			ut16 count = r_mem_get_num (buf+3, 2);
			sprintf (buf_asm, "%s (nb: %u, size: %u)", op.name, count, size);
			dlen = 5;
			break;
		}
		case SWFACTION_WITH: {
			ut16 size = r_mem_get_num (buf+1, 2);
			sprintf (buf_asm, "%s %u", op.name, size);
			dlen = 3;
			break;
		}
		case SWFACTION_DEFINEFUNCTION: {
			//char* name = (char*) buf+1;
			ut16 nbParams = r_mem_get_num (buf+2, 2);
			ut32 size = 0;
			ut16 i;
			for (i = 0; i < nbParams; i++) {
				char* param = (char*) buf+3+i;
				size += strlen(param);
			}
			//ut16 codeSize = r_mem_get_num (buf+4+i, 2);
			break;
		}
		case SWFACTION_STOREREGISTER: {
			ut8 reg = buf[1];
			sprintf (buf_asm, "%s %u", op.name, reg);
			dlen = 2;
			break;
		}
		default:
			strcpy (buf_asm, op.name);
			dlen = 1;
			break;
		}
	}

	return dlen;
}
