#ifndef _INCLUDE_ATOMBIOS_H_
#define _INCLUDE_ATOMBIOS_H_

#include <r_types.h>

#define HEADER_OFFSET	0x48
#define ATOM_MAGIC	(const ut8 *)"ATOM"
#define N_TABLES_CMD	80
#define N_TABLES_DATA	34

typedef struct index_table_s {
    const char  *name;
    const char **tab;
    int          len;
} index_table_t;

enum {
	WS_QUOTIENT = 0x40,
	WS_PRODUCT_LOW32 = 0x40,
	WS_REMAINDER,
	WS_PRODUCT_HI32_XXX = 0x41,
	WS_DATAPTR,
	WS_SHIFT,
	WS_OR_MASK,
	WS_AND_MASK,
	WS_FB_WINDOW,
	WS_ATTRIBUTES,
	WS_REGPTR
};

enum {
    D_REG = 0,
    D_PS,
    D_WS,
    D_FB,
    D_ID,
    D_IM,
    D_PLL,
    D_MC,
    D_hex8,
    D_hex16,
    D_null
};

enum {
    INDEX_NONE = 0,
    INDEX_COMMAND_TABLE,
    INDEX_DATA_TABLE,
    INDEX_ATI_PORT,
    INDEX_WORK_REG,
    INDEX_REG_MM,
    INDEX_REG_PLL,
    INDEX_REG_MC,
    INDEX_REG_PCIE,
    INDEX_REG_PCICONFIG,
    INDEX_REG_SYSTEMIO,
    INDEXTABLE_SIZEOF
};

typedef struct {
    int (*process) (const ut8 *d, char *out);
    const char *name;
    const char *esilop;
    ut8 desttype;
    ut8 srcindex;
    ut8 destindex;
} optab_t;


int atombios_inst_len(const ut8 *buf);
int atombios_disassemble(const ut8 *inbuf, int len, char *outbuf);
const char *get_index (int type, int val);

extern const char *align_source_esil[];
extern const char *align_byte_esil[];
extern const char *align_word_esil[];
extern const char *align_long_esil[];
extern const char *addrtypes_esil[];
extern const char *align_source[];
extern const char *align_byte[];
extern const char *align_word[];
extern const char *align_long[];
extern const int   size_align[];
extern const char *addrnames[];
extern const char *addrtypes[];
extern int addrtypes_shift[];
extern const char *addrtypes_im[];
extern const char *index_command_table[];
extern const char *index_data_table[];
extern const char *index_ati_port[];
extern const char *index_work_reg[];

#define TABENTRY(x) { #x, (index_ ## x), sizeof (index_ ## x) / sizeof (const char **) }

extern index_table_t index_tables[INDEXTABLE_SIZEOF];
extern const optab_t optable[256];

#endif
