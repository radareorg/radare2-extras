/* radare2 - GPL - Copyright 2016 - gde */

#include <stdio.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>

enum instruction_mode {
	NOMODE = -1,
	INHERENT = 0,
	IMMEDIATE,
	IMMEDIATELONG,
	EXTENDED,
	DIRECT,
	RELATIVE,
	RELATIVELONG,
	TFREXG,
	INDEXED,
	PUSHPULLSYSTEM,
	PUSHPULLUSER,
	PAGE2,
	PAGE3,
};

typedef struct mc6809_opcodes_t {
	char *name;
	enum instruction_mode mode;
} mc6809_opcodes_t;

static const mc6809_opcodes_t mc6809_opcodes[256] = {
	/* 0x00 */ {"neg",     DIRECT},
	/* 0x01 */ {"invalid", NOMODE},
	/* 0x02 */ {"invalid", NOMODE},
	/* 0x03 */ {"com",     DIRECT},
	/* 0x04 */ {"lsr",     DIRECT},
	/* 0x05 */ {"invalid", NOMODE},
	/* 0x06 */ {"ror",     DIRECT},
	/* 0x07 */ {"asr",     DIRECT},
	/* 0x08 */ {"asl",     DIRECT},
	/* 0x09 */ {"rol",     DIRECT},
	/* 0x0a */ {"dec",     DIRECT},
	/* 0x0b */ {"invalid", NOMODE},
	/* 0x0c */ {"inc",     DIRECT},
	/* 0x0d */ {"tst",     DIRECT},
	/* 0x0e */ {"jmp",     DIRECT},
	/* 0x0f */ {"clr",     DIRECT},
	/* 0x10 */ {"page 2",  PAGE2},
	/* 0x11 */ {"page 3",  PAGE3},
	/* 0x12 */ {"nop",     INHERENT},
	/* 0x13 */ {"sync",    INHERENT},
	/* 0x14 */ {"invalid", NOMODE},
	/* 0x15 */ {"invalid", NOMODE},
	/* 0x16 */ {"lbra",    RELATIVELONG},
	/* 0x17 */ {"lbsr",    RELATIVELONG},
	/* 0x18 */ {"invalid", NOMODE},
	/* 0x19 */ {"daa",     INHERENT},
	/* 0x1a */ {"orcc",    IMMEDIATE},
	/* 0x1b */ {"invalid", NOMODE},
	/* 0x1c */ {"andcc",   IMMEDIATE},
	/* 0x1d */ {"sex",     INHERENT},
	/* 0x1e */ {"exg",     TFREXG},
	/* 0x1f */ {"tfr",     TFREXG},
	/* 0x20 */ {"bra",     RELATIVE},
	/* 0x21 */ {"brn",     RELATIVE},
	/* 0x22 */ {"bhi",     RELATIVE},
	/* 0x23 */ {"bls",     RELATIVE},
	/* 0x24 */ {"bcc",     RELATIVE},
	/* 0x25 */ {"bcs",     RELATIVE},
	/* 0x26 */ {"bne",     RELATIVE},
	/* 0x27 */ {"beq",     RELATIVE},
	/* 0x28 */ {"bvc",     RELATIVE},
	/* 0x29 */ {"bvs",     RELATIVE},
	/* 0x2a */ {"bpl",     RELATIVE},
	/* 0x2b */ {"bmi",     RELATIVE},
	/* 0x2c */ {"bge",     RELATIVE},
	/* 0x2d */ {"blt",     RELATIVE},
	/* 0x2e */ {"bgt",     RELATIVE},
	/* 0x2f */ {"ble",     RELATIVE},
	/* 0x30 */ {"leax",    INDEXED},
	/* 0x31 */ {"leay",    INDEXED},
	/* 0x32 */ {"leas",    INDEXED},
	/* 0x33 */ {"leau",    INDEXED},
	/* 0x34 */ {"pshs",    PUSHPULLSYSTEM},
	/* 0x35 */ {"puls",    PUSHPULLSYSTEM},
	/* 0x36 */ {"pshu",    PUSHPULLUSER},
	/* 0x37 */ {"pulu",    PUSHPULLUSER},
	/* 0x38 */ {"invalid", NOMODE},
	/* 0x39 */ {"rts",     INHERENT},
	/* 0x3a */ {"abx",     INHERENT},
	/* 0x3b */ {"rti",     INHERENT},
	/* 0x3c */ {"cwai",    IMMEDIATE},
	/* 0x3d */ {"mul",     INHERENT},
	/* 0x3e */ {"invalid", NOMODE},
	/* 0x3f */ {"swi",     INHERENT},
	/* 0x40 */ {"nega",    INHERENT},
	/* 0x41 */ {"invalid", NOMODE},
	/* 0x42 */ {"invalid", NOMODE},
	/* 0x43 */ {"coma",    INHERENT},
	/* 0x44 */ {"lsra",    INHERENT},
	/* 0x45 */ {"invalid", NOMODE},
	/* 0x46 */ {"rora",    INHERENT},
	/* 0x47 */ {"asra",    INHERENT},
	/* 0x48 */ {"asla",    INHERENT},
	/* 0x49 */ {"rola",    INHERENT},
	/* 0x4a */ {"deca",    INHERENT},
	/* 0x4b */ {"invalid", NOMODE},
	/* 0x4c */ {"inca",    INHERENT},
	/* 0x4d */ {"tsta",    INHERENT},
	/* 0x4e */ {"invalid", NOMODE},
	/* 0x4f */ {"clra",    INHERENT},
	/* 0x50 */ {"negb",    INHERENT},
	/* 0x51 */ {"invalid", NOMODE},
	/* 0x52 */ {"invalid", NOMODE},
	/* 0x53 */ {"comb",    INHERENT},
	/* 0x54 */ {"lsrb",    INHERENT},
	/* 0x55 */ {"invalid", NOMODE},
	/* 0x56 */ {"rorb",    INHERENT},
	/* 0x57 */ {"asrb",    INHERENT},
	/* 0x58 */ {"aslb",    INHERENT},
	/* 0x59 */ {"rolb",    INHERENT},
	/* 0x5a */ {"decb",    INHERENT},
	/* 0x5b */ {"invalid", NOMODE},
	/* 0x5c */ {"incb",    INHERENT},
	/* 0x5d */ {"tstb",    INHERENT},
	/* 0x5e */ {"invalid", NOMODE},
	/* 0x5f */ {"clrb",    INHERENT},
	/* 0x60 */ {"neg",     INDEXED},
	/* 0x61 */ {"invalid", NOMODE},
	/* 0x62 */ {"invalid", NOMODE},
	/* 0x63 */ {"com",     INDEXED},
	/* 0x64 */ {"lsr",     INDEXED},
	/* 0x65 */ {"invalid", NOMODE},
	/* 0x66 */ {"ror",     INDEXED},
	/* 0x67 */ {"asr",     INDEXED},
	/* 0x68 */ {"asl",     INDEXED},
	/* 0x69 */ {"rol",     INDEXED},
	/* 0x6a */ {"dec",     INDEXED},
	/* 0x6b */ {"invalid", NOMODE},
	/* 0x6c */ {"inc",     INDEXED},
	/* 0x6d */ {"tst",     INDEXED},
	/* 0x6e */ {"jmp",     INDEXED},
	/* 0x6f */ {"clr",     INDEXED},
	/* 0x70 */ {"neg",     EXTENDED},
	/* 0x71 */ {"invalid", NOMODE},
	/* 0x72 */ {"invalid", NOMODE},
	/* 0x73 */ {"com",     EXTENDED},
	/* 0x74 */ {"lsr",     EXTENDED},
	/* 0x75 */ {"invalid", NOMODE},
	/* 0x76 */ {"ror",     EXTENDED},
	/* 0x77 */ {"asr",     EXTENDED},
	/* 0x78 */ {"asl",     EXTENDED},
	/* 0x79 */ {"rol",     EXTENDED},
	/* 0x7a */ {"dec",     EXTENDED},
	/* 0x7b */ {"invalid", NOMODE},
	/* 0x7c */ {"inc",     EXTENDED},
	/* 0x7d */ {"tst",     EXTENDED},
	/* 0x7e */ {"jmp",     EXTENDED},
	/* 0x7f */ {"clr",     EXTENDED},
	/* 0x80 */ {"suba",    IMMEDIATE},
	/* 0x81 */ {"cmpa",    IMMEDIATE},
	/* 0x82 */ {"sbca",    IMMEDIATE},
	/* 0x83 */ {"subd",    IMMEDIATELONG},
	/* 0x84 */ {"anda",    IMMEDIATE},
	/* 0x85 */ {"bita",    IMMEDIATE},
	/* 0x86 */ {"lda",     IMMEDIATE},
	/* 0x87 */ {"invalid", NOMODE},
	/* 0x88 */ {"eora",    IMMEDIATE},
	/* 0x89 */ {"adca",    IMMEDIATE},
	/* 0x8a */ {"ora",     IMMEDIATE},
	/* 0x8b */ {"adda",    IMMEDIATE},
	/* 0x8c */ {"cmpx",    IMMEDIATELONG},
	/* 0x8d */ {"bsr",     RELATIVE},
	/* 0x8e */ {"ldx",     IMMEDIATELONG},
	/* 0x8f */ {"invalid", NOMODE},
	/* 0x90 */ {"suba",    DIRECT},
	/* 0x91 */ {"cmpa",    DIRECT},
	/* 0x92 */ {"sbca",    DIRECT},
	/* 0x93 */ {"subd",    DIRECT},
	/* 0x94 */ {"anda",    DIRECT},
	/* 0x95 */ {"bita",    DIRECT},
	/* 0x96 */ {"lda",     DIRECT},
	/* 0x97 */ {"sta",     DIRECT},
	/* 0x98 */ {"eora",    DIRECT},
	/* 0x99 */ {"adca",    DIRECT},
	/* 0x9a */ {"ora",     DIRECT},
	/* 0x9b */ {"adda",    DIRECT},
	/* 0x9c */ {"cmpx",    DIRECT},
	/* 0x9d */ {"jsr",     DIRECT},
	/* 0x9e */ {"ldx",     DIRECT},
	/* 0x9f */ {"stx",     DIRECT},
	/* 0xa0 */ {"suba",    INDEXED},
	/* 0xa1 */ {"cmpa",    INDEXED},
	/* 0xa2 */ {"sbca",    INDEXED},
	/* 0xa3 */ {"subd",    INDEXED},
	/* 0xa4 */ {"anda",    INDEXED},
	/* 0xa5 */ {"bita",    INDEXED},
	/* 0xa6 */ {"lda",     INDEXED},
	/* 0xa7 */ {"sta",     INDEXED},
	/* 0xa8 */ {"eora",    INDEXED},
	/* 0xa9 */ {"adca",    INDEXED},
	/* 0xaa */ {"ora",     INDEXED},
	/* 0xab */ {"adda",    INDEXED},
	/* 0xac */ {"cmpx",    INDEXED},
	/* 0xad */ {"jsr",     INDEXED},
	/* 0xae */ {"ldx",     INDEXED},
	/* 0xaf */ {"stx",     INDEXED},
	/* 0xb0 */ {"suba",    EXTENDED},
	/* 0xb1 */ {"cmpa",    EXTENDED},
	/* 0xb2 */ {"sbca",    EXTENDED},
	/* 0xb3 */ {"subd",    EXTENDED},
	/* 0xb4 */ {"anda",    EXTENDED},
	/* 0xb5 */ {"bita",    EXTENDED},
	/* 0xb6 */ {"lda",     EXTENDED},
	/* 0xb7 */ {"sta",     EXTENDED},
	/* 0xb8 */ {"eora",    EXTENDED},
	/* 0xb9 */ {"adca",    EXTENDED},
	/* 0xba */ {"ora",     EXTENDED},
	/* 0xbb */ {"adda",    EXTENDED},
	/* 0xbc */ {"cmpx",    EXTENDED},
	/* 0xbd */ {"jsr",     EXTENDED},
	/* 0xbe */ {"ldx",     EXTENDED},
	/* 0xbf */ {"stx",     EXTENDED},
	/* 0xc0 */ {"subb",    IMMEDIATE},
	/* 0xc1 */ {"cmpb",    IMMEDIATE},
	/* 0xc2 */ {"sbcb",    IMMEDIATE},
	/* 0xc3 */ {"addd",    IMMEDIATELONG},
	/* 0xc4 */ {"andb",    IMMEDIATE},
	/* 0xc5 */ {"bitb",    IMMEDIATE},
	/* 0xc6 */ {"ldb",     IMMEDIATE},
	/* 0xc7 */ {"invalid", NOMODE},
	/* 0xc8 */ {"eorb",    IMMEDIATE},
	/* 0xc9 */ {"adcb",    IMMEDIATE},
	/* 0xca */ {"orb",     IMMEDIATE},
	/* 0xcb */ {"addb",    IMMEDIATE},
	/* 0xcc */ {"ldd",     IMMEDIATELONG},
	/* 0xcd */ {"invalid", NOMODE},
	/* 0xce */ {"ldu",     IMMEDIATELONG},
	/* 0xcf */ {"invalid", NOMODE},
	/* 0xd0 */ {"subb",    DIRECT},
	/* 0xd1 */ {"cmpb",    DIRECT},
	/* 0xd2 */ {"sbcb",    DIRECT},
	/* 0xd3 */ {"addd",    DIRECT},
	/* 0xd4 */ {"andb",    DIRECT},
	/* 0xd5 */ {"bitb",    DIRECT},
	/* 0xd6 */ {"ldb",     DIRECT},
	/* 0xd7 */ {"stb",     DIRECT},
	/* 0xd8 */ {"eorb",    DIRECT},
	/* 0xd9 */ {"adcb",    DIRECT},
	/* 0xda */ {"orb",     DIRECT},
	/* 0xdb */ {"addb",    DIRECT},
	/* 0xdc */ {"ldd",     DIRECT},
	/* 0xdd */ {"std",     DIRECT},
	/* 0xde */ {"ldu",     DIRECT},
	/* 0xdf */ {"stu",     DIRECT},
	/* 0xe0 */ {"subb",    INDEXED},
	/* 0xe1 */ {"cmpb",    INDEXED},
	/* 0xe2 */ {"sbcb",    INDEXED},
	/* 0xe3 */ {"addd",    INDEXED},
	/* 0xe4 */ {"andb",    INDEXED},
	/* 0xe5 */ {"bitb",    INDEXED},
	/* 0xe6 */ {"ldb",     INDEXED},
	/* 0xe7 */ {"stb",     INDEXED},
	/* 0xe8 */ {"eorb",    INDEXED},
	/* 0xe9 */ {"adcb",    INDEXED},
	/* 0xea */ {"orb",     INDEXED},
	/* 0xeb */ {"addb",    INDEXED},
	/* 0xec */ {"ldd",     INDEXED},
	/* 0xed */ {"std",     INDEXED},
	/* 0xee */ {"ldu",     INDEXED},
	/* 0xef */ {"stu",     INDEXED},
	/* 0xf0 */ {"subb",    EXTENDED},
	/* 0xf1 */ {"cmpb",    EXTENDED},
	/* 0xf2 */ {"sbcb",    EXTENDED},
	/* 0xf3 */ {"addd",    EXTENDED},
	/* 0xf4 */ {"andb",    EXTENDED},
	/* 0xf5 */ {"bitb",    EXTENDED},
	/* 0xf6 */ {"ldb",     EXTENDED},
	/* 0xf7 */ {"stb",     EXTENDED},
	/* 0xf8 */ {"eorb",    EXTENDED},
	/* 0xf9 */ {"adcb",    EXTENDED},
	/* 0xfa */ {"orb",     EXTENDED},
	/* 0xfb */ {"addb",    EXTENDED},
	/* 0xfc */ {"ldd",     EXTENDED},
	/* 0xfd */ {"std",     EXTENDED},
	/* 0xfe */ {"ldu",     EXTENDED},
	/* 0xff */ {"stu",     EXTENDED},
};

static const mc6809_opcodes_t mc6809_page2_opcodes[256] = {
	/* 0x1000 */ {"invalid", NOMODE},
	/* 0x1001 */ {"invalid", NOMODE},
	/* 0x1002 */ {"invalid", NOMODE},
	/* 0x1003 */ {"invalid", NOMODE},
	/* 0x1004 */ {"invalid", NOMODE},
	/* 0x1005 */ {"invalid", NOMODE},
	/* 0x1006 */ {"invalid", NOMODE},
	/* 0x1007 */ {"invalid", NOMODE},
	/* 0x1008 */ {"invalid", NOMODE},
	/* 0x1009 */ {"invalid", NOMODE},
	/* 0x100a */ {"invalid", NOMODE},
	/* 0x100b */ {"invalid", NOMODE},
	/* 0x100c */ {"invalid", NOMODE},
	/* 0x100d */ {"invalid", NOMODE},
	/* 0x100e */ {"invalid", NOMODE},
	/* 0x100f */ {"invalid", NOMODE},
	/* 0x1010 */ {"invalid", NOMODE},
	/* 0x1011 */ {"invalid", NOMODE},
	/* 0x1012 */ {"invalid", NOMODE},
	/* 0x1013 */ {"invalid", NOMODE},
	/* 0x1014 */ {"invalid", NOMODE},
	/* 0x1015 */ {"invalid", NOMODE},
	/* 0x1016 */ {"invalid", NOMODE},
	/* 0x1017 */ {"invalid", NOMODE},
	/* 0x1018 */ {"invalid", NOMODE},
	/* 0x1019 */ {"invalid", NOMODE},
	/* 0x101a */ {"invalid", NOMODE},
	/* 0x101b */ {"invalid", NOMODE},
	/* 0x101c */ {"invalid", NOMODE},
	/* 0x101d */ {"invalid", NOMODE},
	/* 0x101e */ {"invalid", NOMODE},
	/* 0x101f */ {"invalid", NOMODE},
	/* 0x1020 */ {"invalid", NOMODE},
	/* 0x1021 */ {"lbrn",    RELATIVELONG},
	/* 0x1022 */ {"lbhi",    RELATIVELONG},
	/* 0x1023 */ {"lbls",    RELATIVELONG},
	/* 0x1024 */ {"lbhs",    RELATIVELONG},
	/* 0x1025 */ {"lbcs",    RELATIVELONG},
	/* 0x1026 */ {"lbne",    RELATIVELONG},
	/* 0x1027 */ {"lbeq",    RELATIVELONG},
	/* 0x1028 */ {"lbvc",    RELATIVELONG},
	/* 0x1029 */ {"lbvs",    RELATIVELONG},
	/* 0x102a */ {"lbpl",    RELATIVELONG},
	/* 0x102b */ {"lbmi",    RELATIVELONG},
	/* 0x102c */ {"lbge",    RELATIVELONG},
	/* 0x102d */ {"lblt",    RELATIVELONG},
	/* 0x102e */ {"lbgt",    RELATIVELONG},
	/* 0x102f */ {"lble",    RELATIVELONG},
	/* 0x1030 */ {"invalid", NOMODE},
	/* 0x1031 */ {"invalid", NOMODE},
	/* 0x1032 */ {"invalid", NOMODE},
	/* 0x1033 */ {"invalid", NOMODE},
	/* 0x1034 */ {"invalid", NOMODE},
	/* 0x1035 */ {"invalid", NOMODE},
	/* 0x1036 */ {"invalid", NOMODE},
	/* 0x1037 */ {"invalid", NOMODE},
	/* 0x1038 */ {"invalid", NOMODE},
	/* 0x1039 */ {"invalid", NOMODE},
	/* 0x103a */ {"invalid", NOMODE},
	/* 0x103b */ {"invalid", NOMODE},
	/* 0x103c */ {"invalid", NOMODE},
	/* 0x103d */ {"invalid", NOMODE},
	/* 0x103e */ {"invalid", NOMODE},
	/* 0x103f */ {"swi2",    INHERENT},
	/* 0x1040 */ {"invalid", NOMODE},
	/* 0x1041 */ {"invalid", NOMODE},
	/* 0x1042 */ {"invalid", NOMODE},
	/* 0x1043 */ {"invalid", NOMODE},
	/* 0x1044 */ {"invalid", NOMODE},
	/* 0x1045 */ {"invalid", NOMODE},
	/* 0x1046 */ {"invalid", NOMODE},
	/* 0x1047 */ {"invalid", NOMODE},
	/* 0x1048 */ {"invalid", NOMODE},
	/* 0x1049 */ {"invalid", NOMODE},
	/* 0x104a */ {"invalid", NOMODE},
	/* 0x104b */ {"invalid", NOMODE},
	/* 0x104c */ {"invalid", NOMODE},
	/* 0x104d */ {"invalid", NOMODE},
	/* 0x104e */ {"invalid", NOMODE},
	/* 0x104f */ {"invalid", NOMODE},
	/* 0x1050 */ {"invalid", NOMODE},
	/* 0x1051 */ {"invalid", NOMODE},
	/* 0x1052 */ {"invalid", NOMODE},
	/* 0x1053 */ {"invalid", NOMODE},
	/* 0x1054 */ {"invalid", NOMODE},
	/* 0x1055 */ {"invalid", NOMODE},
	/* 0x1056 */ {"invalid", NOMODE},
	/* 0x1057 */ {"invalid", NOMODE},
	/* 0x1058 */ {"invalid", NOMODE},
	/* 0x1059 */ {"invalid", NOMODE},
	/* 0x105a */ {"invalid", NOMODE},
	/* 0x105b */ {"invalid", NOMODE},
	/* 0x105c */ {"invalid", NOMODE},
	/* 0x105d */ {"invalid", NOMODE},
	/* 0x105e */ {"invalid", NOMODE},
	/* 0x105f */ {"invalid", NOMODE},
	/* 0x1060 */ {"invalid", NOMODE},
	/* 0x1061 */ {"invalid", NOMODE},
	/* 0x1062 */ {"invalid", NOMODE},
	/* 0x1063 */ {"invalid", NOMODE},
	/* 0x1064 */ {"invalid", NOMODE},
	/* 0x1065 */ {"invalid", NOMODE},
	/* 0x1066 */ {"invalid", NOMODE},
	/* 0x1067 */ {"invalid", NOMODE},
	/* 0x1068 */ {"invalid", NOMODE},
	/* 0x1069 */ {"invalid", NOMODE},
	/* 0x106a */ {"invalid", NOMODE},
	/* 0x106b */ {"invalid", NOMODE},
	/* 0x106c */ {"invalid", NOMODE},
	/* 0x106d */ {"invalid", NOMODE},
	/* 0x106e */ {"invalid", NOMODE},
	/* 0x106f */ {"invalid", NOMODE},
	/* 0x1070 */ {"invalid", NOMODE},
	/* 0x1071 */ {"invalid", NOMODE},
	/* 0x1072 */ {"invalid", NOMODE},
	/* 0x1073 */ {"invalid", NOMODE},
	/* 0x1074 */ {"invalid", NOMODE},
	/* 0x1075 */ {"invalid", NOMODE},
	/* 0x1076 */ {"invalid", NOMODE},
	/* 0x1077 */ {"invalid", NOMODE},
	/* 0x1078 */ {"invalid", NOMODE},
	/* 0x1079 */ {"invalid", NOMODE},
	/* 0x107a */ {"invalid", NOMODE},
	/* 0x107b */ {"invalid", NOMODE},
	/* 0x107c */ {"invalid", NOMODE},
	/* 0x107d */ {"invalid", NOMODE},
	/* 0x107e */ {"invalid", NOMODE},
	/* 0x107f */ {"invalid", NOMODE},
	/* 0x1080 */ {"invalid", NOMODE},
	/* 0x1081 */ {"invalid", NOMODE},
	/* 0x1082 */ {"invalid", NOMODE},
	/* 0x1083 */ {"cmpd",    IMMEDIATELONG},
	/* 0x1084 */ {"invalid", NOMODE},
	/* 0x1085 */ {"invalid", NOMODE},
	/* 0x1086 */ {"invalid", NOMODE},
	/* 0x1087 */ {"invalid", NOMODE},
	/* 0x1088 */ {"invalid", NOMODE},
	/* 0x1089 */ {"invalid", NOMODE},
	/* 0x108a */ {"invalid", NOMODE},
	/* 0x108b */ {"invalid", NOMODE},
	/* 0x108c */ {"cmpy",    IMMEDIATELONG},
	/* 0x108d */ {"invalid", NOMODE},
	/* 0x108e */ {"ldy",     IMMEDIATELONG},
	/* 0x108f */ {"invalid", NOMODE},
	/* 0x1090 */ {"invalid", NOMODE},
	/* 0x1091 */ {"invalid", NOMODE},
	/* 0x1092 */ {"invalid", NOMODE},
	/* 0x1093 */ {"cmpd",    DIRECT},
	/* 0x1094 */ {"invalid", NOMODE},
	/* 0x1095 */ {"invalid", NOMODE},
	/* 0x1096 */ {"invalid", NOMODE},
	/* 0x1097 */ {"invalid", NOMODE},
	/* 0x1098 */ {"invalid", NOMODE},
	/* 0x1099 */ {"invalid", NOMODE},
	/* 0x109a */ {"invalid", NOMODE},
	/* 0x109b */ {"invalid", NOMODE},
	/* 0x109c */ {"cmpy",    DIRECT},
	/* 0x109d */ {"invalid", NOMODE},
	/* 0x109e */ {"ldy",     DIRECT},
	/* 0x109f */ {"sty",     DIRECT},
	/* 0x10a0 */ {"invalid", NOMODE},
	/* 0x10a1 */ {"invalid", NOMODE},
	/* 0x10a2 */ {"invalid", NOMODE},
	/* 0x10a3 */ {"cmpd",    INDEXED},
	/* 0x10a4 */ {"invalid", NOMODE},
	/* 0x10a5 */ {"invalid", NOMODE},
	/* 0x10a6 */ {"invalid", NOMODE},
	/* 0x10a7 */ {"invalid", NOMODE},
	/* 0x10a8 */ {"invalid", NOMODE},
	/* 0x10a9 */ {"invalid", NOMODE},
	/* 0x10aa */ {"invalid", NOMODE},
	/* 0x10ab */ {"invalid", NOMODE},
	/* 0x10ac */ {"cmpy",    INDEXED},
	/* 0x10ad */ {"invalid", NOMODE},
	/* 0x10ae */ {"ldy",     INDEXED},
	/* 0x10af */ {"sty",     INDEXED},
	/* 0x10b0 */ {"invalid", NOMODE},
	/* 0x10b1 */ {"invalid", NOMODE},
	/* 0x10b2 */ {"invalid", NOMODE},
	/* 0x10b3 */ {"cmpd",    EXTENDED},
	/* 0x10b4 */ {"invalid", NOMODE},
	/* 0x10b5 */ {"invalid", NOMODE},
	/* 0x10b6 */ {"invalid", NOMODE},
	/* 0x10b7 */ {"invalid", NOMODE},
	/* 0x10b8 */ {"invalid", NOMODE},
	/* 0x10b9 */ {"invalid", NOMODE},
	/* 0x10ba */ {"invalid", NOMODE},
	/* 0x10bb */ {"invalid", NOMODE},
	/* 0x10bc */ {"cmpy",    EXTENDED},
	/* 0x10bd */ {"invalid", NOMODE},
	/* 0x10be */ {"ldy",     EXTENDED},
	/* 0x10bf */ {"sty",     EXTENDED},
	/* 0x10c0 */ {"invalid", NOMODE},
	/* 0x10c1 */ {"invalid", NOMODE},
	/* 0x10c2 */ {"invalid", NOMODE},
	/* 0x10c3 */ {"invalid", NOMODE},
	/* 0x10c4 */ {"invalid", NOMODE},
	/* 0x10c5 */ {"invalid", NOMODE},
	/* 0x10c6 */ {"invalid", NOMODE},
	/* 0x10c7 */ {"invalid", NOMODE},
	/* 0x10c8 */ {"invalid", NOMODE},
	/* 0x10c9 */ {"invalid", NOMODE},
	/* 0x10ca */ {"invalid", NOMODE},
	/* 0x10cb */ {"invalid", NOMODE},
	/* 0x10cc */ {"invalid", NOMODE},
	/* 0x10cd */ {"invalid", NOMODE},
	/* 0x10ce */ {"lds",     IMMEDIATELONG},
	/* 0x10cf */ {"invalid", NOMODE},
	/* 0x10d0 */ {"invalid", NOMODE},
	/* 0x10d1 */ {"invalid", NOMODE},
	/* 0x10d2 */ {"invalid", NOMODE},
	/* 0x10d3 */ {"invalid", NOMODE},
	/* 0x10d4 */ {"invalid", NOMODE},
	/* 0x10d5 */ {"invalid", NOMODE},
	/* 0x10d6 */ {"invalid", NOMODE},
	/* 0x10d7 */ {"invalid", NOMODE},
	/* 0x10d8 */ {"invalid", NOMODE},
	/* 0x10d9 */ {"invalid", NOMODE},
	/* 0x10da */ {"invalid", NOMODE},
	/* 0x10db */ {"invalid", NOMODE},
	/* 0x10dc */ {"invalid", NOMODE},
	/* 0x10dd */ {"invalid", NOMODE},
	/* 0x10de */ {"lds",     DIRECT},
	/* 0x10df */ {"sts",     DIRECT},
	/* 0x10e0 */ {"invalid", NOMODE},
	/* 0x10e1 */ {"invalid", NOMODE},
	/* 0x10e2 */ {"invalid", NOMODE},
	/* 0x10e3 */ {"invalid", NOMODE},
	/* 0x10e4 */ {"invalid", NOMODE},
	/* 0x10e5 */ {"invalid", NOMODE},
	/* 0x10e6 */ {"invalid", NOMODE},
	/* 0x10e7 */ {"invalid", NOMODE},
	/* 0x10e8 */ {"invalid", NOMODE},
	/* 0x10e9 */ {"invalid", NOMODE},
	/* 0x10ea */ {"invalid", NOMODE},
	/* 0x10eb */ {"invalid", NOMODE},
	/* 0x10ec */ {"invalid", NOMODE},
	/* 0x10ed */ {"invalid", NOMODE},
	/* 0x10ee */ {"lds",     INDEXED},
	/* 0x10ef */ {"sts",     INDEXED},
	/* 0x10f0 */ {"invalid", NOMODE},
	/* 0x10f1 */ {"invalid", NOMODE},
	/* 0x10f2 */ {"invalid", NOMODE},
	/* 0x10f3 */ {"invalid", NOMODE},
	/* 0x10f4 */ {"invalid", NOMODE},
	/* 0x10f5 */ {"invalid", NOMODE},
	/* 0x10f6 */ {"invalid", NOMODE},
	/* 0x10f7 */ {"invalid", NOMODE},
	/* 0x10f8 */ {"invalid", NOMODE},
	/* 0x10f9 */ {"invalid", NOMODE},
	/* 0x10fa */ {"invalid", NOMODE},
	/* 0x10fb */ {"invalid", NOMODE},
	/* 0x10fc */ {"invalid", NOMODE},
	/* 0x10fd */ {"invalid", NOMODE},
	/* 0x10fe */ {"lds",     EXTENDED},
	/* 0x10ff */ {"sts",     EXTENDED},

};

static const mc6809_opcodes_t mc6809_page3_opcodes[256] = {
	/* 0x1100 */ {"invalid", NOMODE},
	/* 0x1101 */ {"invalid", NOMODE},
	/* 0x1102 */ {"invalid", NOMODE},
	/* 0x1103 */ {"invalid", NOMODE},
	/* 0x1104 */ {"invalid", NOMODE},
	/* 0x1105 */ {"invalid", NOMODE},
	/* 0x1106 */ {"invalid", NOMODE},
	/* 0x1107 */ {"invalid", NOMODE},
	/* 0x1108 */ {"invalid", NOMODE},
	/* 0x1109 */ {"invalid", NOMODE},
	/* 0x110a */ {"invalid", NOMODE},
	/* 0x110b */ {"invalid", NOMODE},
	/* 0x110c */ {"invalid", NOMODE},
	/* 0x110d */ {"invalid", NOMODE},
	/* 0x110e */ {"invalid", NOMODE},
	/* 0x110f */ {"invalid", NOMODE},
	/* 0x1110 */ {"invalid", NOMODE},
	/* 0x1111 */ {"invalid", NOMODE},
	/* 0x1112 */ {"invalid", NOMODE},
	/* 0x1113 */ {"invalid", NOMODE},
	/* 0x1114 */ {"invalid", NOMODE},
	/* 0x1115 */ {"invalid", NOMODE},
	/* 0x1116 */ {"invalid", NOMODE},
	/* 0x1117 */ {"invalid", NOMODE},
	/* 0x1118 */ {"invalid", NOMODE},
	/* 0x1119 */ {"invalid", NOMODE},
	/* 0x111a */ {"invalid", NOMODE},
	/* 0x111b */ {"invalid", NOMODE},
	/* 0x111c */ {"invalid", NOMODE},
	/* 0x111d */ {"invalid", NOMODE},
	/* 0x111e */ {"invalid", NOMODE},
	/* 0x111f */ {"invalid", NOMODE},
	/* 0x1120 */ {"invalid", NOMODE},
	/* 0x1121 */ {"invalid", NOMODE},
	/* 0x1122 */ {"invalid", NOMODE},
	/* 0x1123 */ {"invalid", NOMODE},
	/* 0x1124 */ {"invalid", NOMODE},
	/* 0x1125 */ {"invalid", NOMODE},
	/* 0x1126 */ {"invalid", NOMODE},
	/* 0x1127 */ {"invalid", NOMODE},
	/* 0x1128 */ {"invalid", NOMODE},
	/* 0x1129 */ {"invalid", NOMODE},
	/* 0x112a */ {"invalid", NOMODE},
	/* 0x112b */ {"invalid", NOMODE},
	/* 0x112c */ {"invalid", NOMODE},
	/* 0x112d */ {"invalid", NOMODE},
	/* 0x112e */ {"invalid", NOMODE},
	/* 0x112f */ {"invalid", NOMODE},
	/* 0x1130 */ {"invalid", NOMODE},
	/* 0x1131 */ {"invalid", NOMODE},
	/* 0x1132 */ {"invalid", NOMODE},
	/* 0x1133 */ {"invalid", NOMODE},
	/* 0x1134 */ {"invalid", NOMODE},
	/* 0x1135 */ {"invalid", NOMODE},
	/* 0x1136 */ {"invalid", NOMODE},
	/* 0x1137 */ {"invalid", NOMODE},
	/* 0x1138 */ {"invalid", NOMODE},
	/* 0x1139 */ {"invalid", NOMODE},
	/* 0x113a */ {"invalid", NOMODE},
	/* 0x113b */ {"invalid", NOMODE},
	/* 0x113c */ {"invalid", NOMODE},
	/* 0x113d */ {"invalid", NOMODE},
	/* 0x113e */ {"invalid", NOMODE},
	/* 0x113f */ {"swi3", INHERENT},
	/* 0x1140 */ {"invalid", NOMODE},
	/* 0x1141 */ {"invalid", NOMODE},
	/* 0x1142 */ {"invalid", NOMODE},
	/* 0x1143 */ {"invalid", NOMODE},
	/* 0x1144 */ {"invalid", NOMODE},
	/* 0x1145 */ {"invalid", NOMODE},
	/* 0x1146 */ {"invalid", NOMODE},
	/* 0x1147 */ {"invalid", NOMODE},
	/* 0x1148 */ {"invalid", NOMODE},
	/* 0x1149 */ {"invalid", NOMODE},
	/* 0x114a */ {"invalid", NOMODE},
	/* 0x114b */ {"invalid", NOMODE},
	/* 0x114c */ {"invalid", NOMODE},
	/* 0x114d */ {"invalid", NOMODE},
	/* 0x114e */ {"invalid", NOMODE},
	/* 0x114f */ {"invalid", NOMODE},
	/* 0x1150 */ {"invalid", NOMODE},
	/* 0x1151 */ {"invalid", NOMODE},
	/* 0x1152 */ {"invalid", NOMODE},
	/* 0x1153 */ {"invalid", NOMODE},
	/* 0x1154 */ {"invalid", NOMODE},
	/* 0x1155 */ {"invalid", NOMODE},
	/* 0x1156 */ {"invalid", NOMODE},
	/* 0x1157 */ {"invalid", NOMODE},
	/* 0x1158 */ {"invalid", NOMODE},
	/* 0x1159 */ {"invalid", NOMODE},
	/* 0x115a */ {"invalid", NOMODE},
	/* 0x115b */ {"invalid", NOMODE},
	/* 0x115c */ {"invalid", NOMODE},
	/* 0x115d */ {"invalid", NOMODE},
	/* 0x115e */ {"invalid", NOMODE},
	/* 0x115f */ {"invalid", NOMODE},
	/* 0x1160 */ {"invalid", NOMODE},
	/* 0x1161 */ {"invalid", NOMODE},
	/* 0x1162 */ {"invalid", NOMODE},
	/* 0x1163 */ {"invalid", NOMODE},
	/* 0x1164 */ {"invalid", NOMODE},
	/* 0x1165 */ {"invalid", NOMODE},
	/* 0x1166 */ {"invalid", NOMODE},
	/* 0x1167 */ {"invalid", NOMODE},
	/* 0x1168 */ {"invalid", NOMODE},
	/* 0x1169 */ {"invalid", NOMODE},
	/* 0x116a */ {"invalid", NOMODE},
	/* 0x116b */ {"invalid", NOMODE},
	/* 0x116c */ {"invalid", NOMODE},
	/* 0x116d */ {"invalid", NOMODE},
	/* 0x116e */ {"invalid", NOMODE},
	/* 0x116f */ {"invalid", NOMODE},
	/* 0x1170 */ {"invalid", NOMODE},
	/* 0x1171 */ {"invalid", NOMODE},
	/* 0x1172 */ {"invalid", NOMODE},
	/* 0x1173 */ {"invalid", NOMODE},
	/* 0x1174 */ {"invalid", NOMODE},
	/* 0x1175 */ {"invalid", NOMODE},
	/* 0x1176 */ {"invalid", NOMODE},
	/* 0x1177 */ {"invalid", NOMODE},
	/* 0x1178 */ {"invalid", NOMODE},
	/* 0x1179 */ {"invalid", NOMODE},
	/* 0x117a */ {"invalid", NOMODE},
	/* 0x117b */ {"invalid", NOMODE},
	/* 0x117c */ {"invalid", NOMODE},
	/* 0x117d */ {"invalid", NOMODE},
	/* 0x117e */ {"invalid", NOMODE},
	/* 0x117f */ {"invalid", NOMODE},
	/* 0x1180 */ {"invalid", NOMODE},
	/* 0x1181 */ {"invalid", NOMODE},
	/* 0x1182 */ {"invalid", NOMODE},
	/* 0x1183 */ {"cmpu", IMMEDIATELONG},
	/* 0x1184 */ {"invalid", NOMODE},
	/* 0x1185 */ {"invalid", NOMODE},
	/* 0x1186 */ {"invalid", NOMODE},
	/* 0x1187 */ {"invalid", NOMODE},
	/* 0x1188 */ {"invalid", NOMODE},
	/* 0x1189 */ {"invalid", NOMODE},
	/* 0x118a */ {"invalid", NOMODE},
	/* 0x118b */ {"invalid", NOMODE},
	/* 0x118c */ {"cmps", IMMEDIATELONG},
	/* 0x118d */ {"invalid", NOMODE},
	/* 0x118e */ {"invalid", NOMODE},
	/* 0x118f */ {"invalid", NOMODE},
	/* 0x1190 */ {"invalid", NOMODE},
	/* 0x1191 */ {"invalid", NOMODE},
	/* 0x1192 */ {"invalid", NOMODE},
	/* 0x1193 */ {"cmpu", DIRECT},
	/* 0x1194 */ {"invalid", NOMODE},
	/* 0x1195 */ {"invalid", NOMODE},
	/* 0x1196 */ {"invalid", NOMODE},
	/* 0x1197 */ {"invalid", NOMODE},
	/* 0x1198 */ {"invalid", NOMODE},
	/* 0x1199 */ {"invalid", NOMODE},
	/* 0x119a */ {"invalid", NOMODE},
	/* 0x119b */ {"invalid", NOMODE},
	/* 0x119c */ {"cmps", DIRECT},
	/* 0x119d */ {"invalid", NOMODE},
	/* 0x119e */ {"invalid", NOMODE},
	/* 0x119f */ {"invalid", NOMODE},
	/* 0x11a0 */ {"invalid", NOMODE},
	/* 0x11a1 */ {"invalid", NOMODE},
	/* 0x11a2 */ {"invalid", NOMODE},
	/* 0x11a3 */ {"cmpu", INDEXED},
	/* 0x11a4 */ {"invalid", NOMODE},
	/* 0x11a5 */ {"invalid", NOMODE},
	/* 0x11a6 */ {"invalid", NOMODE},
	/* 0x11a7 */ {"invalid", NOMODE},
	/* 0x11a8 */ {"invalid", NOMODE},
	/* 0x11a9 */ {"invalid", NOMODE},
	/* 0x11aa */ {"invalid", NOMODE},
	/* 0x11ab */ {"invalid", NOMODE},
	/* 0x11ac */ {"cmps", INDEXED},
	/* 0x11ad */ {"invalid", NOMODE},
	/* 0x11ae */ {"invalid", NOMODE},
	/* 0x11af */ {"invalid", NOMODE},
	/* 0x11b0 */ {"invalid", NOMODE},
	/* 0x11b1 */ {"invalid", NOMODE},
	/* 0x11b2 */ {"invalid", NOMODE},
	/* 0x11b3 */ {"cmpu", EXTENDED},
	/* 0x11b4 */ {"invalid", NOMODE},
	/* 0x11b5 */ {"invalid", NOMODE},
	/* 0x11b6 */ {"invalid", NOMODE},
	/* 0x11b7 */ {"invalid", NOMODE},
	/* 0x11b8 */ {"invalid", NOMODE},
	/* 0x11b9 */ {"invalid", NOMODE},
	/* 0x11ba */ {"invalid", NOMODE},
	/* 0x11bb */ {"invalid", NOMODE},
	/* 0x11bc */ {"cmps", EXTENDED},
	/* 0x11bd */ {"invalid", NOMODE},
	/* 0x11be */ {"invalid", NOMODE},
	/* 0x11bf */ {"invalid", NOMODE},
	/* 0x11c0 */ {"invalid", NOMODE},
	/* 0x11c1 */ {"invalid", NOMODE},
	/* 0x11c2 */ {"invalid", NOMODE},
	/* 0x11c3 */ {"invalid", NOMODE},
	/* 0x11c4 */ {"invalid", NOMODE},
	/* 0x11c5 */ {"invalid", NOMODE},
	/* 0x11c6 */ {"invalid", NOMODE},
	/* 0x11c7 */ {"invalid", NOMODE},
	/* 0x11c8 */ {"invalid", NOMODE},
	/* 0x11c9 */ {"invalid", NOMODE},
	/* 0x11ca */ {"invalid", NOMODE},
	/* 0x11cb */ {"invalid", NOMODE},
	/* 0x11cc */ {"invalid", NOMODE},
	/* 0x11cd */ {"invalid", NOMODE},
	/* 0x11ce */ {"invalid", NOMODE},
	/* 0x11cf */ {"invalid", NOMODE},
	/* 0x11d0 */ {"invalid", NOMODE},
	/* 0x11d1 */ {"invalid", NOMODE},
	/* 0x11d2 */ {"invalid", NOMODE},
	/* 0x11d3 */ {"invalid", NOMODE},
	/* 0x11d4 */ {"invalid", NOMODE},
	/* 0x11d5 */ {"invalid", NOMODE},
	/* 0x11d6 */ {"invalid", NOMODE},
	/* 0x11d7 */ {"invalid", NOMODE},
	/* 0x11d8 */ {"invalid", NOMODE},
	/* 0x11d9 */ {"invalid", NOMODE},
	/* 0x11da */ {"invalid", NOMODE},
	/* 0x11db */ {"invalid", NOMODE},
	/* 0x11dc */ {"invalid", NOMODE},
	/* 0x11dd */ {"invalid", NOMODE},
	/* 0x11de */ {"invalid", NOMODE},
	/* 0x11df */ {"invalid", NOMODE},
	/* 0x11e0 */ {"invalid", NOMODE},
	/* 0x11e1 */ {"invalid", NOMODE},
	/* 0x11e2 */ {"invalid", NOMODE},
	/* 0x11e3 */ {"invalid", NOMODE},
	/* 0x11e4 */ {"invalid", NOMODE},
	/* 0x11e5 */ {"invalid", NOMODE},
	/* 0x11e6 */ {"invalid", NOMODE},
	/* 0x11e7 */ {"invalid", NOMODE},
	/* 0x11e8 */ {"invalid", NOMODE},
	/* 0x11e9 */ {"invalid", NOMODE},
	/* 0x11ea */ {"invalid", NOMODE},
	/* 0x11eb */ {"invalid", NOMODE},
	/* 0x11ec */ {"invalid", NOMODE},
	/* 0x11ed */ {"invalid", NOMODE},
	/* 0x11ee */ {"invalid", NOMODE},
	/* 0x11ef */ {"invalid", NOMODE},
	/* 0x11f0 */ {"invalid", NOMODE},
	/* 0x11f1 */ {"invalid", NOMODE},
	/* 0x11f2 */ {"invalid", NOMODE},
	/* 0x11f3 */ {"invalid", NOMODE},
	/* 0x11f4 */ {"invalid", NOMODE},
	/* 0x11f5 */ {"invalid", NOMODE},
	/* 0x11f6 */ {"invalid", NOMODE},
	/* 0x11f7 */ {"invalid", NOMODE},
	/* 0x11f8 */ {"invalid", NOMODE},
	/* 0x11f9 */ {"invalid", NOMODE},
	/* 0x11fa */ {"invalid", NOMODE},
	/* 0x11fb */ {"invalid", NOMODE},
	/* 0x11fc */ {"invalid", NOMODE},
	/* 0x11fd */ {"invalid", NOMODE},
	/* 0x11fe */ {"invalid", NOMODE},
	/* 0x11ff */ {"invalid", NOMODE},
};

static const char *mc6809_register_field[16] = {
	/* 0b0000 */ "d",
	/* 0b0001 */ "x",
	/* 0b0010 */ "y",
	/* 0b0011 */ "u",
	/* 0b0100 */ "s",
	/* 0b0101 */ "pc",
	/* 0b0110 */ NULL,
	/* 0b0111 */ NULL,
	/* 0b1000 */ "a",
	/* 0b1001 */ "b",
	/* 0b1010 */ "ccr",
	/* 0b1011 */ "dpr",
};

static const char mc6809_index_registers[] = {
	/* 0b00 */ 'x',
	/* 0b01 */ 'y',
	/* 0b10 */ 'u',
	/* 0b11 */ 's',
};

static int mc6809_append_indexed_args(RStrBuf *buf_asm, const ut8 *buf) {
	char postop_buffer[32];
	int postop_bytes = 0;

	char index_register = mc6809_index_registers[(buf[0] >> 5) & 0x03];

	if (!(buf[0] & 0x80)) {
		/* Top bit not set - 5 bit offset  */
		/* sign extend a 5 bit offset to 8 */
		st8 offset = (st8) buf[0] & 0x1f;
		if (offset & 0x10) {
			offset |= 0xF0;
		}
		sprintf (postop_buffer, " %d,%c", offset, index_register);
		postop_bytes = 1;
	} else {
		/* The top bit of the first argument byte is set */
		switch (buf[0] & 0x1f) {
		case 0x04:
			/* no offset from register, direct */
			sprintf (postop_buffer,
				 " ,%c", index_register);
			postop_bytes = 1;
			break;
		case 0x08:
			/* 8 bit offset from register, direct */
			sprintf (postop_buffer,
				 " $%02x,%c", buf[1], index_register);
			postop_bytes = 2;
			break;
		case 0x09:
			/* 16 bit offset from register, direct */
			sprintf (postop_buffer,
				 " $%04x,%c", buf[1] * 256 + buf[2],
				 index_register);
			postop_bytes = 3;
			break;
		case 0x06:
			/* accumulator offset from register A */
			sprintf (postop_buffer,
				 " a,%c", index_register);
			postop_bytes = 1;
			break;
		case 0x05:
			/* accumulator offset from register B */
			sprintf (postop_buffer,
				 " b,%c", index_register);
			postop_bytes = 1;
			break;
		case 0x0b:
			/* accumulator offset from register D */
			sprintf (postop_buffer,
				 " d,%c", index_register);
			postop_bytes = 1;
			break;
		case 0x00:
			/* auto increment by 1 from register */
			sprintf (postop_buffer,
				 " ,%c+", index_register);
			postop_bytes = 1;
			break;
		case 0x01:
			/* auto increment by 2 from register */
			sprintf (postop_buffer,
				 " ,%c++", index_register);
			postop_bytes = 1;
			break;
		case 0x02:
			/* auto decrement by 1 from register */
			sprintf (postop_buffer,
				 " ,-%c", index_register);
			postop_bytes = 1;
			break;
		case 0x03:
			/* auto decrement by 2 from register */
			sprintf (postop_buffer,
				 " ,--%c", index_register);
			postop_bytes = 1;
			break;
		case 0x0c:
			/* 8 bit offset from PC */
			sprintf (postop_buffer,
				 " $%02x,pc", buf[1]);
			postop_bytes = 2;
			break;
		case 0x0d:
			/* 16 bit offset from PC */
			sprintf (postop_buffer,
				 " $%04x,pc", buf[1]*256+buf[2]);
			postop_bytes = 3;
			break;
		case 0x14:
			/* no offset from register, indirect */
			sprintf (postop_buffer,
				 " [,%c]", index_register);
			postop_bytes = 1;
			break;
		case 0x18:
			/* 8 bit offset from register, indirect */
			sprintf (postop_buffer,
				 " [$%02x,%c]", buf[1], index_register);
			postop_bytes = 2;
			break;
		case 0x19:
			/* 16 bit offset from register, indirect */
			sprintf (postop_buffer,
				 " [$%04x,%c]", buf[1] * 256 + buf[2],
				 index_register);
			postop_bytes = 3;
			break;
		case 0x16:
			/* accumulator offset from register A indirect*/
			sprintf (postop_buffer,
			         " [a,%c]", index_register);
			postop_bytes = 1;
			break;
		case 0x15:
			/* accumulator offset from register B indirect */
			sprintf (postop_buffer,
				 " [b,%c]", index_register);
			postop_bytes = 1;
			break;
		case 0x1b:
			/* accumulator offset from register D indirect */
			sprintf (postop_buffer,
				 " [d,%c]", index_register);
			postop_bytes = 1;
			break;
		case 0x11:
			/* auto increment by 2 from register indirect */
			sprintf (postop_buffer,
				 " [,%c++]", index_register);
			postop_bytes = 1;
			break;
		case 0x13:
			/* auto decrement by 2 from register indirect */
			sprintf (postop_buffer,
				" [,--%c]", index_register);
			postop_bytes = 1;
			break;
		case 0x1c:
			/* 8 bit offset from PC indirect  */
			sprintf (postop_buffer,
				 " [$%02x,pc]", buf[1]);
			postop_bytes = 2;
			break;
		case 0x1d:
			/* 16 bit offset from PC indirect */
			sprintf (postop_buffer,
				 " [$%04x,pc]", buf[1] * 256 + buf[2]);
			postop_bytes = 3;
			break;
		default:
			if (buf[0] == 0x9f) {
				sprintf (postop_buffer,
				         " [$%04x]", buf[1] * 256 + buf[2]);
				postop_bytes = 3;
				break;
			} else {
				strcpy (postop_buffer, " ???");
				postop_bytes = 1;
			}
		}
	}
	r_strbuf_append (buf_asm, postop_buffer);
	return postop_bytes;
}

static int mc6809_append_pushpull_args(enum instruction_mode mode,
				       RStrBuf *buf_asm,
				       const ut8 *opcode_args)
{
	r_strbuf_append (buf_asm, " ");

	if (*opcode_args & 0x80) {
		r_strbuf_append (buf_asm, "pc,");
	}
	if (*opcode_args & 0x40) {
		r_strbuf_append (buf_asm, (mode == PUSHPULLSYSTEM) ? "u," : "s,");
	}
	if (*opcode_args & 0x20) {
		r_strbuf_append (buf_asm, "y,");
	}
	if (*opcode_args & 0x10) {
		r_strbuf_append (buf_asm, "x,");
	}
	if (*opcode_args & 0x08) {
		r_strbuf_append (buf_asm, "dp,");
	}
	if (*opcode_args & 0x04) {
		r_strbuf_append (buf_asm, "b,");
	}
	if (*opcode_args & 0x02) {
		r_strbuf_append (buf_asm, "a,");
	}
	if (*opcode_args & 0x01) {
		r_strbuf_append (buf_asm, "cc,");
	}
	/* Trim off the final unwanted comma */
	/* XXX we miss a proper r_str_buf_trim function here */
	r_strbuf_get (buf_asm)[r_strbuf_length(buf_asm)-1] = '\0';
	return 2;
}

static int mc6809_disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
	ut8 tfrexg_regmasked;
	const char *tfrexg_source_reg;
	const char *tfrexg_dest_reg;
	const char *buf_asm = "invalid";

	const mc6809_opcodes_t *mc6809_opcode = &mc6809_opcodes[buf[0]];
	/* opcode_args points to the first argument byte of the opcode */
	const ut8 *opcode_args = &buf[1];

	op->size = 0;

	switch (mc6809_opcode->mode) {
	case PAGE2:
		/* step past the page 2 prefix */
		mc6809_opcode = &mc6809_page2_opcodes[buf[1]];
		opcode_args++;
		op->size++;
		break;
	case PAGE3:
		/* step past the page 3 prefix */
		mc6809_opcode = &mc6809_page3_opcodes[buf[1]];
		opcode_args++;
		op->size++;
		break;
	default:
		/* non-paged opcode, fall through to the next switch */
		;
	}

	switch (mc6809_opcode->mode) {
	case NOMODE:
	case PAGE2: /* PAGE2 and PAGE3 shouldn't occur twice in a row */
	case PAGE3:
		op->size++;
		break;
	case INHERENT:
		op->size++;
		buf_asm = sdb_fmt ("%s", mc6809_opcode->name);
		break;
	case IMMEDIATE:
		op->size += 2;
		buf_asm = sdb_fmt ("%s #$%02x", mc6809_opcode->name, *opcode_args);
		break;
	case IMMEDIATELONG:
		op->size += 3;
		buf_asm = sdb_fmt ("%s #$%04x", mc6809_opcode->name,
			opcode_args[0] * 256 + opcode_args[1]);
		break;
	case DIRECT:
		op->size += 2;
		buf_asm = sdb_fmt ("%s <$%02x", mc6809_opcode->name, *opcode_args);
		break;
	case RELATIVE:
		op->size += 2;
		buf_asm = sdb_fmt ("%s $%04x",
			mc6809_opcode->name,
			(ut16) (a->pc + (st8) *opcode_args + op->size) & 0xFFFF);
		break;
	case RELATIVELONG:
		op->size += 3;
		buf_asm = sdb_fmt ("%s $%04x", mc6809_opcode->name,
			(ut16) (a->pc + (st16)(opcode_args[0]*256+opcode_args[1])+op->size) & 0xFFFF);
		break;
	case TFREXG:
		/* In the transfer/exchange mode, both top bits of the
		   nibbles must be identical in a valid opcode */
		tfrexg_regmasked = *opcode_args & 0x88;
		if (tfrexg_regmasked && tfrexg_regmasked != 0x88) {
			op->size += 1;
		} else {
			tfrexg_source_reg = \
				mc6809_register_field[(*opcode_args >> 4) & 0x0f];
			tfrexg_dest_reg = \
				mc6809_register_field[*opcode_args & 0x0f];
			if (!tfrexg_source_reg || !tfrexg_dest_reg) {
				op->size += 1;
			} else {
				op->size += 2;
				buf_asm = sdb_fmt (
					 "%s %s,%s",
					 mc6809_opcode->name,
					 tfrexg_source_reg,
					 tfrexg_dest_reg);
			}

		}
		break;
	case INDEXED:
		/* Load Effective Address opcode - variable length */
		buf_asm = sdb_fmt ("%s", mc6809_opcode->name);
		op->size += mc6809_append_indexed_args (&op->buf_asm,
							opcode_args) + 1;
		break;
	case PUSHPULLSYSTEM:
	case PUSHPULLUSER:
		buf_asm = sdb_fmt ("%s", mc6809_opcode->name);
		op->size += mc6809_append_pushpull_args(mc6809_opcode->mode,
							&op->buf_asm,
							opcode_args);
		break;
	case EXTENDED:
		buf_asm = sdb_fmt (
			 "%s $%04x",
			 mc6809_opcode->name,
			 opcode_args[0] * 256 + opcode_args[1]);
		op->size += 3;
		break;
	}

	r_asm_op_set_asm (op, buf_asm);

	return op->size;
}

RAsmPlugin r_asm_plugin_mc6809 = {
	.name = "mc6809",
	.arch = "mc6809",
	.bits = 8,
	.desc = "Motorola MC6809 disassembly plugin",
	.init = NULL,
	.fini = NULL,
	.license = "GPL",
	.disassemble = &mc6809_disassemble,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_mc6809,
	.version = R2_VERSION
};
#endif
