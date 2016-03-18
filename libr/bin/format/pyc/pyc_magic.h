/* radare - LGPL3 - Copyright 2016 - Matthieu (c0riolis) Tardy */

#ifndef PYC_MAGIC_H
#define PYC_MAGIC_H

#include <r_types.h>

#define MAGIC_0_9_4_BETA         0x00949494
#define MAGIC_0_9_9_v0           0x0099be2a
#define MAGIC_0_9_9_v1           0x0099be3a
#define MAGIC_0_9_9_v2           0x00999901
#define MAGIC_1_0_1              0x00999902
#define MAGIC_1_1                0x00999903
#define MAGIC_1_2                0x0a0d4127
#define MAGIC_1_3_B1             0x0a0d2e89
#define MAGIC_1_4_B1_v0          0x0a0d0767
#define MAGIC_1_4_B1_v1          0x0a0d1704
#define MAGIC_1_4                0x0a0d4e95
#define MAGIC_1_5_A1             0x0a0d4e99
#define MAGIC_1_6_A2             0x0a0dc4fc
#define MAGIC_2_0_B1_v0          0x0a0dc61b
#define MAGIC_2_0_B1_v1          0x0a0dc4fc
#define MAGIC_2_0_B1_v1_U        0x0a0dc4fd
#define MAGIC_2_0_B1_v2          0x0a0dc67b
#define MAGIC_2_0_B1_v2_U        0x0a0dc67c
#define MAGIC_2_0_B1_v3          0x0a0dc67f
#define MAGIC_2_0_B1_v3_U        0x0a0dc680
#define MAGIC_2_0_B1_v4          0x0a0dc685
#define MAGIC_2_0_B1_v4_U        0x0a0dc686
#define MAGIC_2_0_B1_v5          0x0a0dc686
#define MAGIC_2_0_B1_v5_U        0x0a0dc687
#define MAGIC_2_0_B1_v6          0x0a0dc687
#define MAGIC_2_0_B1_v6_U        0x0a0dc688
#define MAGIC_2_1_A1             0x0a0deadc
#define MAGIC_2_1_A1_U           0x0a0deadd
#define MAGIC_2_1_A2             0x0a0deb2a
#define MAGIC_2_1_A2_U           0x0a0deb2b
#define MAGIC_2_2_A0             0x0a0dec04
#define MAGIC_2_2_A0_U           0x0a0dec05
#define MAGIC_2_2_A1             0x0a0ded2d
#define MAGIC_2_2_A1_U           0x0a0ded2e
#define MAGIC_2_3_A0_v0          0x0a0df231
#define MAGIC_2_3_A0_v0_U        0x0a0df232
#define MAGIC_2_3_A0_v1          0x0a0df23b
#define MAGIC_2_3_A0_v1_U        0x0a0df23c
#define MAGIC_2_3_A0_v2          0x0a0df245
#define MAGIC_2_3_A0_v2_U        0x0a0df246
#define MAGIC_2_3_A0_v3          0x0a0df23b
#define MAGIC_2_3_A0_v3_U        0x0a0df23c
#define MAGIC_2_4_A0_v0          0x0a0df24f
#define MAGIC_2_4_A0_v0_U        0x0a0df250
#define MAGIC_2_4_A0_v1          0x0a0df259
#define MAGIC_2_4_A0_v1_U        0x0a0df25a
#define MAGIC_2_4_A2             0x0a0df263
#define MAGIC_2_4_A2_U           0x0a0df264
#define MAGIC_2_4_A3             0x0a0df26d
#define MAGIC_2_4_A3_U           0x0a0df26e
#define MAGIC_2_5_A0_v0          0x0a0df277
#define MAGIC_2_5_A0_v0_U        0x0a0df278
#define MAGIC_2_5_A0_v1          0x0a0df281
#define MAGIC_2_5_A0_v1_U        0x0a0df282
#define MAGIC_2_5_A0_v2          0x0a0df28b
#define MAGIC_2_5_A0_v2_U        0x0a0df28c
#define MAGIC_2_5_A0_v3          0x0a0df28c
#define MAGIC_2_5_A0_v3_U        0x0a0df28d
#define MAGIC_2_5_B2_v0          0x0a0df295
#define MAGIC_2_5_B2_v0_U        0x0a0df296
#define MAGIC_2_5_B2_v1          0x0a0df29f
#define MAGIC_2_5_B2_v1_U        0x0a0df2a0
#define MAGIC_2_5_C3             0x0a0df2a9
#define MAGIC_2_5_C3_U           0x0a0df2aa
#define MAGIC_2_6_A0_v0          0x0a0df2b3
#define MAGIC_2_6_A0_v0_U        0x0a0df2b4
#define MAGIC_2_6_A0_v1          0x0a0df2bd
#define MAGIC_2_6_A0_v1_U        0x0a0df2be
#define MAGIC_2_6_A0_v2          0x0a0df2c7
#define MAGIC_2_6_A0_v2_U        0x0a0df2c8
#define MAGIC_2_6_A1_PLUS_v0     0x0a0df2d1
#define MAGIC_2_6_A1_PLUS_v0_U   0x0a0df2d2
#define MAGIC_2_6_A1_PLUS_v1     0x0a0df2d3
#define MAGIC_2_6_A1_PLUS_v1_U   0x0a0df2d4
#define MAGIC_2_6_A1_PLUS_v2     0x0a0df2d1
#define MAGIC_2_6_A1_PLUS_v2_U   0x0a0df2d2
#define MAGIC_2_7_A0_v0          0x0a0df2db
#define MAGIC_2_7_A0_v0_U        0x0a0df2dc
#define MAGIC_2_7_A0_v1          0x0a0df2e5
#define MAGIC_2_7_A0_v1_U        0x0a0df2e6
#define MAGIC_2_7_A0_v2          0x0a0df2ef
#define MAGIC_2_7_A0_v2_U        0x0a0df2f0
#define MAGIC_2_7_A2_PLUS_v0     0x0a0df2f9
#define MAGIC_2_7_A2_PLUS_v0_U   0x0a0df2fa
#define MAGIC_2_7_A2_PLUS_v1     0x0a0df303
#define MAGIC_2_7_A2_PLUS_v1_U   0x0a0df304
#define MAGIC_3_0X_v0            0x0a0d0bb8
#define MAGIC_3_0X_v0_U          0x0a0d0bb9
#define MAGIC_3_0X_v1            0x0a0d0bc2
#define MAGIC_3_0X_v1_U          0x0a0d0bc3
#define MAGIC_3_0X_v2            0x0a0d0bcc
#define MAGIC_3_0X_v2_U          0x0a0d0bcd
#define MAGIC_3_0X_v3            0x0a0d0bd6
#define MAGIC_3_0X_v3_U          0x0a0d0bd7
#define MAGIC_3_0X_v4            0x0a0d0be0
#define MAGIC_3_0X_v4_U          0x0a0d0be1
#define MAGIC_3_0X_v5            0x0a0d0bea
#define MAGIC_3_0X_v5_U          0x0a0d0beb
#define MAGIC_3_0X_v6            0x0a0d0bf4
#define MAGIC_3_0X_v6_U          0x0a0d0bf5
#define MAGIC_3_0_A1_v0          0x0a0d0bfe
#define MAGIC_3_0_A1_v0_U        0x0a0d0bff
#define MAGIC_3_0_A1_v1          0x0a0d0c08
#define MAGIC_3_0_A1_v1_U        0x0a0d0c09
#define MAGIC_3_0_A1_PLUS        0x0a0d0c12
#define MAGIC_3_0_A1_PLUS_U      0x0a0d0c13
#define MAGIC_3_0_A2             0x0a0d0c1c
#define MAGIC_3_0_A2_U           0x0a0d0c1d
#define MAGIC_3_0_A2_PLUS        0x0a0d0c1e
#define MAGIC_3_0_A2_PLUS_U      0x0a0d0c1f
#define MAGIC_3_0_A3_PLUS        0x0a0d0c26
#define MAGIC_3_0_A3_PLUS_U      0x0a0d0c27
#define MAGIC_3_0_A5_PLUS        0x0a0d0c3a
#define MAGIC_3_0_A5_PLUS_U      0x0a0d0c3b
#define MAGIC_3_1_A0_v0          0x0a0d0c44
#define MAGIC_3_1_A0_v0_U        0x0a0d0c45
#define MAGIC_3_1_A0_v1          0x0a0d0c4e
#define MAGIC_3_1_A0_v1_U        0x0a0d0c4f
#define MAGIC_3_2_A0             0x0a0d0c58
#define MAGIC_3_2_A0_U           0x0a0d0c59
#define MAGIC_3_2_A1_PLUS_U      0x0a0d0c62
#define MAGIC_3_2_A2_PLUS_U      0x0a0d0c6c
#define MAGIC_3_3_A0_U           0x0a0d0c76
#define MAGIC_3_3_0_A0_v0_U      0x0a0d0c80
#define MAGIC_3_3_0_A0_v1_U      0x0a0d0c8a
#define MAGIC_3_3_0_A1_PLUS_U    0x0a0d0c94
#define MAGIC_3_3_0_A3_PLUS_U    0x0a0d0c9e
#define MAGIC_3_4_0_A0_v0_U      0x0a0d0ca8
#define MAGIC_3_4_0_A0_v1_U      0x0a0d0cb2
#define MAGIC_3_4_0_A0_v2_U      0x0a0d0cbc
#define MAGIC_3_4_0_A0_v3_U      0x0a0d0cc6
#define MAGIC_3_4_0_A0_v4_U      0x0a0d0cd0
#define MAGIC_3_4_0_A3_PLUS_v0_U 0x0a0d0cda
#define MAGIC_3_4_0_A3_PLUS_v1_U 0x0a0d0ce4
#define MAGIC_3_4_0_RC1_PLUS_U   0x0a0d0cee
#define MAGIC_3_5_0_A0_U         0x0a0d0cf8
#define MAGIC_3_5_0_A4_PLUS_U    0x0a0d0d02
#define MAGIC_3_5_0_B1_PLUS_U    0x0a0d0d0c
#define MAGIC_3_5_0_B2_PLUS_U    0x0a0d0d16
#define MAGIC_3_6_0_A0_v0_U      0x0a0d0d20
#define MAGIC_3_6_0_A0_v1_U      0x0a0d0d21

struct pyc_version {
	ut32 magic;
	char *version;
	char *revision;
	bool unicode;
};

struct pyc_version get_pyc_version(ut32 magic);

#endif
