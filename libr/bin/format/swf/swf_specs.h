/* radare - LGPL3 - 2016 - xarkes */

#ifndef _SWF_H
#define _SWF_H

#define ISWF_MAGIC_0_0 0x46
#define ISWF_MAGIC_0_1 0x43
#define ISWF_MAGIC_0_2 0x5A
#define ISWF_MAGIC  "\x57\x53"

#define SWF_FILE_TYPE "Macromedia Flash data, version %d %s"
/* Be careful when modifying the strings below, the code takes care of ZLIB
 * string size only */
#define SWF_FILE_TYPE_SWF "(Not compressed)"
#define SWF_FILE_TYPE_ZLIB "(ZLIB compressed)"
#define SWF_FILE_TYPE_LZMA "(LZMA compressed)"
#define SWF_FILE_TYPE_ERROR "Compression error"

#define SWF_HDR_MIN_SIZE 12

#endif // _SWF_H
