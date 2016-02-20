/* sys/endian.h - bsd-games compatibility with NetBSD <sys/endian.h> (not
 * a complete emulation).
 *
 * Copyright (c) 1999 Joseph Samuel Myers.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <features.h>
#include <sys/types.h>
#include <netinet/in.h>

#define __BYTE_ORDER 0
#define __BIG_ENDIAN 1
#define __LITTLE_ENDIAN 0

#if __BYTE_ORDER == __BIG_ENDIAN
#ifndef be16toh
#define be16toh(x)	((u_int16_t)(x))
#endif
#ifndef htobe16
#define htobe16(x)	((u_int16_t)(x))
#endif
#ifndef be32toh
#define be32toh(x)	((u_int32_t)(x))
#endif
#ifndef htobe32
#define htobe32(x)	((u_int32_t)(x))
#endif
#ifndef be64toh
#define be64toh(x)	((u_int64_t)(x))
#endif
#ifndef htobe64
#define htobe64(x)	((u_int64_t)(x))
#endif
#ifndef BE16TOH
#define BE16TOH(x)	((void)0)
#endif
#ifndef HTOBE16
#define HTOBE16(x)	((void)0)
#endif
#ifndef BE32TOH
#define BE32TOH(x)	((void)0)
#endif
#ifndef HTOBE32
#define HTOBE32(x)	((void)0)
#endif
#ifndef BE64TOH
#define BE64TOH(x)	((void)0)
#endif
#ifndef HTOBE64
#define HTOBE64(x)	((void)0)
#endif
#else /* little-endian */
#ifndef be16toh
#define be16toh(x)	((u_int16_t)ntohs((u_int16_t)(x)))
#endif
#ifndef htobe16
#define htobe16(x)	((u_int16_t)htons((u_int16_t)(x)))
#endif
#ifndef be32toh
#define be32toh(x)	((u_int32_t)ntohl((u_int32_t)(x)))
#endif
#ifndef htobe32
#define htobe32(x)	((u_int32_t)htonl((u_int32_t)(x)))
#endif
#ifndef be64toh
#ifdef __bswap_64 /* glibc */
#define be64toh(x)	((u_int64_t)__bswap_64((u_int64_t)(x)))
#else /* no __bswap_64 */
#ifdef __swab64 /* Linux kernel headers (libc5, at least with kernel 2.2) */
#define be64toh(x)	((u_int64_t)__swab64((u_int64_t)(x)))
#else /* no __bswap_64 or __swab64 */
static __inline__ u_int64_t be64toh(u_int64_t __x);
static __inline__ u_int64_t be64toh(u_int64_t __x) { return (((u_int64_t)be32toh(__x & (u_int64_t)0xFFFFFFFFULL)) << 32) | ((u_int64_t)be32toh((__x & (u_int64_t)0xFFFFFFFF00000000ULL) >> 32)); }
#define be64toh(x)	be64toh((x))
#endif /* no __bswap_64 or __swab64 */
#endif /* no __bswap_64 */
#endif /* no be64toh */
#ifndef htobe64
#define htobe64(x)	be64toh(x)
#endif
#ifndef BE16TOH
#define BE16TOH(x)	((x) = be16toh((x)))
#endif
#ifndef HTOBE16
#define HTOBE16(x)	((x) = htobe16((x)))
#endif
#ifndef BE32TOH
#define BE32TOH(x)	((x) = be32toh((x)))
#endif
#ifndef HTOBE32
#define HTOBE32(x)	((x) = htobe32((x)))
#endif
#ifndef BE64TOH
#define BE64TOH(x)	((x) = be64toh((x)))
#endif
#ifndef HTOBE64
#define HTOBE64(x)	((x) = htobe64((x)))
#endif
#endif /* little-endian */
