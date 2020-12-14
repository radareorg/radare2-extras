#ifndef _RZ_KEYSTONE_PRIV_H_
#define _RZ_KEYSTONE_PRIV_H_

#include <rz_types.h>
#include <rz_asm.h>

RZ_IPI int keystone_assemble(RzAsm *a, RzAsmOp *ao, const char *str, ks_arch arch, ks_mode mode);

#endif