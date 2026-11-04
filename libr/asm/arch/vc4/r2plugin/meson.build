# vc4 XPS integration for radare2.
# Included from libr/xps/meson.build when this directory lives under
# libr/xps/p/vc4/. Links the arch plugin into libr_arch and the pseudo
# plugin into libr_asm, so rasm2 and r2 get vc4 without external files.

xps_arch_plugins += ['vc4']

r_arch_additional_inc += include_directories(
  '..',
  '../include',
  '../include/opcode',
  '../../include',
)

r_arch_additional_sources += files(
  '../vc4-dis.c',
  '../vc4-asm.c',
  '../vc4-desc.c',
  '../vc4-ibld.c',
  '../vc4-opc.c',
  '../cgen-bitset.c',
  '../cgen-dis.c',
  '../cgen-asm.c',
  '../cgen-opc.c',
  'arch/arch_vc4.c',
)

xps_asm_plugins += ['vc4']

r_asm_additional_sources += files('../pseudo.c')
