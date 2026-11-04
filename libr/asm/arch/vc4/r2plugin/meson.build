# vc4 XPS integration for radare2.
# Included from libr/xps/meson.build when this directory lives under
# libr/xps/p/vc4/. Links the arch plugin into libr_arch and the pseudo
# plugin into libr_asm, so rasm2 and r2 get vc4 without external files.

xps_arch_plugins += ['vc4']

# p/vc4 is usually a symlink, resolve it before going above this directory
vc4_shared_inc = run_command('realpath',
  join_paths(meson.current_source_dir(), '..', '..', 'include'),
  check: true).stdout().strip()

r_arch_additional_inc += include_directories(
  '..',
  '../include',
  '../include/opcode',
  vc4_shared_inc,
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
