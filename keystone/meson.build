project('rizin-keystone', 'cpp')

plugins_dir = join_paths(get_option('prefix'), 'plugins')

rz_asm_lib = dependency('rz_asm')
keystone_lib = dependency('keystone')

foreach arch : ['arm', 'hexagon', 'mips', 'ppc', 'sparc', 'sysz', 'x86']
  library('asm_@0@_ks'.format(arch),
    ['asm_@0@_ks.cpp'.format(arch), 'keystone.cpp'],
    dependencies: [rz_asm_lib, keystone_lib],
    install: true,
    install_dir: plugins_dir,
    soversion: rz_asm_lib.version()
  )
endforeach
