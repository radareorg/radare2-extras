# r2plugin

This directory contains the make and meson files required to link the
vc4 (VideoCore IV) plugins statically inside radare2, using the XPS
(static external plugins) mechanism. See `libr/xps/README.md` in the
radare2 source tree for the full details.

Two plugins are registered directly, without a core wrapper, so both
`rasm2` and `r2` get them:

- `arch.vc4`: cgen based disassembler and analysis, linked into libr_arch
- `asm.vc4`: pseudo syntax (`e asm.pseudo=true`), linked into libr_asm

## Usage

Run these commands from the radare2 source tree:

```console
mkdir -p libr/xps/p
ln -s ../../../../radare2-extras/libr/asm/arch/vc4 libr/xps/p/vc4
echo 'EXTERNAL_PLUGINS+=vc4' >> libr/xps/config.mk
make -C libr/xps clean all
```

Then build radare2 as usual:

```console
./configure && make -j
# or
meson setup build --reconfigure && meson compile -C build
```

The meson build needs a radare2 that provides `xps_arch_plugins`,
`xps_asm_plugins` and `r_{arch,asm}_additional_{sources,inc}`.

Verify the plugins are linked in:

```console
rasm2 -L | grep vc4
rasm2 -a vc4 -d 01000200
r2 -NN -qc 'La~vc4;Lp~vc4' --
```

## Notes

- `libvc4/` is not linked: the plugin only uses the cgen disassembler.
- `r2plugin/arch/arch_vc4.c` includes `libr/asm/p/arch_vc4.c`, which
  lives outside this directory.
- Object files for the make build are stored under `build/r2plugin/`.
