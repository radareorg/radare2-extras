# r2plugin

This directory contains the make and meson files required to link the
vc4 (VideoCore IV) arch plugin statically inside radare2, using the XPS
(static external plugins) mechanism. See `libr/xps/README.md` in the
radare2 source tree for the full details.

The arch plugin is wrapped by a `core.vc4` plugin that registers it
when RCore starts, so `r2 -a vc4` works without loading `arch_vc4.so`.

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

Verify the plugin is linked in:

```console
./binr/radare2/radare2 -q -c 'Lc~vc4;La~vc4' --
./binr/radare2/radare2 -a vc4 -qc 'pd 2' -c 'wx 0100' --
```

## Notes

- `libvc4/` is not linked: the plugin only uses the cgen disassembler.
- Since registration happens in the core plugin, `rasm2` does not see
  the in-tree arch plugin; use `r2 -a vc4` or the external `arch_vc4`.
- Object files for the make build are stored under `build/r2plugin/`.
