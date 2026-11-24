# SquashFS

Build the `squash` plugin with `make -C libr/fs/p`. Install it with
`make -C libr/fs/p install-squash`, or run `make -C libr/fs/squashfs` as the
`fs-squash` package does. It requires the current radare2 RFS headers, zlib
1.2.9 or newer, and liblzma. Run `make -C libr/fs/p check` for the mount tests.

Open the image in radare2, then run `m /rootfs squash 0` with the image's offset
as the last argument. `mdj /rootfs` shows inode reference IDs. Use
`miej /rootfs/path` to map a file's extents, `miej /rootfs <id>` to map it by ID,
and `mfuj /rootfs allocated` to show the used archive range.

This plugin reads SquashFS 4.0 with gzip or XZ, including sparse blocks, shared
fragments, and the basic and extended inode layouts. Symlink reads return the
stored target path. Extent output maps raw bytes to image addresses, marks
sparse blocks, and reports logical ranges with unknown physical mappings for
compressed blocks.

The bundled GPL-2.0-or-later `unsquashfs` sources came from
[the wereHamster tree](https://github.com/wereHamster/squashfs.git). Build the
standalone extractor with `make -C libr/fs/squashfs unsquashfs`.
