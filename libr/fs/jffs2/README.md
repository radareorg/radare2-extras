# JFFS2

Build the `jffs2` plugin with `make -C libr/fs/p` and install it with
`make -C libr/fs/p user-install`. Use a radare2 build with the RFS extent API.
The plugin uses zlib 1.2.9 or newer. `make -C libr/fs/p check` runs the mount
tests for both filesystem plugins.

Open a raw flash image in radare2, then run `m /flash jffs2 0`. For a partition
inside an image, use `m /flash jffs2 0x10000 size=0x800000` with its actual offset
and length. Use `mdj /flash` for entries and IDs, `miej /flash/path` for file
extents, and `mfuj /flash all` for allocation ranges. Free ranges identify erased
words outside nodes. The input should contain flash data with NAND OOB bytes
removed.

The reader supports little- and big-endian images, raw and ZERO nodes, zlib and
RTIME. Symlink reads return the stored target path. The decoder caps compressed
nodes at 16 MiB of stored and decoded data.

`mdxj /flash` lists names with surviving unlink records and their previous
dirents. `mgx /flash <id> output` recovers a regular file when its inode has no
live name and all logical bytes are covered by surviving CRC-checked nodes.
An explicit ZERO node can cover a hole. File extents give physical addresses for
raw bytes. Compressed bytes have a logical extent and an unknown physical
mapping. Set `fs.cwd=/flash` and `search.in=fs.deleted` to scan the raw recovered
ranges directly.

The standalone `jffs2reader` source came from [mtd-utils](https://github.com/vamanea/mtd-utils.git).
