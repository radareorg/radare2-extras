radare2 MicroBlaze plugin
==========================

Support for the microblaze microprocessor in radare2

The plugin uses the current `RArchPlugin` API and provides disassembly and
analysis in one shared object.

The analysis support is still a work in progress and should not be trusted.

Building
--------

Just type `make`.

After installing the plugin, run its regression tests from the repository root:

```
r2r -u -C . test/db/extras/microblaze
```
