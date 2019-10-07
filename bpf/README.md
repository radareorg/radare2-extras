#BPF architecture for radare2

This is meant to add support for Berkeley Packet Filter in radare2, with full [ESIL](https://radare.gitbooks.io/radare2book/content/esil.html) emulation. The main purpose is to ease the analysis of existing filters encountered in reverse engineering, but can also aid filter development through ESIL emulation.

## Components

It is composed by three plugins:

* **asm_bpf** is the disassembler, i'm planning to add also assembler functionality, but for now it's only disassembler - it is mostly ripped from bpf_dbg.c in the Linux kernel
* **anal_bpf** this is the major contribution of this package, i.e. the analysis plugin which translates everything to ESIL and permits to emulate it completely
* **bin_bpf** is a placeholder, not sure if it's useful at all since there isn't a specific file format - i'm using it just to remember that data is represented big endian by enforcing this information

## Installing using r2pm

This plugin is available in latest r2pm, therefore can be installed simply by:

```
r2pm -i bpf
```

## Building manually

In unix system (tested on mac, but should work in Linux or *BSD out of the box) it should be as easy as doing:

```bash
make install
```

There are two known warnings:

* be sure to have the latest [radare2 from git](https://github.com/radareorg/radare2)
* on mac systems radare2 should be installed with sys/install.sh (and not sys/user.sh) because the Makefile relies on a properly working `pkg-config`

## Example

The provided [bpf.bin](bpf.bin) is ripped from the [berkeley crackme](http://crackmes.de/users/kwisatz_haderach/berkeley/), here is an example session:

[![asciicast](https://asciinema.org/a/1q8oq25bjpp00aut5v5sd4sez.png)](https://asciinema.org/a/1q8oq25bjpp00aut5v5sd4sez)

Moreover, i wrote an [r2pipe script](https://github.com/mrmacete/r2scripts/tree/master/bpf-test/bpftest.py) able to read a pcap file, iterate packets, and test them against the filter by using ESIL emulation.

Here is a not-so-clear live action trying to explain the steps of the above python script:

[![asciicast](https://asciinema.org/a/e22kxl5wncmcnqfvseq0k6dxj.png)](https://asciinema.org/a/e22kxl5wncmcnqfvseq0k6dxj)

## Testing

There's a [python script](https://github.com/mrmacete/r2scripts/tree/master/bpf-test/testtool.py) which parses the Linux kernel's BPF test suite and runs it on radare2's emulated BPF using r2pipe. Until now, all the test which doesn't involve kernel emulation are passing (for the CLASSIC bpf test category only).

If you have collections of test cases you can disclose they're welcome, please open an issue or just PR a test script.

## License

Since most of asm_bpf.c is ripped from Linux kernel, it's licensed on GPLv2.
