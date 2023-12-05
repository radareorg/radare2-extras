r2jadx
======

Jadx is decompiles Class and Dex files into Java source code.
The r2jadx project aims to integrate this decompiler into r2.

This project is still WIP, I focus on DEX support for now, so
feel free to report issues or submit improvements/fixes to
get more information from the jadx json files into r2!

Features:

* Show plaintext jadx decompilation results from r2
* Cache decompilation results in disk for fast interactions
* Associate address-to-line (and fileline-to-address)
* Experimental integration into `pdc`
* Supports low level and high level decompilations

Low level have some benefits compared to High Level decompilation

* Output comparable to `r2dec`
* Works even on obfuscated code
* Better match with assembly code (looks nice with decompiler graphs)

Author
------

--pancake @ 2019

Requirements
------------

In order to use r2jadx you need some recent versions of both:

* r2 >= 3.6
* jadx >= 1.0.0
* nodejs >= 10

Installation
------------

The easiest way to install r2, jadx and r2jadx is via r2pm:

* r2pm -i jadx r2jadx

Once the tool and script are installed you may want to make
it available via `pdc` inside r2 to get it working in Cutter
or Panels:

```> e cmd.pdc=!*r2jadx```

Some explanations on this line:

* `cmd.pdc` eval var makes the `pdc` command execute a different program
* `!*` prefix is an alias for the `#!pipe`
* `r2jadx` is the r2jadx.js script installed in `PATH`
* `r2` tweaks the `PATH` envvar to make `r2pm` scripts available into r2
* Running `pdc?` will do `!*r2jadx -h`, `pdc*` -> `!*r2jadx -r2` ...

Usage
-----

The first time you run r2jadx it will create a `.d` directory in the same
place where the loaded `classes.dex` live.

This directory contains two subdirectories with the `json` and `java` outputs
of the JADX decompilation results.

Those are the command line arguments accepted by r2jadx:

* -r -> import ALL the low level decompilation results into r2 as comments
* -r2 -> import ALL the high level decompilation results into r2 as comments

To get the function decompilation results:

* -ll -> low level decompilation of the current function
* -hl -> high level decompilation of the current function (default if no arg)

In addition we can have a full dump of the decompilation

* -ahl -> all functions high-level decompiled results
* -all -> all functions low-level decompiled results
* -cat -> `cat` the decompiled java file associated with the current function

--pancake
