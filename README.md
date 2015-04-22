radare2-extras
==============
This repository contains extra plugins for radare2.

The reasons why those plugins are distributed in a separate
repository are the following:

* Depends on external libraries (yara, ewf)
* Marginal/specific use (ctf-specific asm/anal vm f.ex)
* r2 must be self-contained (no optional/external deps)
* Simplify packagers work, and makes it more flexible
* Duplicates functionality from r2 (no need to have
  multiple disassemblers for the same arch in core)

The compiled plugins will be installed at

	/usr/lib/radare2-extras/$(VERSION)

Some of the plugins/code doesnt compiles, it will be reviewed
and cleaned up, merged into core, updated or removed.

In addition, this repository will be useful to new contributors,
comers who want to write his own r2 plugins for example.

The aim of this repository is to make the master radare2
repository to be as concise as possible, and reduce the
amount of unnecessary plugins to shrink the install size and
keep it usable for 99% of users.

Building
========
To build radare2-extras, just follow the common gnu-configure steps:

	./configure --prefix=/usr
	make baleful
	make baleful-install

To install yara3 and the r2 plugin:

	./configure --prefix=/usr
	make install-yara3
	make yara3
	make yara3-install

Note the `symstall` instead of `install` will symlink the plugins
instead of copying them. This way you can just avoid installing
every time you build. This installation method is prefered for
developers.

Each module may have it's own configure script, this way
packagers can create plugin-specific packages like this:

	radare2-extras-yara -> yara plugin

Directories
===========

* yara/yara2 yara/yara3

	yara2/3 command. Depends on libyara

* libr/asm/p

	Contains assembler/disassembler plugins:

	* m68k
	* armthumb
	* psosvm
	* ppc

* libr/bin/p

	Bin-related plugins:

	* dlang demangler

* libr/anal/p

	Contains code analysis plugins

* libr/vm

	Contains the initial implementation of ESIL. It is kept
	for historical reasons, but will be removed soon or late.

* libr/cmd

	very work-in-progress core cmd plugins
	for historical reasons, but will be removed soon or late.

RFC
===
	
In addition we should add sys/*.sh files to fetch and build the
plugins and dependencies if needed (yara.sh) to allow git users
to get the proper version installed without depending on the
pkgsystem.

We could still provide one-liners to help them. We should keep
different versioning numbers for each plugin..

	radare2-extras-yara3-0.9.9-0.1
	[pkgname] [modname] [r2version] [modversion]

* Do we need a radare2-extra-regressions then?

I would just add the tests inside the radare2-extras/libr/core/p/yara/t/
for example.. and just make those tests run from inside that
repo, no need to add more repos because those plugins would be
pretty contained.

* What about checking all the tests right away?

Also maybe the plugins depend on some r2 behavior, that has
been broken, and we need to test for that jenkins should run
those tests don't know much about jenkins, so i won't say much.
just hoping it covers all our bases.
