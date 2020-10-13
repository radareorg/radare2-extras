radare2-extras
==============

[![GithubCI Status](https://github.com/radareorg/radare2-extras/workflows/radare2-extras/badge.svg)](https://github.com/radareorg/radare2-rlang/actions?query=workflow%3A%22radare2-extras%22)|
[![Travis Status](https://travis-ci.org/radareorg/radare2-extras.svg?branch=master)](https://travis-ci.org/radareorg/radare2-extras)

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

The recommended way to build and install those plugins for users
is to use r2pm. See the radare2-pm repository for details:

	https://github.com/radareorg/radare2-pm
