# afen plugin

Author: satk0

NOTE: Making this plugin would not be possible without the help from pancake. Big thanks to him!

Radare2 plugin to rename expressions

This plugin should register a new `afen` command that should rename any expression
to any text, thus enabling a creation of variables from expressions.

## Building and installing the plugin:

Build:

    r2pm -r meson build

Install:

    meson install -C build

## Run:

    r2 -e asm.parser=afen -e asm.pseudo=true <file>

## Usage:

For instance, to rename `rbp + rax - 0x1020` expression to `cwd[i]`, you could use the following command:

    afen cmd[i] "rbp + rax - 0x1020"
