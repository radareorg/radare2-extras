# afen plugin

Author: satk0

Radare2 plugin to rename expressions

This plugin should register a new `afen` command that should rename any expression
to any text, thus enabling a creation of variables from expressions.

## Building and installing the plugin:

Build:

    r2pm -r meson build

Install:

    meson install -C build

## Usage:

    r2 -e asm.pseudo=true <file>

