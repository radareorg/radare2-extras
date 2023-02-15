# R2POKE

GNU/Poke plugin for radare2.

Poke is a programming language that allows to describe data structures and navigate on them

## Installation

You need to clone and build `poke` so check if the dependencies are available in your system and build the thing, just typing `make` will be enough to build, install and test the plugin.

This plugin is also available as a package for `r2pm`. So you can just run `r2pm -ci r2poke`.

## Missing features:

* [x] .pk files can be handled from an RLang plugin
* [ ] poke repl
* [ ] json formatter
* [ ] bind pk dumps to given offset

## Running .pk scripts from radare2

When this plugin is installed you can interpret .pk scripts as any other script using the `r2 -i <file>` flag or using the dot command `. <file>`

```sh
$ cat hello.pk
var who = "World";
printf ("Hello %s\n", who);

$ r2 -qi hello.pk --
Hello World
```

## Usage

Note that the argument of the r2 `poke` command provided by this plugin must be a complete valid expression, so you will need to use semicolons and other special characters.

```
[0x100003a3c]> poke print("pop");
ERROR: Buffer compile fails
<unknown>:1:12: error: syntax error: unexpected end of file
print("pop")
           ^
```

In order to workaround that, prefix your command with `""`, this will call RCore.cmdCall() internally which is much faster because it just runs the command without parsing or evaluating anything.

```
[0x100003a3c]> ""poke print("pop");
pop
[0x100003a3c]>
```

## Defining types and printing values

To run a pk script do this, but ideally we should make r2 support poke scripts natively with an rlang plugin that calls this:

```
""poke -f test.pk
```

--pancake
