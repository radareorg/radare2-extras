Shell
=====

The default interaction with r2 is the REPL loop.

	[0x8048000]>

You will get something like this after entering r2. This is called "prompt",
and it displays the current seek address.

As long as r2 is block-based, all read/write ops will be done at the blocksize,
which can be specified with the ``b` command.

The first command you may like to ...
