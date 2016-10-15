	 ___  _   ___  ___  ___  ____ ___
	| _ \| | |  _|/  _|/  _||  _ \__ \
	| _ <| |_|  _|\_  \\_  \|    / __/
	|___/|___|___|/___//___/|_|\_\___|


blessr2 is a Node.js frontend for r2 based on bless,
a curses-like library and r2pipe.

Installation
------------

	$ r2pm -i blessr2

or

	$ npm install -g blessr2

Usage
-----

	$ $(npm bin)/blessr2 -h
	Usage: blessr2 [-Htnwd] [file|url]

or from r2

	$ r2 /bin/ls
	[0x8048000]> #!pipe node index.js

By pressing the '=' key. it starts a background webserver which can be attached by another blessr2 instance:

	$ blessr2 http://localhost:9090/cmd/

First run
---------

As long as blessr2 uses r2pipe, everything done in the UI is asyncronous and doesn't blocks the interaction.

The commandline flags provided by blessr2 are similar to the ones in r2:

	-h    show this help message
	-n    do not load rbin info
	-w    open in write mode
	-d    launch debugger
	-D    demo widgets 
	-H    start webserver
	-t    transparent windows

Once in the environment. Press 0-9 keys to select layout and '?' key to know which keys are handled by which action.
