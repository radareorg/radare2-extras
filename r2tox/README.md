r2tox
=====

starts a background thread and exposes a tox node showing the address to be used to talk to it.

Tox should work everywhere, in LAN, with or without internet, behind a router, etc

--pancake 2018

How to build
------------

You need cmake, make, gcc, git, libsodium and radare2. c-toxcore is built in here.

	$ make

How to use
----------

Starting the tox client

	$ r2 /bin/ls
	[0x00000000]> tox
	d561561f8597951459a78825a535ebff221259d0a8b4296466c1a5ee65ca3001be026a2fb46e

Adding a friend

	[0x00000000]> toxf 64aa12846135c591183267fdd9ce959239b65e8916b69602905efed39696101ae2c1fdab1e1e

Sending a message

	[0x00000000]> toxm 0 hi there

Running a command in the remote tox session:

	[0x00000000]> toxc 0 ?V

Closing the tox session

	[0x00000000]> tox-
