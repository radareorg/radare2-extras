Unicorn Emulator Plugin for radare2
===================================
```
                 /\'.         _,.
                 |:\ \.     .'_/
            _.-  |(\\ \   .'_.'
        _.-'  ,__\\ \\_),/ _/
      _:.'  .:::::::.___  ,'
      //   ' ./::::::\<o\(
     //     /|::/   `"(   \
    ;/_    / ::(       `.  `.
   /_'/   | ::::\        `.  \
   '//    '\ :::':\_    _, ` _'-
   / |     '\.:/|::::.._ `-__ )/
   | |       \;| \:(    '.(_ \_)
   | |        \(  \::.    '-)
   \ \  ,          '""""---.
    \ \ \    ,        _.-...)
     \ \/\.  \:,___.-'..:::/
      \ |\\:,.\:::::'.::::/
       `  `:;::::'.::;::'
             '":;:""'
```

How to build and install
------------------------

First you need to have *unicorn* installed from git:

	$ r2pm -i unicorn-lib
	$ r2pm -i unicorn

or

	$ git clone https://github.com/unicorn-engine/unicorn
	$ cd unicorn
	$ make
	$ sudo make install

	$ cd radare2-extras/unicorn
	$ make
	$ make install

Usage
-----

To use the unicorn debugger plugin you have to select it with the `dL` command:

	$ r2 /bin/ls
	> dL unicorn
	[UNICORN] Using arch x86 bits 64
	[UNICORN] BASE 0x100000000
	[UNICORN] Segment 0x100000d78 0x100010d78 Size 65536
	[UNICORN] Set Program Counter 0x00000d78
	[UNICORN] Define 64 KB stack at 0x07000000

Now it's time to go where you want to emulate and type:

	> dpa

The `dpa` command attaches the unicorn debugger to the memory state of r2, which
copies the data from r2 into the unicorn. From now on all the debuggers commands
should work as expected:

	> dr rip=entry0  # set rip register value
	> ds             # perform a step
	> dr=
	...
