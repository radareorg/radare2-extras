# pimp
Triton based R2 plugin for concolic execution (WIP)

---
 ## Asciinema
[![asciicast](http://ak42.io/wp-content/uploads/2017/05/scrot.png)](https://asciinema.org/a/ccncic4ab0m7080dxdl4gye5z)
 
#### Dependencies:
   * r2 (master)
   * Triton (and its dependencies)
   * r2pipe
   * lang-python

#### Warning:
Currently, R2 and Triton need to be compiled with the same libcapsone version.
This should change in the future.

As this is still WIP, commands might change, check for the readme file updates after git pull.


### Installation:
```
git clone https://github.com/kamou/pimp.git
```

### Usage:

As this is about concolic execution, the r2's debug mode is required.
run `r2 -d bnary -i path/to/pimp.py`

Initialise the Triton context:

`pimp.init`

Declare or list the symbolic variables (memory):

`pimp.input [size] [address]`

Emulate execution until a symbolic instruction is met:

`pimp.dcusi`

Emulate execution until a symbolic jump is met:

`pimp.dcusj`

Take Current conditional jump:

`pimp.take`

Avoid current conditional jump:

`pimp.avoid`

Reset triton memory with current binary memory:

`pimp.reset`

Load triton generated input back into r2:

`pimp.sync`

Peek a memory value from the Triton cache:

`pimp.peek size address`

Poke (write) a memory value to the Triton cache (only do this if you know what you are doing):

`pimp.poke value size address`

### Author:
Ayman Khamouma ([@dsknctr](https://twitter.com/dsknctr)) ak42@mg.blackbunny.io

[http://blackbunny.io](http://blackbunny.io)

[http://ak42.io](http://ak42.io)

