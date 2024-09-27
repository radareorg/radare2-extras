# radare2ida

This repository contains a collection of documents, scripts
and utilities that will allow you to use IDA and R2, converting
projects metadata from one tool to the other and providing
tools to integrate them in a more useful way.

In progress:

* Documentation about how to use the tool
* Export IDB from IDA into a radare2 script
* Import radare2 project metadata into IDA database
* Launch r2 from IDA
* Use IDA as an IO backend for R2
* Expose R2 functionalities into IDA
  * Assembler/Disassembler
  * Base converter
  * ROP gadget search
  * ...

## ida2r2

**Note:** This requires the [python-idb](https://github.com/williballenthin/python-idb) installed
and available for python imports. It is recommended to use the latest version of
 `python-idb` by cloning the repository and installing it using `python setup.py install`.


## r2ida - IDA subview to interact with radare2

https://www.youtube.com/watch?v=AkN3uJLdMvM

## features
- sync names (when the idb is opened and when you press sync)
- sync subview (go to asm subview in the point where is the radare seek)
- sync base
- "ida" command to view the ida decompilation in the radare subview

## Install
put the plugin on ida plugins folder, and Crtl + Shift + R


