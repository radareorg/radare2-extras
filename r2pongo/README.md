r2pongo
=======

Radare2 can talk to pongoOS with this IO plugin in order to read memory
from the device or execute commands from pongoOS.

The current code is based on `pongoterm.m` from `pongoOS/scripts`.

--pancake

![IMAGE 2021-05-09 00:49:09](https://user-images.githubusercontent.com/6431515/117555536-5e471d80-b060-11eb-9a5c-93ea57620a58.jpg)


Requirements
------------

* macOS
* iDevice supported by checkra1n
* r2 (git is always recommended)

First you need to get a copy of the pongoOS and build the firmware:

```
git clone https://github.com/checkra1n/pongoOS
cd pongoOS
make
```

Then you may run the checkra1n tool and follow the screen instructions.

```
/Applications/checkra1n.app/Contents/MacOS/checkra1n -k build/Pongo.bin
```

How to use
----------

At this point, the iOS device should be running the OS and you can use
this r2 plugin to interact with it:

```asm
$ r2 -a arm -b 64 pongo://
[connected]
[0x00000000]> =!aes
Usage: aes [cbc|ecb] [enc|dec] [128|192|256] uid|gid0|gid1|ivkey data
Default is: cbc dec 256

[0x00000000]> =!ps
=+= System Information ===
 | served irqs: 553853, caught fiqs: 12669444, preempt: 238576, uptime: 12723.8s
 | free pages: 116603 (1821 MB), inuse: 9786 (152 MB), paged: 5
 | heap: 8 (0 MB), wired: 9433 (147 MB), total: 126389 (1974 MB)
=+=    Process List    ===
 |   sched | task 0 | runcnt = e1d40 | flags = coop, run
 | command | task 4 | runcnt = 18b8a | flags = preempt, run
=+=    IRQ Handlers    ===
 |     sep (122) | runcnt: 0 | irq: 0 | irqcnt: 0 | flags: preempt, wait
 |     sep (123) | runcnt: 0 | irq: 1 | irqcnt: 0 | flags: preempt, wait
 |     sep (124) | runcnt: 0 | irq: 2 | irqcnt: 0 | flags: preempt, wait
 |    uart (282) | runcnt: 0 | irq: 3 | irqcnt: 0 | flags: preempt, wait
 |     usb (324) | runcnt: 553853 | irq: 4 | irqcnt: 553853 | flags: preempt, wait
=+=   Loaded modules   ===
=+========================

[0x00000000]>
[0x00000000]> s 0x100000000

[0x100000000]> pd 10
            0x100000000      mov   x9,   x8
            0x100000004      adr   x4,   0x100000000
            0x100000008      mov   x5,   0x800000000
            0x10000000c      movk  x5,   0x1800, lsl 16
            0x100000010      and   x30,  x30,  4
            0x100000014      orr   x30,  x30,  x5
            0x100000018      cmp   x4,   x5
            0x10000001c      b.eq  0x100000080
            0x100000020      add   x6,   x4,   0x200, lsl 12
            0x100000024      ldr   x3,   [x4], 8

[0x100000000]> =!help
             aes | performs AES operations
        bootargs | prints xnu bootargs struct
           bootl | boots linux
           bootr | boot raw image
          bootux | boots unpatched xnu
           bootx | boots xnu (patched, if such a module is loaded)
           crash | branches to an invalid address
              dt | parses loaded devicetree
         fbclear | clears the framebuffer output (minus banner)
        fbinvert | inverts framebuffer contents
             fdt | load linux fdt from usb
            help | shows this help message
   linux_cmdline | update linux kernel command line
           loadx | loads xnu
           lsdev | prints hal devices tree
             md8 | memory dump
            mipi | mipi tools
         modload | loads module
          paging | tests paging
           panic | calls panic()
            peek | 32bit mem read
        physdump | dumps a page of phys
            poke | 32bit mem write
              ps | lists current tasks and irq handlers
         ramdisk | loads a ramdisk for xnu or linux
           recfg | recfg sequences
       recursion | tests stack guards
           reset | resets the device
             sep | sep tools
           spawn | starts a usermode process
            spin | spins 1 second
        synopsys | prints a synopsysotg register dump
              tz | trustzone info
         tz0_set | change tz0 registers
    tz_blackbird | trustzone blackbird attack
     tz_lockdown | trustzone lockdown
           xargs | prints or sets xnu boot-args
             xfb | gives xnu access to the framebuffer (for -v or -s)
```

Scripting
---------

As usual, r2pipe can be also used with pongoOS and automate actions executed in the target device or inside the local r2. See this example:

```py
import r2pipe

r2 = r2pipe.open("pongo://")
h=r2.cmd("e asm.arch=arm")
h=r2.cmd("e asm.bits=64")

# print(r2.cmd("=!help"))

entrypoint = 0x100000000
r2.cmd("s " + str(entrypoint))
dis = r2.cmd("pd 10")
print("pongoOS entrypoint:")
print(dis)
```

Contributions
-------------

If you find this plugin useful, feel free to submit fixes and improvements. The current code is very hacky, but it works. Ideally `pongoOS` should expose better read/write/exec primitives to be used from r2.

It is possible to make r2pipe scripts that use this plugin to manipulate or automate different actions.
