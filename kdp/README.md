NOTE
====

this is wip, see libr/io/p/kdp.mk for more info

KDP - XNU's Kernel Debugger Protocol
====================================

Install OSX in a VM and type this in a Terminal:

	# nvram boot-args="-v debug=0x1"

You can optionally install a Kernel with debug info:

http://ho.ax/posts/2012/02/debugging-the-mac-os-x-kernel-with-vmware-and-gdb/
https://gist.github.com/steakknife/07df81ffe382d5f257d7

After reboot, the Mac will boot in debug verbose mode and stop before
starting any userland program showing the mac and ip address.

Add a static ARP entry to access to the VM ip 

	arp -s 192.168.242.128 00:0c:29:e6:4c:fb

After this you can launch lldb like this:

	$ lldb
	(lldb) kdp-remote 192.168.242.128
	...
	(lldb) continue
	...

Or you can just to the same with r2:

	$ r2 kdp://192.168.242.128
	[0x00000000]> dc
	...

Links
-----
* http://www.opensource.apple.com/source/xnu/xnu-2422.1.72/tools/lldbmacros/kdp.py
* https://books.google.es/books?id=K8vUkpOXhN4C&pg=PA602&lpg=PA602&dq=kdp+protocol&source=bl&ots=OLkmQZXw1C&sig=biw-q5ZOqLKLPpviI3PP7KSjTKQ&hl=en&sa=X&ved=0CDUQ6AEwA2oVChMIxbOE5KzjxgIVgj0UCh3h3ggd#v=onepage&q=kdp%20protocol&f=false
* http://www.opensource.apple.com/source/gdb/gdb-213/src/gdb-next/kdp-protocol.h?txt
* https://reverse.put.as/2009/03/05/mac-os-x-kernel-debugging-with-vmware/
* https://github.com/saelo/ios-kern-utils/blob/master/lib/kernel/base.c
* https://reverse.put.as/wp-content/uploads/2011/06/SysScan-Singapore-Targeting_The_IOS_Kernel.pdf
* https://www.theiphonewiki.com/wiki/Kernel_ASLR
* https://github.com/stefanesser/serialKDPproxy
