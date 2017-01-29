### Reading from a linear address

<pre>
$ ./r2k -a 0x8469008 -i 3 -b 50 -p 13453 -o c
ioctl: IOCTL_READ_LINEAR_ADDR
ioctl: addr 0x8469008
ioctl: 50 bytes
ioctl: pid (13453)
Reading 50 bytes at 0x8469008 from pid (13453)
ret: 0
ioctl err: Success
Got the state: addr: 0x846a000 - value: L o r e m   I p s u m   e s   s i m p l e m e n t e   e l   t e x t o   d e   r e l l e n o   d e
</pre>
   
### Write from a linear address

<pre>
$ ./r2k -a 0x8469009 -i 4 -w somethingelsewasherebefore -p 13453 -o c
ioctl: IOCTL_WRITE_LINEAR_ADDR
ioctl: addr 0x8469008
ioctl: 26 bytes
ioctl: pid (13453)
Writing 26 bytes at 0x8469008 from pid (13453)
Str: somethingelsewasherebefore
ret: 0
ioctl err: Success
</pre>

#### checking if we wrote at @addr
<pre>

$ ./r2k -a 0x8469008 -i 3 -b 50 -p 13453 -o c
ioctl: IOCTL_READ_LINEAR_ADDR
ioctl: addr 0x8469008
ioctl: 50 bytes
ioctl: pid (13453)
Reading 50 bytes at 0x8469008 from pid (13453)
ret: 0
ioctl err: Success
Got the state: addr: 0x846a000 - value: s o m e t h i n g e l s e w a s h e r e b e f o r e   e l   t e x t o   d e   r e l l e n o   d e
</pre>


### Reading from kernel memory

<pre>
(take this as a reference)
# gdb /bin/ls /proc/kcore
(gdb) x/12b 0xc1002000
0xc1002000:	0x55	0x89	0xe5	0x3e	0x8d	0x74	0x26	0x00
0xc1002008:	0xa3	0xa0	0x87	0x5f
(gdb)


$ ./r2k -a 0xc1002000 -i 1 -b 12
ioctl: IOCTL_READ_KERNEL_MEMORY
ioctl: addr 0xc1002000
ioctl: 12 bytes
ret: 0
ioctl err: Success
Got the state: addr: 0xc1002000 - value: 0x55 0x89 0xe5 0x3e 0x8d 0x74 0x26 0x00 0xa3 0xa0 0x87 0x5f 
</pre>

### Writing kernel memory

<pre>
$ ./r2k -a 0xf82c3074 -i 1 -b 1
ioctl: IOCTL_READ_KERNEL_MEMORY
ioctl: addr 0xf82c3074
ioctl: 1 bytes
ret: 0
ioctl err: Success
Got the state: addr: 0xf82c3074 - value: 0x63    (read to see whch value was)

(gdb) x/1b 0xf82c3074
0xf82c3074:	0x63

now writing...

$  ./r2k -a 0xf82c3074 -i 2 -w p
ioctl: IOCTL_WRITE_KERNEL_MEMORY
ioctl: addr 0xf82c3074
ioctl: 1 bytes
data.buff: 70
ioctl err: Success


and check again:


$ ./r2k -a 0xf82c3074 -i 1 -b 1
ioctl: IOCTL_READ_KERNEL_MEMORY
ioctl: addr 0xf82c3074
ioctl: 1 bytes
ret: 0
ioctl err: Success
Got the state: addr: 0xf82c3074 - value: 0x70

(gdb) x/1b 0xf82c3074
0xf82c3074:	112
(gdb)
</pre>


### Read Physical memory

<pre>
(gdb) x/8x 0xc1004000
0xc1004000:	0x90	0x8d	0x74	0x26	0x00	0xe8	0xd6	0x62

$ ./r2k -a 0x1004000 -i 5 -b 8
ioctl: IOCTL_READ_PHYSICAL_ADDR
ioctl: addr 0x1004000
ioctl: 8 bytes
Reading 8 bytes at 0x1004000 from pid (0)
ret: 0
ioctl err: Success
Got the state: addr: 0x1004000 - value: 0x90 0x8d 0x74 0x26 0x00 0xe8 0xd6 0x62
</pre>
