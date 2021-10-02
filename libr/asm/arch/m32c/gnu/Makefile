CFLAGS=-I../../include -I../include -I.
CFLAGS+=-DCGEN_ARCH=1
CFLAGS+=-fPIC
CFLAGS+=-DCGEN_BFD_ARCH=bfd_arch_m32c

all:
	#gcc m32c*.c -I ../../include -I ../include
	gcc -c $(CFLAGS) cgen-asm.c
	gcc -c $(CFLAGS) cgen-dis.c
	gcc -c $(CFLAGS) cgen-opc.c
	gcc -c $(CFLAGS) cgen-bitset.c
#	gcc -c $(CFLAGS) cgen.c
	gcc -c $(CFLAGS) safe-ctype.c
	gcc -c $(CFLAGS) m32c-dis.c
	gcc -c $(CFLAGS) m32c-opc.c
	gcc -c $(CFLAGS) m32c-ibld.c
	gcc -c $(CFLAGS) m32c-desc.c
	gcc -c $(CFLAGS) m32c-asm.c
	# gcc -c $(CFLAGS) m32r-opinst.c
