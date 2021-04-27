
ARM64V35_HOME?=arch-arm64/
ARM64V35_SRCDIR=$(ARM64V35_HOME)/disassembler/

ARM64V35_CFLAGS=-I$(ARM64V35_SRCDIR)
ARM64V35_OBJS+=decode.o
ARM64V35_OBJS+=decode0.o
ARM64V35_OBJS+=decode1.o
ARM64V35_OBJS+=decode2.o
ARM64V35_OBJS+=decode_fields32.o
ARM64V35_OBJS+=decode_scratchpad.o
ARM64V35_OBJS+=encodings_dec.o
ARM64V35_OBJS+=encodings_fmt.o
ARM64V35_OBJS+=format.o
ARM64V35_OBJS+=gofer.o
ARM64V35_OBJS+=operations.o
ARM64V35_OBJS+=pcode.o
ARM64V35_OBJS+=regs.o
ARM64V35_OBJS+=sysregs.o
#ARM64V35_OBJS+=test.o
ARM64V35_LINK=$(addprefix $(ARM64V35_SRCDIR),$(ARM64V35_OBJS))

${ARM64V35_LINK}: $(ARM64V35_SRCDIR)
$(ARM64V35_SRCDIR): 
	$(MAKE) git-clone-arm64v35

git-clone-arm64v35:
	$(MAKE) -C $(ARM64V35_HOME) all

.PHONY: git-clone-arm64v35
