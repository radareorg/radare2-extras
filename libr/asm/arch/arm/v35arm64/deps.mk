
ARM64V35_HOME?=arch-arm64/
ARM64V35_SRCDIR=$(ARM64V35_HOME)/disassembler/

ARM64V35_CFLAGS=-I$(ARM64V35_SRCDIR)
ARM64V35_OBJS=format.o pcode.o decode.o decode0.o decode1.o decode_fields32.o decode_scratchpad.o decode2.o operations.o encodings_dec.o regs.o
ARM64V35_LINK=$(addprefix $(ARM64V35_SRCDIR),$(ARM64V35_OBJS))

${ARM64V35_LINK}: $(ARM64V35_SRCDIR)
$(ARM64V35_SRCDIR): 
	$(MAKE) git-clone-arm64v35

git-clone-arm64v35:
	$(MAKE) -C $(ARM64V35_HOME) all

.PHONY: git-clone-arm64v35
