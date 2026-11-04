VC4_ARCH_WD=$(LIBR)/xps/p/vc4
VC4_ARCH_BUILD=$(VC4_ARCH_WD)/build/r2plugin/arch
VC4_ARCH_SRC=\
	vc4-dis.c vc4-asm.c vc4-desc.c vc4-ibld.c vc4-opc.c \
	cgen-bitset.c cgen-dis.c cgen-asm.c cgen-opc.c
VC4_ARCH_OBJ=$(addprefix $(VC4_ARCH_BUILD)/,$(VC4_ARCH_SRC:.c=.o))
VC4_ARCH_OBJ+=$(VC4_ARCH_BUILD)/arch_vc4.o
EXTERNAL_STATIC_OBJS+=$(VC4_ARCH_OBJ)

# must come before r2's libr/arch/include, which ships its own sysdep.h, mybfd.h..
VC4_ARCH_CFLAGS=-I$(VC4_ARCH_WD) -I$(VC4_ARCH_WD)/include \
	-I$(VC4_ARCH_WD)/include/opcode -I$(VC4_ARCH_WD)/../include

$(VC4_ARCH_BUILD)/arch_vc4.o: $(VC4_ARCH_WD)/r2plugin/arch/arch_vc4.c $(VC4_ARCH_WD)/../../p/arch_vc4.c
	@mkdir -p $(dir $@)
	$(CC) -c $(VC4_ARCH_CFLAGS) $(CFLAGS) -o $@ $<

$(VC4_ARCH_BUILD)/%.o: $(VC4_ARCH_WD)/%.c
	@mkdir -p $(dir $@)
	$(CC) -c $(VC4_ARCH_CFLAGS) $(CFLAGS) -o $@ $<

-include $(VC4_ARCH_OBJ:.o=.d)
