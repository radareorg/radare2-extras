VC4_ASM_WD=$(LIBR)/xps/p/vc4
VC4_ASM_OBJ=$(VC4_ASM_WD)/build/r2plugin/asm/pseudo.o
EXTERNAL_STATIC_OBJS+=$(VC4_ASM_OBJ)

$(VC4_ASM_OBJ): $(VC4_ASM_WD)/pseudo.c
	@mkdir -p $(dir $@)
	$(CC) -c $(CFLAGS) -o $@ $<
