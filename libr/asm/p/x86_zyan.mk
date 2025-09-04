CFLAGS_ZYAN=$(CFLAGS)
CFLAGS_ZYAN+=-I../arch/x86/zyan/include

OBJ_X86_ZYAN=arch_x86_zyan.o
OBJ_X86_ZYAN+=zyan_Decoder.o
OBJ_X86_ZYAN+=zyan_Formatter.o
OBJ_X86_ZYAN+=zyan_InstructionTable.o
OBJ_X86_ZYAN+=zyan_Mnemonic.o
OBJ_X86_ZYAN+=zyan_Register.o
OBJ_X86_ZYAN+=zyan_Utils.o
OBJ_X86_ZYAN+=zyan_Zydis.o

STATIC_OBJ+=${OBJ_X86_ZYAN}
TARGET_X86_ZYAN=arch_x86_zyan.$(LIBEXT)
ALL_TARGETS+=${TARGET_X86_ZYAN}

arch_x86_zyan.o: arch_x86_zyan.c
	$(CC) -c $(CFLAGS_ZYAN) $< -o $@

${TARGET_X86_ZYAN}: ${OBJ_X86_ZYAN}
	${CC} ${LDFLAGS} ${CFLAGS_ZYAN} -o ${TARGET_X86_ZYAN} ${OBJ_X86_ZYAN}

zyan_Decoder.o: ../arch/x86/zyan/src/Decoder.c
	$(CC) -c $(CFLAGS_ZYAN) -o $@ $<
zyan_Formatter.o: ../arch/x86/zyan/src/Formatter.c
	$(CC) -c $(CFLAGS_ZYAN) -o $@ $<
zyan_InstructionTable.o: ../arch/x86/zyan/src/InstructionTable.c
	$(CC) -c $(CFLAGS_ZYAN) -o $@ $<
zyan_Mnemonic.o: ../arch/x86/zyan/src/Mnemonic.c
	$(CC) -c $(CFLAGS_ZYAN) -o $@ $<
zyan_Register.o: ../arch/x86/zyan/src/Register.c
	$(CC) -c $(CFLAGS_ZYAN) -o $@ $<
zyan_Utils.o: ../arch/x86/zyan/src/Utils.c
	$(CC) -c $(CFLAGS_ZYAN) -o $@ $<
zyan_Zydis.o: ../arch/x86/zyan/src/Zydis.c
	$(CC) -c $(CFLAGS_ZYAN) -o $@ $<
