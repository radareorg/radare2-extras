CFLAGS_ZYAN=$(R2_CFLAGS)
CFLAGS_ZYAN+=-g -I$(TOP)/shlr -I../arch/ -I../arch/include
CFLAGS_ZYAN+=-Wall -shared -fPIC ${LDFLAGS_LIB}
CFLAGS_ZYAN+=-I../arch/x86/zyan/include

OBJ_X86_ZYAN=asm_x86_zyan.o
OBJ_X86_ZYAN+=../arch/x86/zyan/src/Decoder.o
OBJ_X86_ZYAN+=../arch/x86/zyan/src/Formatter.o
OBJ_X86_ZYAN+=../arch/x86/zyan/src/InstructionTable.o
OBJ_X86_ZYAN+=../arch/x86/zyan/src/Mnemonic.o
OBJ_X86_ZYAN+=../arch/x86/zyan/src/Register.o
OBJ_X86_ZYAN+=../arch/x86/zyan/src/Utils.o
OBJ_X86_ZYAN+=../arch/x86/zyan/src/Zydis.o

STATIC_OBJ+=${OBJ_X86_ZYAN}
TARGET_X86_ZYAN=asm_x86_zyan.$(LIBEXT)
ALL_TARGETS+=${TARGET_X86_ZYAN}

$(OBJ_X86_ZYAN): %.o : %.c
	$(CC) -c $(CFLAGS_ZYAN) $< -o $@

${TARGET_X86_ZYAN}: ${OBJ_X86_ZYAN}
	${CC} ${LDFLAGS} ${CFLAGS_ZYAN} -o ${TARGET_X86_ZYAN} ${OBJ_X86_ZYAN}
