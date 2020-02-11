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
CFLAGS+=-I../arch/x86/zyan/include

${TARGET_X86_ZYAN}: ${OBJ_X86_ZYAN}
	${CC} ${LDFLAGS} ${CFLAGS} -o ${TARGET_X86_ZYAN} ${OBJ_X86_ZYAN}
