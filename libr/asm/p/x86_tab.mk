OBJ_X86_TAB=arch_x86_tab.o

STATIC_OBJ+=${OBJ_X86_TAB}
TARGET_X86_TAB=arch_x86_tab.$(LIBEXT)

ALL_TARGETS+=${TARGET_X86_TAB}

$(OBJ_X86_TAB): %.o : %.c
	$(CC) -c $(CFLAGS) $< -o $@

${TARGET_X86_TAB}: ${OBJ_X86_TAB}
	${CC} $(call libname,arch_x86_tab) ${LDFLAGS} ${CFLAGS} -o ${TARGET_X86_TAB} ${OBJ_X86_TAB}
