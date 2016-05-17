OBJ_EWF=io_ewf.o

STATIC_OBJ+=${OBJ_EWF}
TARGET_EWF=io_ewf.${LIBEXT}
ALL_TARGETS+=${TARGET_EWF}

ifeq (${HAVE_LIB_EWF},1)
CFLAGS+=${EWF_CFLAGS}
LDFLAGS+=${EWF_LDFLAGS}
CFLAGS+=${R2_CFLAGS}
LDFLAGS+=${R2_LDFLAGS}
endif
#/opt/local/include

ifeq (${HAVE_LIB_EWF},1)
${TARGET_EWF}: ${OBJ_EWF}
	#${CC_LIB} $(call libname,io_ewf) ${CFLAGS} -o ${TARGET_EWF} ${OBJ_EWF} ${LINKFLAGS}
	${CC} -shared ${CFLAGS} -o ${TARGET_EWF} ${OBJ_EWF} ${LINKFLAGS}
else
${TARGET_EWF}:
	@echo "Cannot find libewf"
endif

ewf: ${TARGET_EWF}

ewf-install:
	cp -f ${TARGET_EWF} ~/.config/radare2/plugins

ewf-uninstall:
	rm -f ~/.config/radare2/plugins/${TARGET_EWF} 
