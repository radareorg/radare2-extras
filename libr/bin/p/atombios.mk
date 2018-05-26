OBJ_ATOMBIOS=bin_atombios.o
OBJ_ATOMBIOS+=../../asm/arch/atombios/atombios.o

STATIC_OBJ+=${OBJ_ATOMBIOS}
TARGET_ATOMBIOS=bin_atombios.$(LIBEXT)

ALL_TARGETS+=${TARGET_ATOMBIOS}
CFLAGS+=-I../format/atombios
CFLAGS+=-I../../asm/arch/atombios/

${TARGET_ATOMBIOS}: ${OBJ_ATOMBIOS}
	${CC} -g ${CFLAGS} -o ${TARGET_ATOMBIOS} ${OBJ_ATOMBIOS} \
		$(R2_CFLAGS) $(R2_LDFLAGS) -lr_util

