# vector35 arm64 disassembler

OBJ_ARMV35=asm_arm_v35.o
ARM64V35_HOME=$(shell pwd)/../arch/arm/v35arm64/
include ../arch/arm/v35arm64/deps.mk
OBJ_ARMV35+=$(ARM64V35_LINK)

STATIC_OBJ+=${OBJ_ARMV35}
SHARED_OBJ+=${SHARED_ARMV35}
TARGET_ARMV35=asm_arm_v35.${LIBEXT}

ALL_TARGETS+=${TARGET_ARMV35}

%.o: %.c
	$(CC) $(ARM64V35_CFLAGS) $(CFLAGS) -o $@ -c $<

$(OBJC_ARMV35): $(ARM64V35_SRCDIR)

${TARGET_ARMV35}: $(ARM64V35_SRCDIR) $(OBJ_ARMV35)
	${CC} $(call libname,asm_arm_v35) -o $(TARGET_ARMV35) \
		${OBJ_ARMV35} $(ARM64V35_LDFLAGS) \
		${LDFLAGS} $(ARM64V35_CFLAGS) $(CFLAGS)
