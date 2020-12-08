N=anal_arm_v35
ARM64V35_HOME=$(shell pwd)/../../asm/arch/arm/v35arm64/
include ../../asm/arch/arm/v35arm64/deps.mk
OBJ_ARM_V35=anal_arm_v35.o
OBJ_ARM_V35+=${ARM64V35_LINK}

STATIC_OBJ+=${OBJ_ARM_V35}
CFLAGS+=$(ARM64V35_CFLAGS)
TARGET_ARM_V35=$(N).${LIBEXT}

ALL_TARGETS+=${TARGET_ARM_V35}

${TARGET_ARM_V35}: $(STATIC_OBJ)
	${CC} ${CFLAGS} $(call libname,$(N)) $(ARM64V35_CFLAGS) \
		-lr_util -lr_search \
		-o $(TARGET_ARM_V35) ${OBJ_ARM_V35} $(ARM64V35_LDFLAGS)
