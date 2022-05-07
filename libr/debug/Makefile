evm:
	$(MAKE) -C p debug_evm.$(LIBEXT)

unicorn:
	$(MAKE) -C p debug_unicorn.$(LIBEXT)

PD=$(shell r2 -H R2_USER_PLUGINS)
u:
	$(MAKE) unicorn
	rm -f $(PD)/debug_unicorn.$(LIBEXT)
	cp -f p/debug_unicorn.$(LIBEXT) $(PD)/
	-codesign -f -s - $(PD)/debug_unicorn.$(LIBEXT)

all:
	$(MAKE) -C p

clean:
	$(MAKE) -C p clean

install:
	$(MAKE) -C p install

include ../../options.mk
