EXTERNAL_PLUGINS+=vc4

.PHONY: vc4

vc4: p/vc4

p/vc4:
	cd p && git clone --depth 1 https://github.com/radareorg/radare2-extras
	ln -fs radare2-extras/libr/asm/arch/vc4 p/vc4
