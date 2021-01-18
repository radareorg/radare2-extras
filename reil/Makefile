R2_LIBEXT=$(shell r2 -HR2_LIBEXT)

all:
	$(CC) -shared esil2reil.c core_esil2reil.c -o core_esil2reil.$(R2_LIBEXT) $(shell pkg-config --cflags --libs r_core r_anal)

clean:
	rm -f core_esil2reil.$(R2_LIBEXT)
