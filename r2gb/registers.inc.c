/* radare2 - LGPL - Copyright 2026 - pancake */

typedef struct {
	RReg *reg;
	REsilRegInterface previous;
	RRegItem *single[128];
	RRegItem *pair[128];
	RRegItem *mpc;
	RRegItem *ime;
} GameBoyRegisters;

static RRegItem *gameboy_register_item(GameBoyRegisters *registers, const char *name) {
	ut8 first = name[0];
	if (!first || first >= 128) {
		return NULL;
	}
	if (!name[1]) {
		return registers->single[first];
	}
	if (!name[2]) {
		if (!strcmp (name, "PC")) {
			return registers->mpc;
		}
		if (!strcmp (name, "SP")) {
			return registers->pair['s'];
		}
		RRegItem *item = registers->pair[first];
		return item && !strcmp (item->name, name)? item: NULL;
	}
	if (!strcmp (name, "mpc")) {
		return registers->mpc;
	}
	return !strcmp (name, "ime")? registers->ime: NULL;
}

static bool gameboy_register_is_reg(void *user, const char *name) {
	GameBoyRegisters *registers = user;
	return gameboy_register_item (registers, name) || registers->previous.is_reg (registers->previous.reg, name);
}

static bool gameboy_register_read(void *user, const char *name, ut64 *value) {
	GameBoyRegisters *registers = user;
	RRegItem *item = gameboy_register_item (registers, name);
	if (!item) {
		return registers->previous.reg_read (registers->previous.reg, name, value);
	}
	*value = r_reg_get_value (registers->reg, item);
	return true;
}

static bool gameboy_register_write(void *user, const char *name, ut64 value) {
	GameBoyRegisters *registers = user;
	RRegItem *item = gameboy_register_item (registers, name);
	return item? r_reg_set_value (registers->reg, item, value): registers->previous.reg_write (registers->previous.reg, name, value);
}

static ut32 gameboy_register_size(void *user, const char *name) {
	GameBoyRegisters *registers = user;
	RRegItem *item = gameboy_register_item (registers, name);
	return item? item->size: registers->previous.reg_size (registers->previous.reg, name);
}

static bool gameboy_register_alias(void *user, int alias, const char *name) {
	GameBoyRegisters *registers = user;
	return registers->previous.reg_alias (registers->previous.reg, alias, name);
}

static ut32 gameboy_register_packed_size(void *user, const char *name) {
	return 0;
}

static void gameboy_registers_init(GameBoyRegisters *registers, RCore *core) {
	static const char single[] = "abcdefhlmZNHC";
	static const char *pair[] = { "af", "bc", "de", "hl", "pc", "sp" };
	registers->reg = core->anal->reg;
	registers->previous = core->esil.esil.reg_if;
	int i;
	for (i = 0; single[i]; i++) {
		char name[] = { single[i], 0 };
		registers->single[(ut8)single[i]] = r_reg_get (registers->reg, name, -1);
	}
	for (i = 0; i < R_ARRAY_SIZE (pair); i++) {
		registers->pair[(ut8)pair[i][0]] = r_reg_get (registers->reg, pair[i], -1);
	}
	registers->mpc = r_reg_get (registers->reg, "mpc", -1);
	registers->ime = r_reg_get (registers->reg, "ime", -1);
	core->esil.esil.reg_if = (REsilRegInterface) {
		.reg = registers,
		.is_reg = gameboy_register_is_reg,
		.reg_read = gameboy_register_read,
		.reg_write = gameboy_register_write,
		.reg_size = gameboy_register_size,
		.reg_alias = gameboy_register_alias,
		.reg_packed_size = gameboy_register_packed_size,
	};
}

static void gameboy_registers_fini(GameBoyRegisters *registers, RCore *core) {
	core->esil.esil.reg_if = registers->previous;
	int i;
	for (i = 0; i < R_ARRAY_SIZE (registers->single); i++) {
		r_unref (registers->single[i]);
		r_unref (registers->pair[i]);
	}
	r_unref (registers->mpc);
	r_unref (registers->ime);
}

static ut64 gameboy_register_get(REsil *esil, const char *name) {
	ut64 value = 0;
	esil->reg_if.reg_read (esil->reg_if.reg, name, &value);
	return value;
}

static void gameboy_register_set(REsil *esil, const char *name, ut64 value) {
	esil->reg_if.reg_write (esil->reg_if.reg, name, value);
}
