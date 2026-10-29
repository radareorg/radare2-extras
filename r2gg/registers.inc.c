/* radare2 - LGPL - Copyright 2026 - pancake */

typedef struct {
	RReg *reg;
	REsilRegInterface previous;
	RRegItem *items[128];
	RRegItem *pc, *sp;
} GameGearRegisters;

static ut32 gamegear_register_hash(const char *name) {
	return ((ut8)name[0] * 33 + (name[0]? (ut8)name[1]: 0)) & 127;
}

static RRegItem *gamegear_register_item(GameGearRegisters *registers, const char *name) {
	if (!strcmp (name, "PC")) {
		return registers->pc;
	}
	if (!strcmp (name, "SP")) {
		return registers->sp;
	}
	ut32 index = gamegear_register_hash (name);
	while (registers->items[index]) {
		RRegItem *item = registers->items[index];
		if (!strcmp (item->name, name)) {
			return item;
		}
		index = (index + 1) & 127;
	}
	return NULL;
}

static bool gamegear_register_is_reg(void *user, const char *name) {
	GameGearRegisters *registers = user;
	return gamegear_register_item (registers, name) || registers->previous.is_reg (registers->previous.reg, name);
}

static bool gamegear_register_read(void *user, const char *name, ut64 *value) {
	GameGearRegisters *registers = user;
	RRegItem *item = gamegear_register_item (registers, name);
	if (!item) {
		return registers->previous.reg_read (registers->previous.reg, name, value);
	}
	*value = r_reg_get_value (registers->reg, item);
	return true;
}

static bool gamegear_register_write(void *user, const char *name, ut64 value) {
	GameGearRegisters *registers = user;
	RRegItem *item = gamegear_register_item (registers, name);
	return item? r_reg_set_value (registers->reg, item, value): registers->previous.reg_write (registers->previous.reg, name, value);
}

static ut32 gamegear_register_size(void *user, const char *name) {
	GameGearRegisters *registers = user;
	RRegItem *item = gamegear_register_item (registers, name);
	return item? item->size: registers->previous.reg_size (registers->previous.reg, name);
}

static bool gamegear_register_alias(void *user, int alias, const char *name) {
	GameGearRegisters *registers = user;
	return registers->previous.reg_alias (registers->previous.reg, alias, name);
}

static ut32 gamegear_register_packed_size(void *user, const char *name) {
	GameGearRegisters *registers = user;
	RRegItem *item = gamegear_register_item (registers, name);
	return item? item->packed_size: registers->previous.reg_packed_size (registers->previous.reg, name);
}

static void gamegear_registers_init(GameGearRegisters *registers, RCore *core) {
	registers->reg = core->anal->reg;
	registers->previous = core->esil.esil.reg_if;
	RListIter *iter;
	RRegItem *item;
	int count = 0;
	r_list_foreach (r_reg_get_list (registers->reg, R_REG_TYPE_ALL), iter, item) {
		if (++count > 96) {
			break;
		}
		ut32 index = gamegear_register_hash (item->name);
		while (registers->items[index]) {
			index = (index + 1) & 127;
		}
		registers->items[index] = r_ref (item);
	}
	registers->pc = r_reg_get (registers->reg, "PC", -1);
	registers->sp = r_reg_get (registers->reg, "SP", -1);
	core->esil.esil.reg_if = (REsilRegInterface) {
		.reg = registers,
		.is_reg = gamegear_register_is_reg,
		.reg_read = gamegear_register_read,
		.reg_write = gamegear_register_write,
		.reg_size = gamegear_register_size,
		.reg_alias = gamegear_register_alias,
		.reg_packed_size = gamegear_register_packed_size,
	};
}

static void gamegear_registers_fini(GameGearRegisters *registers, RCore *core) {
	core->esil.esil.reg_if = registers->previous;
	int i;
	for (i = 0; i < R_ARRAY_SIZE (registers->items); i++) {
		r_unref (registers->items[i]);
	}
	r_unref (registers->pc);
	r_unref (registers->sp);
}

static ut64 gamegear_register_get(REsil *esil, const char *name) {
	ut64 value = 0;
	esil->reg_if.reg_read (esil->reg_if.reg, name, &value);
	return value;
}

static void gamegear_register_set(REsil *esil, const char *name, ut64 value) {
	esil->reg_if.reg_write (esil->reg_if.reg, name, value);
}
