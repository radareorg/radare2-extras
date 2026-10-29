/* radare2 - LGPL-3.0-only - Copyright 2026 - pancake */
#include <r_anal.h>
#include <errno.h>
#define R2_PLUGIN_INCORE 1
#include "../arch_md32.c"

#define MAX_MAPS 32
#define MAX_BYTES (64 * 1024 * 1024)

typedef struct {
	ut64 base;
	size_t size;
	ut8 *bytes;
	ut8 *initialized;
	bool code;
	const char *name;
} Map;

typedef struct {
	Map maps[MAX_MAPS];
	unsigned nmaps;
	RReg *reg;
	ut8 reg_initialized[256];
	const char *reason;
	ut64 fault;
	char fault_reg[32];
	PJ *events;
	REsil *esil;
} Machine;

static Map *find_map(Machine *m, ut64 addr, int len, bool code) {
	unsigned i;
	for (i = 0; i < m->nmaps; i++) {
		Map *map = &m->maps[i];
		if (map->code == code && len > 0 && addr >= map->base
			&& addr - map->base < map->size && (ut64)len <= map->size - (addr - map->base)) {
			return map;
		}
	}
	return NULL;
}

static void event(Machine *m, const char *kind, ut64 addr, int len) {
	pj_o (m->events);
	pj_ks (m->events, "access", kind);
	pj_kn (m->events, "address", addr);
	pj_ki (m->events, "size", len);
	pj_end (m->events);
}

// Backing reads also serve ESIL's internal pre-store flag bookkeeping.
// Those reads are not firmware reads and must not report uninitialized RAM.
static bool read_memory(void *user, ut64 addr, ut8 *buf, int len) {
	Machine *m = user;
	Map *map = find_map (m, addr, len, false);
	if (!map) {
		return false;
	}
	memcpy (buf, map->bytes + addr - map->base, len);
	return true;
}

static bool check_memory(REsil *esil, ut64 addr, ut8 *buf, int len) {
	Machine *m = esil->cb.user;
	Map *map = find_map (m, addr, len, false);
	event (m, "read", addr, len);
	if (!map) {
		m->reason = "unmapped_data_read";
		m->fault = addr;
	} else {
		const size_t off = addr - map->base;
		int i;
		for (i = 0; i < len; i++) {
			if (!map->initialized[off + i]) {
				m->reason = "uninitialized_data_read";
				m->fault = addr + i;
				break;
			}
		}
	}
	if (!m->reason) {
		return false;
	}
	r_esil_set_fault (esil, R_ANAL_TRAP_READ_ERR, m->fault);
	esil->parse_stop = 1;
	memset (buf, 0, len);
	return true;
}

static bool write_memory(void *user, ut64 addr, const ut8 *buf, int len) {
	Machine *m = user;
	Map *map = find_map (m, addr, len, false);
	event (m, "write", addr, len);
	if (!map) {
		m->reason = "unmapped_data_write";
		m->fault = addr;
		return false;
	}
	const size_t off = addr - map->base;
	memcpy (map->bytes + off, buf, len);
	memset (map->initialized + off, 1, len);
	return true;
}

static bool reg_range(Machine *m, const char *name, size_t *off, size_t *size) {
	RRegItem *ri = r_reg_get (m->reg, name, -1);
	if (!ri || ri->offset < 0 || ri->size <= 0 || ri->offset % 8 || ri->size % 8) {
		return false;
	}
	*off = ri->offset / 8;
	*size = ri->size / 8;
	return *off < sizeof (m->reg_initialized) && *size <= sizeof (m->reg_initialized) - *off;
}

// Only semantic reads go through this hook. ESIL's silent read of a write
// destination's old value is bookkeeping, not a firmware use of that value.
static bool check_register(REsil *esil, const char *name, ut64 *value, int *bits) {
	Machine *m = esil->cb.user;
	size_t off, size;
	if (!reg_range (m, name, &off, &size)) {
		return false;
	}
	size_t i;
	for (i = 0; i < size; i++) {
		if (!m->reg_initialized[off + i]) {
			m->reason = "uninitialized_register_read";
			r_str_ncpy (m->fault_reg, name, sizeof (m->fault_reg));
			esil->parse_stop = 1;
			*value = 0;
			if (bits) {
				*bits = size * 8;
			}
			return true;
		}
	}
	return false;
}

static bool mark_register(REsil *esil, const char *name, ut64 *value) {
	Machine *m = esil->cb.user;
	size_t off, size;
	if (reg_range (m, name, &off, &size)) {
		memset (m->reg_initialized + off, 1, size);
	}
	return false;
}

static bool set_register(Machine *m, const char *name, ut64 value) {
	size_t off, size;
	if (!reg_range (m, name, &off, &size) || !r_reg_setv (m->reg, name, value)) {
		return false;
	}
	memset (m->reg_initialized + off, 1, size);
	return true;
}

static bool number(const char *str, ut64 *value) {
	char *end;
	if (!str || !*str || *str == '-') {
		return false;
	}
	errno = 0;
	*value = strtoull (str, &end, 0);
	return !errno && !*end;
}

static bool add_map(Machine *m, const char *arg, bool code, bool zero, bool file) {
	if (m->nmaps == MAX_MAPS) {
		return false;
	}
	char *left = strdup (arg);
	char *sep = strrchr (left, file? '@': ':');
	ut64 base, size;
	if (!sep) {
		free (left);
		return false;
	}
	*sep++ = 0;
	Map map = { .code = code, .name = arg };
	if (file) {
		if (!number (sep, &base)) {
			free (left);
			return false;
		}
		const ut64 disk_size = r_file_size (left);
		if (!disk_size || disk_size > MAX_BYTES) {
			free (left);
			return false;
		}
		size_t bytes = 0;
		map.bytes = (ut8 *)r_file_slurp (left, &bytes);
		size = bytes;
	} else {
		if (!number (left, &base) || !number (sep, &size)) {
			free (left);
			return false;
		}
	}
	free (left);
	if (!size || size > MAX_BYTES || base > UT32_MAX || size > (1ULL << 32) - base) {
		free (map.bytes);
		return false;
	}
	map.base = base;
	map.size = size;
	unsigned i;
	for (i = 0; i < m->nmaps; i++) {
		Map *old = &m->maps[i];
		if (old->code == code && base < old->base + old->size && old->base < base + size) {
			free (map.bytes);
			return false;
		}
	}
	if (!map.bytes) {
		if (file) {
			return false;
		}
		map.bytes = calloc (size, 1);
	}
	map.initialized = malloc (size);
	if (!map.bytes || !map.initialized) {
		free (map.bytes);
		free (map.initialized);
		return false;
	}
	memset (map.initialized, file || zero, size);
	m->maps[m->nmaps++] = map;
	return true;
}

static void usage(void) {
	fprintf (stderr, "Usage: md32-run [--cpu md32|usip] --image FILE@BASE [--image ...]\n"
		"  --entry ADDRESS | --vector (execute vector-0 instruction at first image base)\n"
		"  --data FILE@BASE  --ram BASE:SIZE  --zero BASE:SIZE\n"
		"  --reg NAME=VALUE  --steps COUNT (default 100)\n"
		"Code and data maps are separate. RAM/registers start uninitialized.\n"
		"JSON trace stops on missing semantics or external/uninitialized state.\n");
}

int main(int argc, char **argv) {
	Machine m = { 0 };
	const char *cpu = "md32";
	ut64 entry = UT64_MAX, steps = 100;
	bool vector = false;
	int rc = 1, i;
	RAnal *anal = NULL;
	PJ *output = pj_new ();
	m.events = pj_new ();
	if (!output || !m.events) {
		goto cleanup;
	}
	for (i = 1; i < argc; i++) {
		const char *opt = argv[i];
		if (!strcmp (opt, "--vector")) {
			vector = true;
			continue;
		}
		if (i + 1 == argc) {
			goto invalid;
		}
		const char *arg = argv[++i];
		if (!strcmp (opt, "--cpu")) {
			cpu = arg;
			if (strcmp (cpu, "md32") && strcmp (cpu, "ms15e30") && strcmp (cpu, "usip")) {
				goto invalid;
			}
		} else if (!strcmp (opt, "--image") || !strcmp (opt, "--data")) {
			if (!add_map (&m, arg, !strcmp (opt, "--image"), false, true)) {
				goto invalid;
			}
		} else if (!strcmp (opt, "--ram") || !strcmp (opt, "--zero")) {
			if (!add_map (&m, arg, false, !strcmp (opt, "--zero"), false)) {
				goto invalid;
			}
		} else if (!strcmp (opt, "--entry")) {
			if (!number (arg, &entry) || entry > UT32_MAX) {
				goto invalid;
			}
		} else if (!strcmp (opt, "--steps")) {
			if (!number (arg, &steps) || !steps || steps > 1000000) {
				goto invalid;
			}
		} else if (strcmp (opt, "--reg")) {
			goto invalid;
		}
	}
	Map *first = NULL;
	for (i = 0; i < (int)m.nmaps; i++) {
		if (m.maps[i].code) {
			first = &m.maps[i];
			break;
		}
	}
	if (!first || (vector && entry != UT64_MAX)) {
		goto invalid;
	}
	if (vector) {
		if (first->size < 4) {
			goto invalid;
		}
		// These firmware vectors contain instructions, not address pointers.
		entry = first->base;
	} else if (entry == UT64_MAX) {
		entry = first->base;
	}
	anal = r_anal_new ();
	if (!anal) {
		goto cleanup;
	}
	anal->config->bits = 32;
	anal->config->endian = R_SYS_ENDIAN_BIG;
	RArchConfig cfg = { .bits = 32, .endian = R_SYS_ENDIAN_BIG, .cpu = (char *)cpu };
	RArchSession session = { .config = &cfg };
	m.reg = anal->reg;
	char *profile = regs (&session);
	bool ok = r_reg_set_profile_string (m.reg, profile);
	free (profile);
	if (!ok || !set_register (&m, "pc", entry)) {
		goto cleanup;
	}
	for (i = 1; i + 1 < argc; i++) {
		if (strcmp (argv[i], "--reg")) {
			continue;
		}
		char *arg = strdup (argv[++i]);
		char *equal = strchr (arg, '=');
		ut64 value;
		ok = false;
		if (equal) {
			*equal++ = 0;
			ok = number (equal, &value) && set_register (&m, arg, value);
		}
		free (arg);
		if (!ok) {
			goto invalid;
		}
	}
	REsilOptions opts = r_esil_options (m.reg, NULL);
	opts.addrsize = 32;
	opts.iotrap = true;
	opts.ifaces.mem = (REsilMemInterface) { .user = &m, .mem_read = read_memory, .mem_write = write_memory };
	m.esil = r_esil_new (&opts);
	if (!m.esil) {
		goto cleanup;
	}
	m.esil->anal = anal;
	m.esil->cb.user = &m;
	m.esil->cb.hook_mem_read = check_memory;
	m.esil->cb.hook_reg_read = check_register;
	m.esil->cb.hook_reg_write = mark_register;
	pj_a (m.events);
	pj_o (output);
	pj_ks (output, "cpu", cpu);
	pj_kn (output, "entry", entry);
	pj_ks (output, "entry_source", vector? "vector0_instruction": "explicit_or_image_base");
	pj_ka (output, "trace");
	ut64 completed = 0, stopped_pc = entry;
	bool partial = false;
	while (completed < steps) {
		const ut64 pc = r_reg_getv (m.reg, "pc");
		stopped_pc = pc;
		if (pc & 1) {
			m.reason = "unaligned_instruction_fetch";
			m.fault = pc;
			break;
		}
		Map *map = find_map (&m, pc, 2, true);
		if (!map) {
			m.reason = "unmapped_instruction_fetch";
			m.fault = pc;
			break;
		}
		const size_t off = pc - map->base;
		RAnalOp op;
		r_anal_op_init (&op);
		op.addr = pc;
		op.bytes = map->bytes + off;
		op.weakbytes = true;
		op.size = R_MIN (64, map->size - off);
		ok = decode (&session, &op, R_ARCH_OP_MASK_ALL);
		pj_o (output);
		pj_kn (output, "pc", pc);
		pj_ki (output, "size", op.size);
		pj_ks (output, "instruction", op.mnemonic? op.mnemonic: "invalid");
		pj_ks (output, "esil", r_strbuf_get (&op.esil));
		pj_end (output);
		if (!ok) {
			m.reason = "invalid_or_truncated_instruction";
		} else if (op.delay) {
			m.reason = "unsupported_delay_slot_execution";
		} else if (!*r_strbuf_get (&op.esil) && op.type != R_ANAL_OP_TYPE_NOP) {
			m.reason = "unsupported_instruction_semantics";
		}
		if (m.reason) {
			r_anal_op_fini (&op);
			break;
		}
		r_esil_set_pc (m.esil, pc);
		set_register (&m, "pc", (ut32)(pc + op.size));
		ok = op.type == R_ANAL_OP_TYPE_NOP || r_esil_parse (m.esil, r_strbuf_get (&op.esil));
		const bool self_loop = op.type == R_ANAL_OP_TYPE_JMP && op.jump == pc;
		r_esil_stack_free (m.esil);
		r_anal_op_fini (&op);
		if (!ok || m.reason || m.esil->trap) {
			partial = true;
			if (!m.reason) {
				m.reason = "esil_execution_fault";
			}
			break;
		}
		completed++;
		if (self_loop) {
			m.reason = "unconditional_self_loop";
			break;
		}
	}
	pj_end (output);
	pj_kn (output, "completed_steps", completed);
	pj_kn (output, "last_attempt_pc", stopped_pc);
	pj_kb (output, "partial_instruction_state", partial);
	pj_kn (output, "pc", r_reg_getv (m.reg, "pc"));
	pj_ks (output, "stop_reason", m.reason? m.reason: "step_limit");
	if (m.reason && (strstr (m.reason, "data_") || strstr (m.reason, "fetch"))) {
		pj_kn (output, "fault_address", m.fault);
	}
	if (*m.fault_reg) {
		pj_ks (output, "fault_register", m.fault_reg);
	}
	pj_ko (output, "initialized_registers");
	RListIter *it;
	RRegItem *ri;
	r_list_foreach (r_reg_get_list (m.reg, R_REG_TYPE_GPR), it, ri) {
		size_t off, size, j;
		if (!reg_range (&m, ri->name, &off, &size)) {
			continue;
		}
		for (j = 0; j < size && m.reg_initialized[off + j]; j++) {
		}
		if (j == size) {
			pj_kn (output, ri->name, r_reg_get_value (m.reg, ri));
		}
	}
	pj_end (output);
	pj_end (m.events);
	pj_k (output, "memory_accesses");
	pj_j (output, pj_string (m.events));
	pj_end (output);
	puts (pj_string (output));
	rc = 0;
	goto cleanup;
invalid:
	usage ();
cleanup:
	r_esil_free (m.esil);
	r_anal_free (anal);
	pj_free (output);
	pj_free (m.events);
	for (i = 0; i < (int)m.nmaps; i++) {
		free (m.maps[i].bytes);
		free (m.maps[i].initialized);
	}
	return rc;
}
