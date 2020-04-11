/* radare - LGPL - Copyright 2015-2017 - pancake */

// r2 -e dbg.backend=unicorn -e cfg.debug=1 /bin/ls
// r2 -D unicorn /bin/ls
// > dpa
// > dr rip=$$
// > ds
// > dr=

#include <r_userconf.h>
#include <r_debug.h>
#include <r_asm.h>
#include <r_cons.h>
#include <r_reg.h>
#include <r_lib.h>
#include <sdb/sdb.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/param.h>
#include <unicorn/unicorn.h>

static const char *logo = \
"                 /\\'.         _,.\n" \
"                 |:\\ \\.     .'_/\n" \
"            _.-  |(\\\\ \\   .'_.'\n" \
"        _.-'  ,__\\\\ \\\\_),/ _/\n" \
"      _:.'  .:::::::.___  ,'\n" \
"      //   ' ./::::::\\\\<o\\(\n" \
"     //     /|::/   `\\\\\"(  \\\n" \
"    ;/_    / ::(       `.  `.\n" \
"   /_'/   | ::::\\        `.  \\\n" \
"   '//    '\\ :::':\\_    _, ` _'-\n" \
"   / |     '\\.:/|::::.._ `-__ )/\n" \
"   | |       \\;| \\:(    '.(_ \\_)\n" \
"   | |        \\(  \\::.    '-)\n" \
"   \\ \\  ,          '\"\"\"\"---.\n" \
"    \\ \\ \\    ,        _.-...)\n" \
"     \\ \\/\\.  \\:,___.-'..:::/\n" \
"      \\ |\\:,.\\:::::'.::::/\n" \
"       `  `:;::::'.::;::'\n" \
"             '\\\":;:\"\"'\n" \
;

#define JUST_FIRST_BLOCK 0

#if HAVE_PKGCFG_UNICORN

int color = 0;
const char *msgcolor = Color_RED;
#define COLORS 5
const char *rainbow[COLORS] = {
	Color_GREEN, Color_YELLOW, Color_CYAN,
	Color_RED, Color_WHITE
};
// color=r_num_rand(COLORS); if (color>=COLORS) color=0;

#define rainbow_printf(x,y...) \

static int message(const char *fmt, ...) {
	char str[1024], *p;
	va_list ap;
	*str = 0;
	p = str;
	va_start (ap, fmt);
	vsnprintf (str, sizeof (str), fmt, ap);
fprintf (stderr, Color_BMAGENTA"%s"Color_RESET, p);
	if (++color>=COLORS) color = 0;
	msgcolor = rainbow[color];
#if 0
	while (*p) {
		fprintf(stderr,"%s%c", msgcolor, *p);
		if (++color>=COLORS) color = 0;
		msgcolor = rainbow[color];
		p++;
	}
	fprintf (stderr, "%s", Color_RESET);
#endif
	va_end (ap);
	return 0;
}

static uc_engine *uh = NULL;

static int r_debug_unicorn_init(RDebug *dbg);

static int r_debug_handle_signals(RDebug *dbg) {
	return -1;
}

static const char *r_debug_unicorn_reg_profile(RDebug *dbg) {
	if (dbg->bits & R_SYS_BITS_64) {
		return strdup (
			"=PC	rip\n"
			"=SP	rsp\n"
			"=BP	rbp\n"
			"=A0	rax\n"
			"=A1	rbx\n"
			"=A2	rcx\n"
			"=A3	rdi\n"
			"gpr	rip	8	0x000	0\n"
			"gpr	rax	8	0x008	0\n"
			"gpr	rcx	8	0x010	0\n"
			"gpr	rdx	8	0x018	0\n"
			"gpr	rbx	8	0x020	0\n"
			"gpr	rsp	8	0x028	0\n"
			"gpr	rbp	8	0x030	0\n"
			"gpr	rsi	8	0x038	0\n"
			"gpr	rdi	8	0x040	0\n"
			"gpr	r8	8	0x048	0\n"
			"gpr	r9	8	0x050	0\n"
			"gpr	r10	8	0x058	0	\n"
			"gpr	r11	8	0x060	0	\n"
			"gpr	r12	8	0x068	0	\n"
			"gpr	r13	8	0x070	0	\n"
			"gpr	r14	8	0x078	0	\n"
			"gpr	r15	8	0x080	0	\n"
			"gpr	eflags	4	0x088	0	c1p.a.zstido.n.rv\n"
#if 0
			"seg	cs	2	0x038	0\n"
			"seg	ds	2	0x03A	0\n"
			"seg	es	2	0x03C	0\n"
			"seg	fs	2	0x03E	0\n"
			"seg	gs	2	0x040	0\n"
			"seg	ss	2	0x042	0\n"
			"drx	dr0	8	0x048	0\n"
			"drx	dr1	8	0x050	0\n"
			"drx	dr2	8	0x058	0\n"
			"drx	dr3	8	0x060	0\n"
			"drx	dr6	8	0x068	0\n"
			"drx	dr7	8	0x070	0\n"
			"gpr	cf	.1	.544	0	carry\n"
			"gpr	pf	.1	.546	0	parity\n"
			"gpr	af	.1	.548	0	adjust\n"
			"gpr	zf	.1	.550	0	zero\n"
			"gpr	sf	.1	.551	0	sign\n"
			"gpr	tf	.1	.552	0	trap\n"
			"gpr	if	.1	.553	0	interrupt\n"
			"gpr	df	.1	.554	0	direction\n"
			"gpr	of	.1	.555	0	overflow\n"
#endif
			);
	} else {
		return strdup(
			"=PC	eip\n"
			"=SP	esp\n"
			"=BP	ebp\n"
			"=A0	eax\n"
			"=A1	ebx\n"
			"=A2	ecx\n"
			"=A3	edi\n"
			"drx	dr0	.32	4	0\n"
			"drx	dr1	.32	8	0\n"
			"drx	dr2	.32	12	0\n"
			"drx	dr3	.32	16	0\n"
			"drx	dr6	.32	20	0\n"
			"drx	dr7	.32	24	0\n"
			/* floating save area 4+4+4+4+4+4+4+80+4 = 112 */
			"seg	gs	.32	140	0\n"
			"seg	fs	.32	144	0\n"
			"seg	es	.32	148	0\n"
			"seg	ds	.32	152	0\n"
			"gpr	edi	.32	156	0\n"
			"gpr	esi	.32	160	0\n"
			"gpr	ebx	.32	164	0\n"
			"gpr	edx	.32	168	0\n"
			"gpr	ecx	.32	172	0\n"
			"gpr	eax	.32	176	0\n"
			"gpr	ebp	.32	180	0\n"
			"gpr	eip	.32	184	0\n"
			"seg	cs	.32	188	0\n"
			"gpr	eflags	.32	192	0	c1p.a.zstido.n.rv\n" // XXX must be flg
			"gpr	esp	.32	196	0\n"
			"seg	ss	.32	200	0\n"
			"gpr	cf	.1	.1536	0	carry\n"
			"gpr	pf	.1	.1538	0	parity\n"
			"gpr	af	.1	.1540	0	adjust\n"
			"gpr	zf	.1	.1542	0	zero\n"
			"gpr	sf	.1	.1543	0	sign\n"
			"gpr	tf	.1	.1544	0	trap\n"
			"gpr	if	.1	.1545	0	interrupt\n"
			"gpr	df	.1	.1546	0	direction\n"
			"gpr	of	.1	.1547	0	overflow\n"
			/* +512 bytes for maximum supoprted extension extended registers */
			);
	}
	return NULL;
}

static RList *r_debug_unicorn_threads(RDebug *dbg, int pid) {
	return NULL;
}

static RList *r_debug_unicorn_tids(RDebug *dbg, int pid) {
	message ("TODO: Threads: \n");
	return NULL;
}

static RList *r_debug_unicorn_pids(RDebug *dbg, int pid) {
	RList *list = r_list_new ();
	r_list_append (list, r_debug_pid_new ("???", pid, 0, 's', 0));
	return list;
}

static RList *r_debug_unicorn_map_get(RDebug *dbg) {
	RDebugMap *m;
	RList *list;
	RIOMap *map;
	int i = 0;
	list = r_list_new ();
	//list->free = r_debug_map_free;
	r_vector_foreach (&dbg->iob.io->maps.v, map) {
		m = r_debug_map_new (map->name,
			map->itv.addr,
			map->itv.addr + map->itv.size,
			map->perm, 0);
		if (m) {
			r_list_append (list, m);
		}
		if (JUST_FIRST_BLOCK)
			break;
		i++;
	}
	return list;
}

static RDebugInfo* r_debug_unicorn_info(RDebug *dbg, const char *arg) {
	RDebugInfo *rdi = R_NEW0(RDebugInfo);
	rdi->status = R_DBG_PROC_SLEEP; // TODO: Fix this
	rdi->pid = dbg->pid;
	rdi->tid = dbg->tid;
	rdi->uid = -1;// TODO
	rdi->gid = -1;// TODO
	rdi->cwd = NULL;// TODO : use readlink
	rdi->exe = NULL;// TODO : use readlink!
	//rdi->cmdline = strdup ("unicorn-emu... ");
	return rdi;
}

static RDebugMap * r_debug_unicorn_map_alloc(RDebug *dbg, ut64 addr, int size, bool thp) {
	RDebugMap *map;
	uc_err err = uc_mem_map (uh, addr, size, UC_PROT_WRITE | UC_PROT_READ);
	if (err) {
		message ("[UNICORN] Cannot allocated map\n");
		return NULL;
	}
	map = R_NEW0 (RDebugMap);
	map->name = r_str_newf ("unimap%d", r_list_length (dbg->maps));
	map->addr = addr;
	map->addr_end = addr +size;
	map->size = size;
	map->file = NULL;
	map->perm = 6; // rw
	map->user = 1;
	return map;
}

static int r_debug_desc_native_open(const char *path) {
	return 0;
}

static int r_debug_unicorn_map_dealloc(RDebug *dbg, ut64 addr, int size) {
	return 0;
}

static int r_debug_unicorn_detach(RDebug *dbg, int pid) {
	if (uh) {
		/* unicorn lib doesnt checks for null. it just crashes -_-U */
		uc_close (uh);
		uh = NULL;
	}
	return 0;
}

static bool r_debug_unicorn_kill(RDebug *dbg, int pid, int tid, int sig) {
	// TODO: implement thread support signaling here
	message ("TODO: r_debug_unicorn_kill\n");
	(void)r_debug_unicorn_detach(dbg, pid);
	return false;
}

#if 0
static int r_debug_unicorn_bp(RBreakpointItem *bp, int set, void *user) {
	RDebug *dbg = user;
	if (!bp)
		return false;
	if (!bp->hw)
		return false;
	return set?drx_add(dbg, bp->addr, bp->rwx) :drx_del(dbg, bp->addr, bp->rwx);
}
#endif

static int r_debug_unicorn_reg_read(RDebug *dbg, int type, ut8 *buf, int size) {
	// NOTE: This must be in sync with the profile.
	ut64 *rip = (ut64*)(buf+0x00);
	ut64 *rax = (ut64*)(buf+0x08);
	ut64 *rcx = (ut64*)(buf+0x10);
	ut64 *rdx = (ut64*)(buf+0x18);
	ut64 *rbx = (ut64*)(buf+0x20);
	ut64 *rsp = (ut64*)(buf+0x28);
	ut64 *rbp = (ut64*)(buf+0x30);
	ut64 *rsi = (ut64*)(buf+0x38);
	ut64 *rdi = (ut64*)(buf+0x40);
	ut64 *r8  = (ut64*)(buf+0x48);
	ut64 *r9  = (ut64*)(buf+0x50);
	ut64 *r10 = (ut64*)(buf+0x58);
	memset (buf, 0, size);
	if (type == R_REG_TYPE_GPR) {
		uc_reg_read (uh, UC_X86_REG_RIP, rip);
		uc_reg_read (uh, UC_X86_REG_RAX, rax);
		uc_reg_read (uh, UC_X86_REG_RCX, rcx);
		uc_reg_read (uh, UC_X86_REG_RDX, rdx);
		uc_reg_read (uh, UC_X86_REG_RBX, rbx);
		uc_reg_read (uh, UC_X86_REG_RSP, rsp);
		uc_reg_read (uh, UC_X86_REG_RBP, rbp);
		uc_reg_read (uh, UC_X86_REG_RSI, rsi);
		uc_reg_read (uh, UC_X86_REG_RDI, rdi);
		uc_reg_read (uh, UC_X86_REG_R8, r8);
		uc_reg_read (uh, UC_X86_REG_R9, r9);
		uc_reg_read (uh, UC_X86_REG_R10, r10);
		//message ("TODO: unicorn- reg read 0x%"PFMT64x"\n", *rip);
		return size;
	}
	return 0;
}

static int r_debug_unicorn_reg_write(RDebug *dbg, int type, const ut8* buf, int size) {
	// NOTE: This must be in sync with the profile.
	ut64 *rip = (ut64*)(buf+0x00);
	ut64 *rax = (ut64*)(buf+0x08);
	ut64 *rcx = (ut64*)(buf+0x10);
	ut64 *rdx = (ut64*)(buf+0x18);
	ut64 *rbx = (ut64*)(buf+0x20);
	ut64 *rsp = (ut64*)(buf+0x28);
	ut64 *rbp = (ut64*)(buf+0x30);
	ut64 *rsi = (ut64*)(buf+0x38);
	ut64 *rdi = (ut64*)(buf+0x40);
	ut64 *r8  = (ut64*)(buf+0x48);
	ut64 *r9  = (ut64*)(buf+0x50);
	ut64 *r10 = (ut64*)(buf+0x58);
	uc_err err;
	if (type == R_REG_TYPE_GPR) {
		uint64_t u = *rip;
		err = uc_reg_write (uh, UC_X86_REG_RIP, &u);
		if (err) {
			message ("[UNICORN] RIP reg_write ERROR\n");
		}
		uc_reg_write (uh, UC_X86_REG_RAX, rax);
		uc_reg_write (uh, UC_X86_REG_RCX, rcx);
		uc_reg_write (uh, UC_X86_REG_RDX, rdx);
		uc_reg_write (uh, UC_X86_REG_RBX, rbx);
		uc_reg_write (uh, UC_X86_REG_RSP, rsp);
		uc_reg_write (uh, UC_X86_REG_RBP, rbp);
		uc_reg_write (uh, UC_X86_REG_RSI, rsi);
		uc_reg_write (uh, UC_X86_REG_RDI, rdi);
		uc_reg_write (uh, UC_X86_REG_R8, r8);
		uc_reg_write (uh, UC_X86_REG_R9, r9);
		uc_reg_write (uh, UC_X86_REG_R10, r10);
		return size;
	}
	return 0;
}

static int r_debug_unicorn_map_protect(RDebug *dbg, ut64 addr, int size, int perms) {
	message ("Unicorn map protect\n");
	return 0;
}

void _interrupt(uc_engine *handle, uint32_t intno, void *user_data) {
	message ("[UNICORN] Interrupt 0x%x userdata %p\n", intno, user_data);
	if (intno == 6) {
		uc_emu_stop (handle);
	}
}

static void _code(uc_engine *handle, uint64_t address, uint32_t size, void *user_data) {
	message ("[UNICORN] Begin Code\n");
	uc_emu_stop (handle);
}

static void _block(uc_engine *handle, uint64_t address, uint32_t size, void *user_data) {
	message ("[UNICORN] Begin Block\n");
}

static void _insn_out(uc_engine *handle, uint32_t port, int size, uint32_t value, void *user_data) {
	message ("[UNICORN] Step Out\n");
	uc_emu_stop (handle);
}

static bool _mem_invalid(uc_engine *handle, uc_mem_type type,
		uint64_t address, int size, int64_t value, void *user_data) {
	const char *typestr = "";
	switch (type) {
	case UC_MEM_READ_AFTER:
			typestr = "read-after";
			break;
	case UC_MEM_READ:
			typestr = "read";
			break;
	case UC_MEM_WRITE:
			typestr = "write";
			break;
	case UC_MEM_FETCH:
			typestr = "fetch";
			break;
	case UC_MEM_READ_UNMAPPED:
			typestr = "unmapped read";
			break;
	case UC_MEM_WRITE_UNMAPPED:
			typestr = "unmapped write";
			break;
	case UC_MEM_FETCH_UNMAPPED:
			typestr = "unmapped fetch";
			break;
	case UC_MEM_WRITE_PROT:
			typestr = "write protected write";
			break;
	case UC_MEM_READ_PROT:
			typestr = "read protected read";
			break;
	case UC_MEM_FETCH_PROT:
			typestr = "non-executable fetch";
			break;
	}
	message ("[UNICORN] Invalid %s of %d bytes at 0x%"PFMT64x"\n",
		typestr, size, address);
	uc_emu_stop (handle);
	return false;
}

static int r_debug_unicorn_step(RDebug *dbg) {
	uc_err err;
	ut64 addr = 0;
	ut64 addr_end = 4;
	static uc_hook uh_interrupt = 0;
	static uc_hook uh_invalid = 0;
	static uc_hook uh_code = 0;
	static uc_hook uh_insn = 0;

	uc_reg_read (uh, UC_X86_REG_RIP, &addr);
	addr_end = addr + 32;

	message ("EMU From 0x%llx To 0x%llx\n", addr, addr_end);
	if (uh_interrupt) {
		uc_hook_del (uh, uh_interrupt);
	}
	if (uh_code) {
		uc_hook_del (uh, uh_code);
	}
	if (uh_insn) {
		uc_hook_del (uh, uh_insn);
	}
	if (uh_invalid) {
		uc_hook_del (uh, uh_invalid);
	}
	uc_hook_add (uh, &uh_interrupt, UC_HOOK_INTR, _interrupt, NULL, 1, 0);
	//uc_hook_add (uh, &uh_code, UC_HOOK_CODE, _code, NULL, addr, addr+1); //(void*)(size_t)1, 0);
	uc_hook_add (uh, &uh_code, UC_HOOK_BLOCK, _block, NULL, 1, 0);
	{
		uint8_t mem[8];
		uc_err err = uc_mem_read (uh, addr, mem, 4);
		message ("[EIP] = %d = %02x %02x %02x %02x\n", err, mem[0], mem[1], mem[2], mem[3]);
	}
	uc_hook_add (uh, &uh_invalid, UC_HOOK_MEM_INVALID, _mem_invalid, NULL, 1, 0);
	uc_hook_add (uh, &uh_insn, UC_HOOK_INSN, _insn_out, NULL, 1, 0, UC_X86_INS_OUT);
	err = uc_emu_start (uh, addr, addr_end, 0, 1);
	message ("[UNICORN] Step Instruction At 0x%08"PFMT64x"\n", addr);
	{
		uint64_t rip;
		uc_reg_read (uh, UC_X86_REG_RIP, &rip);
		message ("NEW PC 0x%08"PFMT64x"\n", rip);
	}
	//err = uc_emu_stop (uh);
	return true;
}

static int r_debug_unicorn_attach(RDebug *dbg, int pid) {
#if 0
	int ret = -1;
	if (pid == dbg->pid)
		return pid;
	dbg->process_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (dbg->process_handle != (HANDLE)NULL && DebugActiveProcess(pid))
		ret = first_thread(pid);
	else
		ret = -1;
	ret = first_thread(pid);
	return ret;
#endif
	//if (!uh) {
		r_debug_unicorn_detach (dbg, pid);
		r_debug_unicorn_init (dbg);
	//}
	return 'U' + 'N' + 'I' + 'C' + 'O' + 'R' + 'N';
}

static int r_debug_unicorn_continue_syscall(RDebug *dbg, int pid, int num) {
	// uc_hook_intr() syscall/sysenter
	// XXX: num is ignored
	message ("TODO: continue syscall not implemented yet\n");
	return -1;
}

static int r_debug_unicorn_continue(RDebug *dbg, int pid, int tid, int sig) {
	return tid;
}

static int r_debug_unicorn_wait(RDebug *dbg, int pid) {
	// no need to wait
	return true;
}

static int r_debug_unicorn_init(RDebug *dbg) {
	int code_is_mapped;
	RIOMap *map;
	int bits = (dbg->bits & R_SYS_BITS_64) ? 64: 32;
	uc_err err;
	if (uh) {
		// run detach to allow reinit
		return true;
	}
	// TODO: add support for ARM, MIPS, ...
	if (!strcmp (dbg->arch, "x86")) {
		err = uc_open (UC_ARCH_X86, bits==64? UC_MODE_64: UC_MODE_32, &uh);
	} else if (!strcmp (dbg->arch, "arm")) {
		err = uc_open (UC_ARCH_ARM, bits==64? UC_MODE_64: UC_MODE_32, &uh);
	} else {
		err = 1;
		message ("[UNICORN] Unsupported architecture\n");
	}
	message ("[UNICORN] Using arch %s bits %d\n", dbg->arch, bits);
	if (err) {
		message ("[UNICORN] Cannot initialize Unicorn engine\n");
		return false;
	}
	ut64 lastvaddr = 0LL;
	size_t n_sect = dbg->iob.io->maps.v.len;
	if (n_sect == 0) {
		message (logo);
		message ("[UNICORN] dpa            # reatach to initialize the unicorn\n");
		message ("[UNICORN] dr rip=entry0  # set program counter to the entrypoint\n");
	}
	code_is_mapped = 0;

	r_vector_foreach (&dbg->iob.io->maps.v, map) {
		int perms = 0;
		if (map->perm & R_PERM_R) perms |= UC_PROT_READ;
		if (map->perm & R_PERM_W) perms |= UC_PROT_WRITE;
		if (map->perm & R_PERM_X) perms |= UC_PROT_EXEC;
		ut64 mapbase = map->itv.addr >> 12 << 12;
		int bufdelta = map->itv.addr - mapbase;
		ut32 vsz = 64 * 1024;
		ut8 *buf;
		if (map->itv.addr < lastvaddr)
			continue;
		if (!(map->perm & 1))
			continue;
		if (!strstr (map->name, "text"))
			continue;
		buf = calloc (vsz+bufdelta+1024, 1);
		if (!buf) continue;
		message ("[UNICORN] BASE 0x%08"PFMT64x"\n", mapbase);
		//message ("DELTA = %d SIZE = %d\n", bufdelta,
			//R_MIN (map->itv.size, (vsz - bufdelta)));
		dbg->iob.read_at (dbg->iob.io, map->itv.addr, buf + bufdelta,
			R_MIN (map->itv.size, (vsz - bufdelta)));
		message ("[UNICORN] Segment 0x%08"PFMT64x" 0x%08"PFMT64x" Size %d\n",
			map->itv.addr, map->itv.addr + vsz, vsz);
		err = uc_mem_map_ptr (uh, mapbase, vsz, perms, buf);
		if (err) {
			message("[UNICORN] muc_mem_map_ptr failed to allocated %d\n", vsz);
		}
		//err = uc_mem_write (uh, map->itv.addr, buf, vsz);
		/*
		err = uc_mem_write (uh, mapbase, buf, vsz);
		if (err) {
			message("[UNICORN] muc_mem_write failed %d\n", err);
		}*/
		//eprintf ("%02x %02x\n", buf[0], buf[1]);
		//eprintf ("WRT = %d\n", err);

		//err = uc_mem_read (uh, mapbase, buf, vsz); //map->itv.size+bufdelta);
		//eprintf ("RAD = %d\n", err);
		lastvaddr = map->itv.addr + map->itv.size;
		code_is_mapped = 1;
		if (JUST_FIRST_BLOCK) break;
//break;
#if 0
		// test
		dbg->iob.read_at (dbg->iob.io, 0x100001058, buf, vsz);
		uc_mem_map (uh, 0x100001058, vsz);
		uc_mem_write (uh, 0x100001058, buf, vsz);
		free (buf);
#endif
	}
	if (!code_is_mapped) {
		message("[UNICORN] No code mapped into the Unicorn. Use `dpa` to attach and transfer\n");
	}

	message ("[UNICORN] Set Program Counter 0x%08"PFMT64x"\n",
		dbg->iob.io->off);
	if (bits == 64) {
		err = uc_reg_write (uh, UC_X86_REG_RIP, &dbg->iob.io->off);
	} else {
		err = uc_reg_write (uh, UC_X86_REG_EIP, &dbg->iob.io->off);
	}
	if (err) {
		message ("[UNICORN] Cannot Set PC\n");
		return false;
	}

	/* stack */
	{
		uc_err err;
		ut32 stacksize = 8 * 4096;
		ut64 stackaddr = 0x7000000;
		message ("[UNICORN] Define 64 KB stack at 0x%08"PFMT64x"\n", stackaddr);
		err = uc_mem_map (uh, stackaddr, stacksize, UC_PROT_WRITE | UC_PROT_READ);
		if (err) {
			eprintf ("Cannot allocate stack %d\n", err);
		}
		if (bits == 64) {
			ut64 rsp = stackaddr + (stacksize/2);
			err = uc_reg_write (uh, UC_X86_REG_RSP, &rsp);
		} else {
			ut32 esp = stackaddr + (stacksize/2);
			err = uc_reg_write (uh, UC_X86_REG_ESP, &esp);
		}
	}
	return true;
}

RDebugPlugin r_debug_plugin_unicorn = {
	.name = "unicorn",
	.license = "GPL",
	.bits = R_SYS_BITS_32 | R_SYS_BITS_64,
	.arch = "x86",
	.canstep = 1,
	.keepio = 1,

	.init = &r_debug_unicorn_init,
	.step = &r_debug_unicorn_step,
	.cont = &r_debug_unicorn_continue,
	.wait = &r_debug_unicorn_wait,
	.contsc = &r_debug_unicorn_continue_syscall,
	.attach = &r_debug_unicorn_attach,
	.detach = &r_debug_unicorn_detach,
	.kill = &r_debug_unicorn_kill,
	//.breakpoint = r_debug_unicorn_bp,
	.breakpoint = NULL,

	.pids = &r_debug_unicorn_pids,
	.tids = &r_debug_unicorn_tids,
	.threads = &r_debug_unicorn_threads,

	.reg_profile = (void *)r_debug_unicorn_reg_profile,
	.reg_read = r_debug_unicorn_reg_read,
	.reg_write = (void *)&r_debug_unicorn_reg_write,
	//.drx = r_debug_unicorn_drx,

	.info = r_debug_unicorn_info,
	.map_get = r_debug_unicorn_map_get,
	.map_alloc = r_debug_unicorn_map_alloc,
	.map_dealloc = r_debug_unicorn_map_dealloc,
	.map_protect = r_debug_unicorn_map_protect,
};

RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_DBG,
	.data = &r_debug_plugin_unicorn,
	.version = R2_VERSION
};
#else
#error Cannot find unicorn library
RDebugPlugin r_debug_plugin_unicorn = {
	.name = "unicorn",
};
#endif // DEBUGGER
