/* radare - LGPL - Copyright 2015 - pancake */

// r2 -e dbg.backend=unicorn -e cfg.debug=1 /bin/ls
// > dr rip=$$
// > ds
// > dr=

#include <r_userconf.h>
#include <r_debug.h>
#include <r_asm.h>
#include <r_reg.h>
#include <r_lib.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/param.h>
#include <unicorn/unicorn.h>

#if HAVE_PKGCFG_UNICORN

static uch uh = 0;

static int r_debug_unicorn_init(RDebug *dbg);

static int r_debug_handle_signals(RDebug *dbg) {
	return -1;
}

static const char *r_debug_unicorn_reg_profile(RDebug *dbg) {
	if (dbg->bits & R_SYS_BITS_64) {
		return strdup (
			"=pc	rip\n"
			"=sp	rsp\n"
			"=bp	rbp\n"
			"=a0	rax\n"
			"=a1	rbx\n"
			"=a2	rcx\n"
			"=a3	rdi\n"
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
			"=pc	eip\n"
			"=sp	esp\n"
			"=bp	ebp\n"
			"=a0	eax\n"
			"=a1	ebx\n"
			"=a2	ecx\n"
			"=a3	edi\n"
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

static RList *r_debug_unicorn_tids(int pid) {
	eprintf ("TODO: Threads: \n");
	return NULL;
}

static RList *r_debug_unicorn_pids(int pid) {
	RList *list = r_list_new();
	r_list_append (list, r_debug_pid_new ("???", pid, 's', 0));
	return list;
}

static RList *r_debug_unicorn_map_get(RDebug *dbg) {
	eprintf ("TODO: unicorn: map-get\n");
	return NULL;
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

static RDebugMap * r_debug_unicorn_map_alloc(RDebug *dbg, ut64 addr, int size) {
	// XXX: segfaults if its not power of 2
	// many overflows may happen
	uc_mem_map (uh, addr, size);
	return NULL;
}

static int r_debug_desc_native_open(const char *path) {
	return 0;
}

static int r_debug_unicorn_map_dealloc(RDebug *dbg, ut64 addr, int size) {
	return 0;
}

static int r_debug_unicorn_kill(RDebug *dbg, int pid, int tid, int sig) {
	// TODO: implement thread support signaling here
	eprintf("TODO: r_debug_unicorn_kill\n");
	return R_FALSE;
}

#if 0
static int r_debug_unicorn_bp(RBreakpointItem *bp, int set, void *user) {
	RDebug *dbg = user;
	if (!bp)
		return R_FALSE;
	if (!bp->hw)
		return R_FALSE;
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
		eprintf ("TODO: unicorn- reg read 0x%"PFMT64x"\n", *rip);
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
			eprintf ("ERROR\n");
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
	eprintf ("Unicorn map protect\n");
	return 0;
}

void _interrupt(uch handle, uint32_t intno, void *user_data) {
	eprintf ("[UNICORN] Interrupt 0x%x userdata %p\n", intno, user_data);
	if (intno == 6) {
		uc_emu_stop (handle);
	}
}

static void _code(uch handle, uint64_t address, uint32_t size, void *user_data) {
	eprintf ("[UNICORN] Begin Code\n");
	uc_emu_stop (handle);
}

static void _block(uch handle, uint64_t address, uint32_t size, void *user_data) {
	eprintf ("[UNICORN] Begin Block\n");
}

static void _insn_out(uch handle, uint32_t port, int size, uint32_t value, void *user_data) {
	eprintf ("[UNICORN] Step Out\n");
	uc_emu_stop (handle);
}

static int r_debug_unicorn_step(RDebug *dbg) {
	uc_err err;
	ut64 addr = 0;
	ut64 addr_end = 4;
	static uch uh_interrupt = 0;
	static uch uh_code = 0;
	static uch uh_insn = 0;

	uc_reg_read (uh, UC_X86_REG_RIP, &addr);
	addr_end = addr + 64;

	eprintf ("EMU From 0x%llx To 0x%llx\n", addr, addr_end);
	if (uh_interrupt) {
		uc_hook_del (uh, &uh_interrupt);
	}
	if (uh_code) {
		uc_hook_del (uh, &uh_code);
	}
	if (uh_insn) {
		uc_hook_del (uh, &uh_insn);
	}
	uc_hook_add (uh, &uh_interrupt, UC_HOOK_INTR, _interrupt, NULL);
	uc_hook_add (uh, &uh_code, UC_HOOK_CODE, _code, NULL, addr, addr+1); //(void*)(size_t)1, 0);
	//uc_hook_add (uh, &uh_code, UC_HOOK_BLOCK, _block, NULL, (void*)(size_t)1, 0);
	uc_hook_add (uh, &uh_insn, UC_HOOK_INSN, _insn_out, NULL, UC_X86_INS_OUT);
	err = uc_emu_start (uh, addr, addr_end, 0, 1);
	eprintf ("[UNICORN] Step Instruction\n");
	return R_TRUE;
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
	if (!uh) {
		r_debug_unicorn_init (dbg);
	}
	return 'U' + 'N' + 'I' + 'C' + 'O' + 'R' + 'N';
}

static int r_debug_unicorn_detach(int pid) {
	uc_close (&uh);
	uh = 0;
	return 0;
}

static int r_debug_unicorn_continue_syscall(RDebug *dbg, int pid, int num) {
	// uc_hook_intr() syscall/sysenter
	// XXX: num is ignored
	eprintf ("TODO: continue syscall not implemented yet\n");
	return -1;
}

static int r_debug_unicorn_continue(RDebug *dbg, int pid, int tid, int sig) {
	return tid;
}

static int r_debug_unicorn_wait(RDebug *dbg, int pid) {
	// no need to wait
	return R_TRUE;
}

static int r_debug_unicorn_init(RDebug *dbg) {
	RListIter *iter;
	RIOSection *sect;
	uc_err err;
	if (uh) {
		// run detach to allow reinit
		return R_TRUE;
	}
	err = uc_open (UC_ARCH_X86,
		(dbg->bits & R_SYS_BITS_64) ? UC_MODE_64: UC_MODE_32,
		&uh);
	eprintf ("[UNICORN] Using arch %s bits %d\n", "x86", dbg->bits*8);
	if (err) {
		eprintf ("[UNICORN] Cannot initialize Unicorn engine\n");
		return R_FALSE;
	}
	ut64 lastvaddr = 0LL;
	r_list_foreach (dbg->iob.io->sections, iter, sect) {
		ut32 vsz = (sect->vsize>>2<<(2+1)) ;
		ut8 *buf = malloc (vsz);
		int i;
		if (!buf) continue;
		if (sect->vaddr < lastvaddr) 
			continue;
		dbg->iob.read_at (dbg->iob.io, sect->vaddr, buf, vsz);
		eprintf ("[UNICORN] Segment 0x%08"PFMT64x" 0x%08"PFMT64x" Size %d\n",
			sect->vaddr, sect->vaddr+vsz, vsz);
		uc_mem_map (uh, sect->vaddr, vsz);
		uc_mem_write (uh, sect->vaddr, buf, vsz);
		lastvaddr = sect->vaddr + sect->vsize;
#if 0
		// test
		dbg->iob.read_at (dbg->iob.io, 0x100001058, buf, vsz);
		uc_mem_map (uh, 0x100001058, vsz);
		uc_mem_write (uh, 0x100001058, buf, vsz);
		free (buf);
#endif
	}

	eprintf ("[UNICORN] Set Program Counter 0x%08"PFMT64x"\n", dbg->iob.io->off);
	if (dbg->bits & R_SYS_BITS_64) {
		err = uc_reg_write (uh, UC_X86_REG_RIP, &dbg->iob.io->off);
	} else {
		err = uc_reg_write (uh, UC_X86_REG_EIP, &dbg->iob.io->off);
	}
	if (err) {
		eprintf ("[UNICORN] Cannot Set PC\n");
		return R_FALSE;
	}
	return R_TRUE;
}

struct r_debug_plugin_t r_debug_plugin_unicorn = {
	.name = "unicorn",
	.license = "GPL",
	.bits = R_SYS_BITS_32 | R_SYS_BITS_64,
	.arch = R_ASM_ARCH_X86, // TODO: Supports more!
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

struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_DBG,
	.data = &r_debug_plugin_unicorn
};
#else
#warning Cannot find unicorn library
struct r_debug_plugin_t r_debug_plugin_unicorn = {
	.name = "unicorn",
};
#endif // DEBUGGER
