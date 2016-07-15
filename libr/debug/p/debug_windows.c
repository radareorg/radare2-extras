/* radare - LGPL - Copyright 2015 - Skuater */

#include <r_userconf.h>
#include <r_debug.h>
#include <r_asm.h>
#include <r_reg.h>
#include <r_lib.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/param.h>
#include "x86/drx.c" // x86 specific
#include "x86/reg.c" // x86 specific
#if __WINDOWS__
#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>

#define MAXBT 128
#define R_DEBUG_REG_T CONTEXT
struct r_debug_desc_plugin_t r_debug_desc_plugin_native_windows;
static int r_debug_native_continue(RDebug *dbg, int pid, int tid, int sig);
static int r_debug_native_reg_read(RDebug *dbg, int type, ut8 *buf, int size);
static int r_debug_native_reg_write(RDebug *dbg, int type, const ut8* buf, int size);

static void (*gmbn) (HANDLE, HMODULE, LPTSTR, int) = NULL;
static int (*gmi) (HANDLE, HMODULE, LPMODULEINFO, int) = NULL;
static BOOL   WINAPI(*w32_detach) (DWORD) = NULL;
static HANDLE WINAPI(*w32_openthread) (DWORD, BOOL, DWORD) = NULL;
static HANDLE WINAPI(*w32_dbgbreak) (HANDLE) = NULL;
static DWORD  WINAPI(*w32_getthreadid) (HANDLE) = NULL; // Vista
static DWORD  WINAPI(*w32_getprocessid) (HANDLE) = NULL; // XP
static HANDLE WINAPI(*w32_openprocess) (DWORD, BOOL, DWORD) = NULL;
inline static int w32_h2t(HANDLE h) {
	if (w32_getthreadid != NULL) // >= Windows Vista
		return w32_getthreadid (h);
	if (w32_getprocessid != NULL) // >= Windows XP1
		return w32_getprocessid (h);
	return (int)(size_t)h; // XXX broken
}
static inline int CheckValidPE(unsigned char * PeHeader) {
	IMAGE_DOS_HEADER *dos_header = (IMAGE_DOS_HEADER *)PeHeader;
	IMAGE_NT_HEADERS *nt_headers;

	if (dos_header->e_magic==IMAGE_DOS_SIGNATURE) {
		nt_headers = (IMAGE_NT_HEADERS *)((char *)dos_header
				+ dos_header->e_lfanew);
		if (nt_headers->Signature==IMAGE_NT_SIGNATURE)
			return 1;
	}
	return 0;
}
static void r_str_wtoc(char* d, const WCHAR* s) {
	int i = 0;
	while (s[i] != '\0') {
		d[i] = (char)s[i];
		++i;
	}
	d[i] = 0;
}
static void print_lasterr(const char *str) {
	/* code from MSDN, :? */
	LPWSTR pMessage = L"%1!*.*s! %4 %5!*s!";
	DWORD_PTR pArgs[] = { (DWORD_PTR)4, (DWORD_PTR)2, (DWORD_PTR)L"Bill",  // %1!*.*s!
		(DWORD_PTR)L"Bob",                                                // %4
		(DWORD_PTR)6, (DWORD_PTR)L"Bill" };                               // %5!*s!
	WCHAR buffer[200];
	char cbuffer[100];
	if (!FormatMessage (FORMAT_MESSAGE_FROM_STRING |
				FORMAT_MESSAGE_ARGUMENT_ARRAY,
				pMessage,
				0,  // ignored
				0,  // ignored
				(LPTSTR)&buffer,
				sizeof (buffer)-1,
				(va_list*)pArgs)) {
		eprintf ("(%s): Format message failed with 0x%x\n",
				r_str_get (str), (ut32)GetLastError ());
		return;
	}
	r_str_wtoc (cbuffer, buffer);
	eprintf ("print_lasterr: %s ::: %s\n", r_str_get (str), r_str_get (cbuffer));
}
static HANDLE tid2handler(int pid, int tid) {
	HANDLE th = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, pid);
	THREADENTRY32 te32 = { .dwSize = sizeof(THREADENTRY32) };
	int ret = -1;
	if (th == INVALID_HANDLE_VALUE)
		return NULL;
	if (!Thread32First(th, &te32)) {
		CloseHandle(th);
		return NULL;
	}
	do {
		if (te32.th32OwnerProcessID == pid && te32.th32ThreadID == tid) {
			CloseHandle(th);
			return w32_openthread(THREAD_ALL_ACCESS, 0,
					te32.th32ThreadID);
		}
		ret++;
	} while (Thread32Next(th, &te32));
	if (ret == -1)
		print_lasterr((char *)__FUNCTION__);
	CloseHandle(th);
	return NULL;
}
static int first_thread(int pid) {
	HANDLE th;
	HANDLE thid;
	THREADENTRY32 te32;
	int ret = -1;

	te32.dwSize = sizeof(THREADENTRY32);

	if (w32_openthread == NULL) {
		eprintf("w32_thread_list: no w32_openthread?\n");
		return -1;
	}
	th = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, pid);
	if (th == INVALID_HANDLE_VALUE) {
		eprintf("w32_thread_list: invalid handle\n");
		return -1;
	}
	if (!Thread32First(th, &te32)) {
		CloseHandle(th);
		eprintf("w32_thread_list: no thread first\n");
		return -1;
	}
	do {
		/* get all threads of process */
		if (te32.th32OwnerProcessID == pid) {
			thid = w32_openthread(THREAD_ALL_ACCESS, 0, te32.th32ThreadID);
			if (thid == NULL)
				goto err_load_th;
			CloseHandle(th);
			return te32.th32ThreadID;
		}
	} while (Thread32Next(th, &te32));
err_load_th:
	if (ret == -1)
		print_lasterr((char *)__FUNCTION__);
	eprintf("w32thread: Oops\n");
	return pid; // -1 ?
}

static int r_debug_handle_signals(RDebug *dbg) {
	return -1;
}

static RList *r_debug_native_threads(RDebug *dbg, int pid) {
	RList *list = r_list_new();
	if (list == NULL) {
		eprintf("No list?\n");
		return NULL;
	}
	HANDLE th;
	HANDLE thid;
	THREADENTRY32 te32;
	int ret;

	ret = -1;
	te32.dwSize = sizeof(THREADENTRY32);

	if (w32_openthread == NULL) {
		eprintf("w32_thread_list: no w32_openthread?\n");
		return list;
	}
	th = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, pid);
	if (th == INVALID_HANDLE_VALUE || !Thread32First(th, &te32))
		goto err_load_th;
	do {
		/* get all threads of process */
		if (te32.th32OwnerProcessID == pid) {
			//te32.dwFlags);
			/* open a new handler */
			// XXX: fd leak?
#if 0
			75 typedef struct tagTHREADENTRY32 {
				76         DWORD dwSize;
				77         DWORD cntUsage;
				78         DWORD th32ThreadID;
				79         DWORD th32OwnerProcessID;
				80         LONG tpBasePri;
				81         LONG tpDeltaPri;
				82         DWORD dwFlags;
#endif
				thid = w32_openthread(THREAD_ALL_ACCESS, 0, te32.th32ThreadID);
				if (thid == NULL)
					goto err_load_th;
				ret = te32.th32ThreadID;
				//eprintf("Thread: %x %x\n", thid, te32.th32ThreadID);
				r_list_append(list, r_debug_pid_new("???", te32.th32ThreadID, 's', 0));
			}
		} while (Thread32Next(th, &te32));
err_load_th:
		if (ret == -1)
			print_lasterr((char *)__FUNCTION__);
		if (th != INVALID_HANDLE_VALUE)
			CloseHandle(th);
		return list;
	}
static RList *r_debug_native_tids(int pid) {
	printf("TODO: Threads: \n");
	// T
	return NULL;
}
static RList *r_debug_native_pids(int pid) {
	RList *list = r_list_new();
	HANDLE th;
	THREADENTRY32 te32;
	int ret = -1;
	te32.dwSize = sizeof(THREADENTRY32);
	if (w32_openthread == NULL) {
		eprintf("w32_thread_list: no w32_openthread?\n");
		return list;
	}
	th = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, pid);
	if (th == INVALID_HANDLE_VALUE || !Thread32First(th, &te32))
		goto err_load_th;
	do {
		if (ret != te32.th32OwnerProcessID)
			r_list_append(list, r_debug_pid_new("???", te32.th32OwnerProcessID, 's', 0));
		ret = te32.th32OwnerProcessID;
	} while (Thread32Next(th, &te32));
err_load_th:
	if (ret == -1)
		print_lasterr((char *)__FUNCTION__);
	if (th != INVALID_HANDLE_VALUE)
		CloseHandle(th);
	return list;
}
static RList *r_debug_native_map_get(RDebug *dbg) {
	HANDLE hProcess = 0;
	HANDLE hModuleSnap = 0;
	IMAGE_DOS_HEADER *dos_header;
	IMAGE_NT_HEADERS *nt_headers;
	IMAGE_SECTION_HEADER *SectionHeader;
	SIZE_T ret_len;
	MODULEENTRY32 me32;
	RDebugMap *mr;
	ut8 PeHeader[1024];
	char *mapname = NULL;
	int NumSections, i;
	int pid = dbg->pid;
	RList *list = r_list_new();

	hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
	if (hModuleSnap == NULL) {
		//print_lasterr ((char *)__FUNCTION__);
		CloseHandle(hModuleSnap);
		return NULL;
	}
	me32.dwSize = sizeof(MODULEENTRY32);
	if (!Module32First(hModuleSnap, &me32))	{
		//print_lasterr ((char *)__FUNCTION__);
		CloseHandle(hModuleSnap);
		return NULL;
	}
	hProcess = w32_openprocess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
	do {
		ReadProcessMemory((hProcess), (const void *)me32.modBaseAddr, (LPVOID)PeHeader, sizeof(PeHeader), &ret_len);
		if (ret_len == sizeof(PeHeader) && CheckValidPE(PeHeader)) {
			dos_header = (IMAGE_DOS_HEADER *)PeHeader;
			if (dos_header != NULL) {
				nt_headers = (IMAGE_NT_HEADERS *)((char *)dos_header + dos_header->e_lfanew);
				if (nt_headers != NULL) {
					NumSections = nt_headers->FileHeader.NumberOfSections;
					SectionHeader = (IMAGE_SECTION_HEADER *)((char *)nt_headers + sizeof(IMAGE_NT_HEADERS));
					mr = r_debug_map_new(me32.szModule,
							(ut64)(size_t)(me32.modBaseAddr),
							(ut64)(size_t)(me32.modBaseAddr + SectionHeader->VirtualAddress),
							SectionHeader->Characteristics,
							0);
					if (mr != NULL)
						r_list_append(list, mr);
					if (NumSections > 0) {
						mapname = (char *)malloc(MAX_PATH);
						for (i = 0; i < NumSections; i++) {
							if (SectionHeader->Misc.VirtualSize > 0) {
								sprintf(mapname, "%s | %s", me32.szModule, SectionHeader->Name);
								mr = r_debug_map_new(mapname,
										(ut64)(size_t)(SectionHeader->VirtualAddress + me32.modBaseAddr),
										(ut64)(size_t)(SectionHeader->VirtualAddress + me32.modBaseAddr + SectionHeader->Misc.VirtualSize),
										SectionHeader->Characteristics, // XXX?
										0);
								if (mr != NULL)
									r_list_append(list, mr);
							}
							SectionHeader++;
						}
						free(mapname);
					}
				}
			}
		}
	} while (Module32Next(hModuleSnap, &me32));
	CloseHandle(hModuleSnap);
	CloseHandle(hProcess);
	return(list);
}
static RList *r_debug_native_frames_x86_64(RDebug *dbg, ut64 at) {
	int i;
	ut8 buf[8];
	RDebugFrame *frame;
	ut64 ptr, ebp2;
	ut64 _rip, _rsp, _rbp;
	RList *list;
	RReg *reg = dbg->reg;
	RIOBind *bio = &dbg->iob;
	_rip = r_reg_get_value(reg, r_reg_get(reg, "rip", R_REG_TYPE_GPR));
	if (at == UT64_MAX) {
		_rsp = r_reg_get_value(reg, r_reg_get(reg, "rsp", R_REG_TYPE_GPR));
		_rbp = r_reg_get_value(reg, r_reg_get(reg, "rbp", R_REG_TYPE_GPR));
	}
	else {
		_rsp = _rbp = at;
	}

	list = r_list_new();
	list->free = free;
	bio->read_at(bio->io, _rip, (ut8*)&buf, 8);
	/* %rbp=old rbp, %rbp+4 points to ret */
	/* Plugin before function prelude: push %rbp ; mov %rsp, %rbp */
	if (!memcmp(buf, "\x55\x89\xe5", 3) || !memcmp(buf, "\x89\xe5\x57", 3)) {
		if (bio->read_at(bio->io, _rsp, (ut8*)&ptr, 8) != 8) {
			eprintf("read error at 0x%08"PFMT64x"\n", _rsp);
			r_list_purge(list);
			free(list);
			return false;
		}
		RDebugFrame *frame = R_NEW(RDebugFrame);
		frame->addr = ptr;
		frame->size = 0; // TODO ?
		r_list_append(list, frame);
		_rbp = ptr;
	}

	for (i = 1; i<MAXBT; i++) {
		// TODO: make those two reads in a shot
		bio->read_at(bio->io, _rbp, (ut8*)&ebp2, 8);
		if (ebp2 == UT64_MAX)
			break;
		bio->read_at(bio->io, _rbp + 8, (ut8*)&ptr, 8);
		if (!ptr || !_rbp)
			break;
		frame = R_NEW(RDebugFrame);
		frame->addr = ptr;
		frame->size = 0; // TODO ?
		r_list_append(list, frame);
		_rbp = ebp2;
	}
	return list;
}
static RList *r_debug_native_frames_x86_32(RDebug *dbg, ut64 at) {
	RRegItem *ri;
	RReg *reg = dbg->reg;
	ut32 i, _esp, esp, ebp2;
	RList *list = r_list_new();
	RIOBind *bio = &dbg->iob;
	ut8 buf[4];
	list->free = free;
	ri = (at == UT64_MAX) ? r_reg_get(reg, "ebp", R_REG_TYPE_GPR) : NULL;
	_esp = (ut32)((ri) ? r_reg_get_value(reg, ri) : at);
	// TODO: implement [stack] map uptrace method too
	esp = _esp;
	for (i = 0; i<MAXBT; i++) {
		bio->read_at(bio->io, esp, (void *)&ebp2, 4);
		if (ebp2 == UT32_MAX)
			break;
		*buf = '\0';
		bio->read_at(bio->io, (ebp2 - 5) - (ebp2 - 5) % 4, (void *)&buf, 4);

		// TODO: arch_is_call() here and this fun will be portable
		if (buf[(ebp2 - 5) % 4] == 0xe8) {
			RDebugFrame *frame = R_NEW(RDebugFrame);
			frame->addr = ebp2;
			frame->size = esp - _esp;
			r_list_append(list, frame);
		}
		esp += 4;
	}
	return list;
}
static RList *r_debug_native_frames(RDebug *dbg, ut64 at) {
	if (dbg->bits == R_SYS_BITS_64)
		return r_debug_native_frames_x86_64(dbg, at);
	return r_debug_native_frames_x86_32(dbg, at);
}
static RList *r_debug_desc_native_list(int pid) {
	RList *ret = NULL;
	// TODO: windows
	return ret;
}

static RDebugInfo* r_debug_native_info(RDebug *dbg, const char *arg) {
	RDebugInfo *rdi = R_NEW0(RDebugInfo);
	rdi->status = R_DBG_PROC_SLEEP; // TODO: Fix this
	rdi->pid = dbg->pid;
	rdi->tid = dbg->tid;
	rdi->uid = -1;// TODO
	rdi->gid = -1;// TODO
	rdi->cwd = NULL;// TODO : use readlink
	rdi->exe = NULL;// TODO : use readlink!
	//snprintf(procpid_cmdline, sizeof(procpid_cmdline), "/proc/%d/cmdline", rdi->pid);
	//rdi->cmdline = r_file_slurp(procpid_cmdline, NULL);
	return rdi;
}
static RDebugMap * r_debug_native_map_alloc(RDebug *dbg, ut64 addr, int size) {
	RDebugMap *map = NULL;
	LPVOID base = NULL;
	if (!dbg->process_handle) {
		dbg->process_handle = tid2handler(dbg->pid, dbg->tid);
	}
	base = VirtualAllocEx(dbg->process_handle, (LPVOID)(size_t)addr,
			(SIZE_T)size, MEM_COMMIT, PAGE_READWRITE);
	if (!base) {
		eprintf("Failed to allocate memory\n");
		return map;
	}
	r_debug_map_sync(dbg);
	map = r_debug_map_get(dbg, (ut64)(size_t)base);
	return map;
}


static int r_debug_desc_native_open(const char *path) {
	return 0;
}
static int r_debug_native_map_dealloc(RDebug *dbg, ut64 addr, int size) {
	if (!dbg->process_handle) {
		dbg->process_handle = tid2handler(dbg->pid, dbg->tid);
	}
	if (!VirtualFreeEx (dbg->process_handle, (LPVOID)(size_t)addr, (SIZE_T)size, MEM_DECOMMIT)) {
		eprintf("Failed to free memory\n");
		return false;
	}
	return true;
}
static int r_debug_native_kill(RDebug *dbg, int pid, int tid, int sig) {
	// TODO: implement thread support signaling here
	eprintf("TODO: r_debug_native_kill\n");
	return false;
}
static int r_debug_native_drx(RDebug *dbg, int n, ut64 addr, int sz, int rwx, int g) {
	drxt regs[8] = { 0 };
	// sync drx regs
#define R dbg->reg
	regs[0] = r_reg_getv(R, "dr0");
	regs[1] = r_reg_getv(R, "dr1");
	regs[2] = r_reg_getv(R, "dr2");
	regs[3] = r_reg_getv(R, "dr3");
	/*
	   RESERVED
	   regs[4] = r_reg_getv (R, "dr4");
	   regs[5] = r_reg_getv (R, "dr5");
	 */
	regs[6] = r_reg_getv(R, "dr6");
	regs[7] = r_reg_getv(R, "dr7");
	if (sz == 0) {
		w32_drx_list((drxt*)&regs);
		return false;
	}
	if (sz<0) { // remove
		w32_drx_set(regs, n, addr, -1, 0, 0);
	} else {
		w32_drx_set(regs, n, addr, sz, rwx, g);
	}
	r_reg_setv(R, "dr0", regs[0]);
	r_reg_setv(R, "dr1", regs[1]);
	r_reg_setv(R, "dr2", regs[2]);
	r_reg_setv(R, "dr3", regs[3]);
	r_reg_setv(R, "dr6", regs[6]);
	r_reg_setv(R, "dr7", regs[7]);
	return true;
}
static int drx_add(RDebug *dbg, ut64 addr, int rwx) {
        // TODO
	return false;
}
static int drx_del(RDebug *dbg, ut64 addr, int rwx) {
        // TODO
        return false;
}

static int r_debug_native_bp(RBreakpointItem *bp, int set, void *user) {
	RDebug *dbg = user;
	if (!bp)
		return false;
	if (!bp->hw)
		return false;
	return set?drx_add(dbg, bp->addr, bp->rwx) :drx_del(dbg, bp->addr, bp->rwx);
}
static int r_debug_native_reg_read(RDebug *dbg, int type, ut8 *buf, int size) {
	eprintf("Estro es de nuestro debugger\n");
	int showfpu = false;
	int pid = dbg->pid;
	if (size<1)
		return false;
	if (type<-1) {
		showfpu = true; // hack for debugging
		type = -type;
	}
	int tid = dbg->tid;
	HANDLE hProcess = tid2handler(pid, tid);
	CONTEXT ctx __attribute__((aligned(16)));
	ctx.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;
	if (!GetThreadContext(hProcess, &ctx)) {
		eprintf("GetThreadContext: %x\n", (int)GetLastError());
		CloseHandle(hProcess);
		return false;
	}
	CloseHandle(hProcess);
	if (type == R_REG_TYPE_FPU || type == R_REG_TYPE_MMX || type == R_REG_TYPE_XMM) {
#if __MINGW64__
		eprintf("TODO: r_debug_native_reg_read fpu/mmx/xmm\n");
#else
		int i;
		if (showfpu) {
			eprintf("cwd = 0x%08x  ; control   ", (ut32)ctx.FloatSave.ControlWord);
			eprintf("swd = 0x%08x  ; status\n", (ut32)ctx.FloatSave.StatusWord);
			eprintf("twd = 0x%08x ", (ut32)ctx.FloatSave.TagWord);
			eprintf("eof = 0x%08x\n", (ut32)ctx.FloatSave.ErrorOffset);
			eprintf("ese = 0x%08x\n", (ut32)ctx.FloatSave.ErrorSelector);
			eprintf("dof = 0x%08x\n", (ut32)ctx.FloatSave.DataOffset);
			eprintf("dse = 0x%08x\n", (ut32)ctx.FloatSave.DataSelector);
			eprintf("mxcr = 0x%08x\n", (ut32)ctx.ExtendedRegisters[24]);
			for (i = 0; i<8; i++) {
				ut32 *a = (ut32*)&(ctx.ExtendedRegisters[10 * 16]);
				a = a + (i * 4);
				eprintf("xmm%d = %08x %08x %08x %08x  ", i, (int)a[0], (int)a[1], (int)a[2], (int)a[3]);
				ut64 *b = (ut64 *)&ctx.FloatSave.RegisterArea[i * 10];
				eprintf("st%d = %lg (0x%08"PFMT64x")\n", i, (double)*((double*)&ctx.FloatSave.RegisterArea[i * 10]), *b);
			}
		}
#endif
	}
	if (sizeof(CONTEXT) < size)
		size = sizeof(CONTEXT);

	memcpy(buf, &ctx, size);
	return size;
	// XXX this must be defined somewhere else
}

static int r_debug_native_reg_write(RDebug *dbg, int type, const ut8* buf, int size) {
	// XXX use switch or so
	if (type == R_REG_TYPE_DRX)
	{
		int tid = dbg->tid;
		int pid = dbg->pid;
		BOOL ret;
		HANDLE hProcess;
		CONTEXT ctx __attribute__((aligned(16)));
		memcpy(&ctx, buf, sizeof(CONTEXT));
		ctx.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;
		hProcess = tid2handler(pid, tid);
		ret = SetThreadContext(hProcess, &ctx) ? true : false;
		CloseHandle(hProcess);
		return ret;
	}
	else if (type == R_REG_TYPE_GPR)
	{
		int pid = dbg->pid;
		int tid = dbg->tid;
		BOOL ret;
		HANDLE hProcess;
		CONTEXT ctx __attribute__((aligned(16)));
		memcpy(&ctx, buf, sizeof(CONTEXT));
		ctx.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;
		//	eprintf ("EFLAGS =%x\n", ctx.EFlags);
		hProcess = tid2handler(pid, tid);
		ret = SetThreadContext(hProcess, &ctx) ? true : false;
		CloseHandle(hProcess);
		return ret;
	}
	else
		eprintf("TODO: reg_write_non-gpr (%d)\n", type);
	return false;
}
static int r_debug_native_map_protect(RDebug *dbg, ut64 addr, int size, int perms) {
	DWORD old;
	if (!dbg->process_handle) {
		dbg->process_handle = tid2handler(dbg->pid, dbg->tid);
	}
	// TODO: align pointers
	return VirtualProtectEx((dbg->process_handle), (LPVOID)(UINT)addr, size, perms, &old);
}
static int r_debug_native_step(RDebug *dbg) {
	int pid = dbg->pid;
	/* set TRAP flag */
	CONTEXT regs __attribute__((aligned(16)));
	r_debug_native_reg_read (dbg, R_REG_TYPE_GPR, (ut8 *)&regs, sizeof(regs));
	regs.EFlags |= 0x100;
	r_debug_native_reg_write (dbg, R_REG_TYPE_GPR, (ut8 *)&regs, sizeof(regs));
	r_debug_native_continue (dbg, pid, dbg->tid, dbg->signum);
	return true;
}
static int r_debug_native_attach(RDebug *dbg, int pid) {
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

}
static int r_debug_native_detach(int pid) {

	return w32_detach(pid) ? 0 : -1;

}
static int r_debug_native_continue_syscall(RDebug *dbg, int pid, int num) {
	// XXX: num is ignored
	eprintf("TODO: continue syscall not implemented yet\n");
	return -1;
}
static int r_debug_native_continue(RDebug *dbg, int pid, int tid, int sig) {
	if (ContinueDebugEvent(pid, tid, DBG_CONTINUE) == 0) {
		print_lasterr((char *)__FUNCTION__);
		eprintf("debug_contp: error\n");
		return false;
	}
	return tid;
}
static int FirstBreakPoint = true;
static int r_debug_native_wait(RDebug *dbg, int pid) {
	DEBUG_EVENT DBGEvent;
	DWORD DBGCode;
	BOOL BreakDBG = FALSE;
	int tid;
	unsigned int code;
	int ret = R_DBG_REASON_UNKNOWN;

	while (!BreakDBG)
	{
		if (WaitForDebugEvent(&DBGEvent, INFINITE) == 0) {
			print_lasterr((char *)__FUNCTION__);
			return -1;
		}
		tid = DBGEvent.dwThreadId;
		code = DBGEvent.dwDebugEventCode;
		if (DBGEvent.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT)
		{
			DBGCode = DBG_CONTINUE;
			eprintf("(%d) created process (%d:%p)\n", pid, w32_h2t(DBGEvent.u.CreateProcessInfo.hProcess), DBGEvent.u.CreateProcessInfo.lpStartAddress);
			ret = R_DBG_REASON_NEW_PID;
		}
		else if (DBGEvent.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT)
		{
			eprintf("\n\n______________[ process finished ]_______________\n\n");
			//debug_load();
			ret = R_DBG_REASON_EXIT_PID;
			DBGCode = DBG_CONTINUE;
			BreakDBG = TRUE;
		}
		else if (DBGEvent.dwDebugEventCode == CREATE_THREAD_DEBUG_EVENT)
		{
			eprintf("(%d) created thread (%p)\n", pid, DBGEvent.u.CreateThread.lpStartAddress);
			ret = R_DBG_REASON_NEW_TID;
			DBGCode = DBG_CONTINUE;
		}
		else if (DBGEvent.dwDebugEventCode == EXIT_THREAD_DEBUG_EVENT)
		{
			eprintf("EXIT_THREAD\n");
			ret = R_DBG_REASON_EXIT_TID;
			DBGCode = DBG_CONTINUE;
		}
		else if (DBGEvent.dwDebugEventCode == LOAD_DLL_DEBUG_EVENT)
		{
			eprintf("(%d) Loading %s library at %p\n", pid, "", DBGEvent.u.LoadDll.lpBaseOfDll);
			ret = R_DBG_REASON_NEW_LIB;
			DBGCode = DBG_CONTINUE;
		}
		else if (DBGEvent.dwDebugEventCode == UNLOAD_DLL_DEBUG_EVENT)
		{
			eprintf("UNLOAD_DLL\n");
			DBGCode = DBG_CONTINUE;
		}
		else if (DBGEvent.dwDebugEventCode == OUTPUT_DEBUG_STRING_EVENT)
		{
			eprintf("OUTPUT_DEBUG_STRING\n");
			DBGCode = DBG_CONTINUE;
		}
		else if (DBGEvent.dwDebugEventCode == EXCEPTION_DEBUG_EVENT)
		{

			if (DBGEvent.u.Exception.dwFirstChance == FALSE)
			{
				DBGCode = DBG_EXCEPTION_NOT_HANDLED;
			}
			if (DBGEvent.u.Exception.ExceptionRecord.ExceptionCode == STATUS_BREAKPOINT)
			{
				DBGCode = DBG_CONTINUE;
				if (FirstBreakPoint)
				{
					FirstBreakPoint = false;
				}
				else
					return R_DBG_REASON_TRAP;
			}
			else if (DBGEvent.u.Exception.ExceptionRecord.ExceptionCode == STATUS_SINGLE_STEP)
			{
				DBGCode = DBG_CONTINUE;
				return R_DBG_REASON_TRAP;
			}
			else if (DBGEvent.u.Exception.ExceptionRecord.ExceptionCode == STATUS_GUARD_PAGE_VIOLATION)
			{
				DBGCode = DBG_EXCEPTION_NOT_HANDLED;

			}
			else if (DBGEvent.u.Exception.ExceptionRecord.ExceptionCode == STATUS_ILLEGAL_INSTRUCTION)
			{
				DBGCode = DBG_EXCEPTION_NOT_HANDLED;
			}
			else if (DBGEvent.u.Exception.ExceptionRecord.ExceptionCode == STATUS_NONCONTINUABLE_EXCEPTION)
			{
				DBGCode = DBG_EXCEPTION_NOT_HANDLED;
			}
			else if (DBGEvent.u.Exception.ExceptionRecord.ExceptionCode == STATUS_ACCESS_VIOLATION)
			{
				DBGCode = DBG_EXCEPTION_NOT_HANDLED;
			}
			else if (DBGEvent.u.Exception.ExceptionRecord.ExceptionCode == STATUS_ARRAY_BOUNDS_EXCEEDED)
			{
				DBGCode = DBG_EXCEPTION_NOT_HANDLED;
			}
			else if (DBGEvent.u.Exception.ExceptionRecord.ExceptionCode == STATUS_FLOAT_DENORMAL_OPERAND)
			{
				DBGCode = DBG_EXCEPTION_NOT_HANDLED;
			}
			else if (DBGEvent.u.Exception.ExceptionRecord.ExceptionCode == STATUS_FLOAT_DIVIDE_BY_ZERO)
			{
				DBGCode = DBG_EXCEPTION_NOT_HANDLED;
			}
			else if (DBGEvent.u.Exception.ExceptionRecord.ExceptionCode == STATUS_INTEGER_DIVIDE_BY_ZERO)
			{
				DBGCode = DBG_EXCEPTION_NOT_HANDLED;
			}
			else if (DBGEvent.u.Exception.ExceptionRecord.ExceptionCode == STATUS_INTEGER_OVERFLOW)
			{
				DBGCode = DBG_EXCEPTION_NOT_HANDLED;
			}
			else if (DBGEvent.u.Exception.ExceptionRecord.ExceptionCode == STATUS_PRIVILEGED_INSTRUCTION)
			{
				DBGCode = DBG_EXCEPTION_NOT_HANDLED;
			}
#if __MINGW64__
			else if (DBGEvent.u.Exception.ExceptionRecord.ExceptionCode == 0x4000001f) { //STATUS_WX86_BREAKPOINT
				eprintf("WOW64 Loaded.\n");
				DBGCode = DBG_CONTINUE;
			}
#endif
			else {
				eprintf("unknown exception\n");
				DBGCode = DBG_CONTINUE;
			}
		}
		if (!ContinueDebugEvent(DBGEvent.dwProcessId, DBGEvent.dwThreadId, DBGCode))
		{

		}
	}

	return ret;
}

static int r_debug_native_init(RDebug *dbg) {
	dbg->h->desc = r_debug_desc_plugin_native_windows;
	HANDLE lib;

	/* escalate privs (required for win7/vista) */
	int ret = true;
	TOKEN_PRIVILEGES tokenPriv;
	HANDLE hToken = NULL;
	LUID luidDebug;
	if (!OpenProcessToken(GetCurrentProcess(),
				TOKEN_ADJUST_PRIVILEGES, &hToken)) {
		return false;
	}

	if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luidDebug)) {
		CloseHandle(hToken);
		return false;
	}

	tokenPriv.PrivilegeCount = 1;
	tokenPriv.Privileges[0].Luid = luidDebug;
	tokenPriv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	if (AdjustTokenPrivileges(hToken, FALSE, &tokenPriv, 0, NULL, NULL) != FALSE) {
		if (tokenPriv.Privileges[0].Attributes == SE_PRIVILEGE_ENABLED) {
			//	eprintf ("PRIV ENABLED\n");
		}
		// Always successful, even in the cases which lead to OpenProcess failure
		//	eprintf ("Successfully changed token privileges.\n");
		// XXX if we cant get the token nobody tells?? wtf
	} else {
		eprintf("Failed to change token privileges 0x%x\n", (int)GetLastError());
		ret = false;
	}
	CloseHandle(hToken);

	/* lookup function pointers for portability */
	w32_detach = (BOOL WINAPI(*)(DWORD))GetProcAddress(GetModuleHandle("kernel32"), "DebugActiveProcessStop");
	w32_openthread = (HANDLE WINAPI(*)(DWORD, BOOL, DWORD))GetProcAddress(GetModuleHandle("kernel32"), "OpenThread");
	w32_openprocess = (HANDLE WINAPI(*)(DWORD, BOOL, DWORD))GetProcAddress(GetModuleHandle("kernel32"), "OpenProcess");
	w32_dbgbreak = (HANDLE WINAPI(*)(HANDLE))GetProcAddress(GetModuleHandle("kernel32"), "DebugBreakProcess");
	// only windows vista :(
	w32_getthreadid = (DWORD WINAPI(*)(HANDLE))GetProcAddress(GetModuleHandle("kernel32"), "GetThreadId");
	// from xp1
	w32_getprocessid = (DWORD WINAPI(*)(HANDLE))GetProcAddress(GetModuleHandle("kernel32"), "GetProcessId");

	lib = LoadLibrary("psapi.dll");
	if (lib == NULL) {
		eprintf("Cannot load psapi.dll!!\n");
		return false;
	}
	gmbn = (void(*)(HANDLE, HMODULE, LPTSTR, int))
		GetProcAddress(lib, "GetModuleBaseNameA");
	gmi = (int(*)(HANDLE, HMODULE, LPMODULEINFO, int))
		GetProcAddress(lib, "GetModuleInformation");
	if (w32_detach == NULL || w32_openthread == NULL || w32_dbgbreak == NULL ||
			gmbn == NULL || gmi == NULL) {
		// OOPS!
		eprintf("debug_init_calls:\n"
			"DebugActiveProcessStop: 0x%p\n"
			"OpenThread: 0x%p\n"
			"DebugBreakProcess: 0x%p\n"
			"GetThreadId: 0x%p\n",
			w32_detach, w32_openthread, w32_dbgbreak, w32_getthreadid);
		return false;
	}
	return true;
}

struct r_debug_desc_plugin_t r_debug_desc_plugin_native_windows = {
	.open = r_debug_desc_native_open,
	.list = r_debug_desc_native_list,
};

struct r_debug_plugin_t r_debug_plugin_native_windows = {
	.name = "nativewindows",
	.license = "AnarchyFree",
#if __i386__
	.bits = R_SYS_BITS_32,
	.arch = R_ASM_ARCH_X86,
	.canstep = 1,
#elif __x86_64__
	.bits = R_SYS_BITS_32 | R_SYS_BITS_64,
	.arch = R_ASM_ARCH_X86,
	.canstep = 1,
#endif
	.init = &r_debug_native_init,
	.step = &r_debug_native_step,
	.cont = &r_debug_native_continue,
	.wait = &r_debug_native_wait,
	.contsc = &r_debug_native_continue_syscall,
	.attach = &r_debug_native_attach,
	.detach = &r_debug_native_detach,
	.kill = &r_debug_native_kill,
	.breakpoint = r_debug_native_bp,

	.frames = &r_debug_native_frames, // rename to backtrace ?
	.pids = &r_debug_native_pids,
	.tids = &r_debug_native_tids,
	.threads = &r_debug_native_threads,

	.reg_profile = (void *)r_debug_native_reg_profile,
	.reg_read = r_debug_native_reg_read,
	.reg_write = (void *)&r_debug_native_reg_write,
	.drx = r_debug_native_drx,

	.info = r_debug_native_info,
	.map_get = r_debug_native_map_get,
	.map_alloc = r_debug_native_map_alloc,
	.map_dealloc = r_debug_native_map_dealloc,
	.map_protect = r_debug_native_map_protect,
};

struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_DBG,
	.data = &r_debug_plugin_native_windows
};
#else
struct r_debug_plugin_t r_debug_plugin_native_windows = {
	.name = "nativewindows",
};
#endif // DEBUGGER
