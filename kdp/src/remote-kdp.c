/* Remote debugging interface for NeXT / Mac OS X via KDP, for GDB.
   Copyright 1997  Free Software Foundation, Inc.
   Written by Klee Dienes.  Contributed by Apple Computer, Inc.

This file is part of GDB.

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.  */

//#include "ppc-reg.h"

//#include "defs.h"
//#include "inferior.h"
//#include "gdbcmd.h"

#include "target.h"
#include "defs.h"
#include "event-top.h"
#include "event-loop.h"
//#include "inf-loop.h"

#include <stdio.h>
#include <string.h>
#include <signal.h>
#include "kdp-udp.h"
#include "kdp-transactions.h"

#if TARGET_I386
#define KDP_TARGET_I386 1
#else
#undef KDP_TARGET_I386
#endif

#if TARGET_POWERPC
#define KDP_TARGET_POWERPC 1
#else
#undef KDP_TARGET_POWERPC
#endif

#if KDP_TARGET_POWERPC
#include "ppc-thread-status.h"
#include "ppc-next-tdep.h"
#endif

#if KDP_TARGET_I386
#include "i386-thread-status.h"
#include "i386-next-tdep.h"
#endif

#ifndef CPU_TYPE_I386
#define CPU_TYPE_I386 (7)
#endif

#ifndef CPU_TYPE_POWERPC
#define CPU_TYPE_POWERPC (18)
#endif

#ifndef KDP_REMOTE_ID
#define KDP_REMOTE_ID 3
#endif

#include <stdarg.h>
#include <string.h>
#include <ctype.h>

extern int standard_is_async_p (void);
extern int standard_can_async_p (void);

static void kdp_mourn_inferior ();
static unsigned int kdp_debug_level = 3;
static unsigned int kdp_default_port = 41139;

static char *kdp_default_host_type_str = "powerpc";
static int kdp_default_host_type = CPU_TYPE_POWERPC;

static kdp_connection c;
static int kdp_host_type = -1;

static int kdp_stopped = 0;
static int kdp_timeout = 5000;
static int kdp_retries = 10;

//struct target_ops kdp_ops;

static void
set_timeouts (args, from_tty, cmd)
     char *args;
     int from_tty;
     struct cmd_list_element *cmd;
{
  kdp_set_timeouts (&c, kdp_timeout, kdp_retries);
}

static int 
parse_host_type (const char *host)
{
  if ((strcasecmp (host, "powerpc") == 0) 
      || (strcasecmp (host, "ppc") == 0)) {
#if KDP_TARGET_POWERPC
    return CPU_TYPE_POWERPC;
#else
    return -2;
#endif
  } else if ((strcasecmp (host, "ia32") == 0) 
	     || (strcasecmp (host, "i386") == 0) 
	     || (strcasecmp (host, "i486") == 0)
	     || (strcasecmp (host, "i586") == 0)
	     || (strcasecmp (host, "pentium") == 0)) {
#if KDP_TARGET_I386
    return CPU_TYPE_I386;
#else
    return -2;
#endif
  } else {
    return -1;
  }
}

static void
logger (kdp_log_level l, const char *format, ...)
{
  va_list ap;
        
  if (l > kdp_debug_level) { return; }

  va_start (ap, format);
  vfprintf (stderr, format, ap);
  va_end (ap);
}
  
#if 0
static void
kdp_open (name, from_tty)
     char *name;
     int from_tty;
{
  push_target (&kdp_ops);
}
#endif

static void
kdp_close (quitting)
     int quitting;
{
}

static int convert_host_type (unsigned int mach_type)
{
return -1;
#if 0
  switch (mach_type) {
  case CPU_TYPE_POWERPC:
    return bfd_arch_powerpc;
  case CPU_TYPE_I386:
    return bfd_arch_i386;
  default:
    return -1;
  }
#endif
}

static void
kdp_detach_command (args, from_tty)
     char *args;
     int from_tty;
{
  kdp_connection c2;
  kdp_return_t kdpret;

  char **argv;
  char *host;
  unsigned int seqno;
  
  argv = buildargv (args);

  if ((argv == NULL) || (argv[0] == NULL) || (argv[1] == NULL) || (argv[2] != NULL)) {
    error ("usage: kdp-detach <hostname> <seqno>");
  }
  host = argv[0];
  seqno = atoi (argv[1]);

  kdp_reset (&c2);

  kdpret = kdp_create (&c2, logger, argv[0], kdp_default_port, kdp_timeout, kdp_retries);
  if (kdpret != RR_SUCCESS) {
    error ("unable to create connection for host \"%s\": %s", args, kdp_return_string (kdpret));
  }

  c2.request->disconnect_req.hdr.request = KDP_DISCONNECT;
  c2.request->hdr.key = 0;
  c2.request->hdr.is_reply = 0;
  c2.request->hdr.seq = seqno;
    
  kdp_set_big_endian (&c2);
  kdpret = kdp_transmit_debug (&c2, c2.request);
  if (kdpret != RR_SUCCESS) {
    error ("unable to send reset request: %s", kdp_return_string (kdpret));
  }
    
  kdp_set_little_endian (&c2);
  kdpret = kdp_transmit_debug (&c2, c2.request);
  if (kdpret != RR_SUCCESS) {
    error ("unable to send reset request: %s", kdp_return_string (kdpret));
  }
    
  kdpret = kdp_destroy (&c2);
  if (kdpret != RR_SUCCESS) {
    error ("unable to destroy connection: %s", kdp_return_string (kdpret));
  }
}

static void
kdp_attach (args, from_tty)
     char *args;
     int from_tty;
{
  kdp_return_t kdpret, kdpret2;
  unsigned int old_seqno, old_exc_seqno;

  if (args == NULL) { 
    args = "";
  }

  {
    char *s = args;
    while ((*s != '\0') && isspace (*s)) { s++; }
    if (*s == '\0') { error ("usage: attach <hostname>"); }
    while ((*s != '\0') && !isspace (*s)) { s++; }
    while ((*s != '\0') && isspace (*s)) { s++; }
    if (*s != '\0') { error ("usage: attach <hostname>"); }
  }

  if (kdp_is_connected (&c)) {
    kdpret = kdp_disconnect (&c);
    if (kdpret != RR_SUCCESS) {
      error ("unable to disconnect from host: %s", kdp_return_string (kdpret));
    }
  }

  if (kdp_is_bound (&c)) {
    kdpret = kdp_destroy (&c);
    if (kdpret != RR_SUCCESS) {
      error ("unable to deallocate KDP connection: %s", kdp_return_string (kdpret));
    }
  }

  old_seqno = c.seqno;
  old_exc_seqno = c.exc_seqno;

  kdpret = kdp_create (&c, logger, args, kdp_default_port, kdp_timeout, kdp_retries);
  if (kdpret != RR_SUCCESS) {
    error ("unable to create connection for host \"%s\": %s", args, kdp_return_string (kdpret));
  }

  c.seqno = old_seqno;
  c.exc_seqno = old_exc_seqno;

#if 0
#if TARGET_POWERPC
  kdp_set_little_endian (&c);
#elif TARGET_I386
  kdp_set_big_endian (&c);
#else
#error "unsupported architecture"
#endif
#endif
  kdp_set_little_endian (&c);

  kdpret = kdp_connect (&c);
  if (kdpret != RR_SUCCESS) {
    kdpret2 = kdp_destroy (&c);
    if (kdpret2 != RR_SUCCESS) {
      warning ("unable to destroy host connection after error connecting: %s",
	       kdp_return_string (kdpret2));
    }
    error ("unable to connect to host \"%s\": %s", args, kdp_return_string (kdpret));
  }

  {
    c.request->readregs_req.hdr.request = KDP_HOSTINFO;

    kdpret = kdp_transaction (&c, c.request, c.response, "kdp_attach");
    if (kdpret != RR_SUCCESS) {
      kdpret2 = kdp_disconnect (&c);
      if (kdpret2 != RR_SUCCESS) {
	warning ("unable to disconnect from host after error determining cpu type: %s",
		 kdp_return_string (kdpret2));
      }
      kdpret2 = kdp_destroy (&c);
      if (kdpret2 != RR_SUCCESS) {
	warning ("unable to destroy host connection after error determining cpu type: %s",
		 kdp_return_string (kdpret2));
      }
      error ("kdp_attach: unable to determine host type: %s", kdp_return_string (kdpret));
    }

    kdp_host_type = convert_host_type (c.response->hostinfo_reply.cpu_type);

    if (kdp_host_type == -1) {
      warning ("kdp_attach: unknown host type 0x%lx; trying default (0x%lx)\n",
	       (unsigned long) c.response->hostinfo_reply.cpu_type,
	       (unsigned long) kdp_default_host_type);
      kdp_host_type = convert_host_type (kdp_default_host_type);
    }
    
    if (kdp_host_type == -1) {
      kdpret2 = kdp_disconnect (&c);
      if (kdpret2 != RR_SUCCESS) {
	warning ("unable to disconnect from host after error determining cpu type: %s",
		 kdp_return_string (kdpret2));
      }
      kdpret2 = kdp_destroy (&c);
      if (kdpret2 != RR_SUCCESS) {
	warning ("unable to destroy host connection after error determining cpu type: %s",
		 kdp_return_string (kdpret2));
      }
      error ("kdp_attach: unknown host type 0x%x\n", c.response->hostinfo_reply.cpu_type);
    }
  }
  
#if 0
  kdp_ops.to_has_all_memory = 1;
  kdp_ops.to_has_memory = 1;
  kdp_ops.to_has_stack = 1;
  kdp_ops.to_has_registers = 1;
  kdp_ops.to_has_execution = 1;
#endif

  update_current_target ();
  cleanup_target (&current_target);

  inferior_pid = KDP_REMOTE_ID;
  kdp_stopped = 1;
}

static void
kdp_detach (args, from_tty)
     char *args;
     int from_tty;
{
  kdp_return_t kdpret;

  if (kdp_is_connected (&c)) {
    kdpret = kdp_disconnect (&c);
    if (kdpret != RR_SUCCESS) {
      warning ("unable to disconnect from host: %s", kdp_return_string (kdpret));
    }
  }

#if 0
  kdp_ops.to_has_all_memory = 0;
  kdp_ops.to_has_memory = 0;
  kdp_ops.to_has_stack = 0;
  kdp_ops.to_has_registers = 0;
  kdp_ops.to_has_execution = 0;
#endif

  update_current_target ();
  cleanup_target (&current_target);
  
  if (kdp_is_bound (&c)) {
    kdpret = kdp_destroy (&c);
    if (kdpret != RR_SUCCESS) {
      error ("unable to deallocate KDP connection: %s", kdp_return_string (kdpret));
    }
  }
  kdp_mourn_inferior();
}

static void
kdp_set_trace_bit (int step)
{
#if 0
  switch (kdp_host_type) {

  case bfd_arch_powerpc: {
#if KDP_TARGET_POWERPC
    LONGEST srr1 = read_register (PS_REGNUM);
    if (step) { 
      srr1 |= 0x400UL;
    } else {
      srr1 &= ~0x400UL;
    }
    write_register (PS_REGNUM, srr1);
#else
    error ("kdp_set_trace_bit: not configured to support powerpc");    
#endif
  }
  break;

  case bfd_arch_i386: {
#ifdef KDP_TARGET_I386
    LONGEST eflags = read_register (PS_REGNUM);
    if (step) { 
      eflags |= 0x100UL;
    } else {
      eflags &= ~0x100UL;
    }
    write_register (PS_REGNUM, eflags);
#else
    error ("kdp_set_trace_bit: not configured to support i386");    
#endif
  }
  break;
  
  default:
    error ("kdp_set_trace_bit: unknown host type 0x%lx", kdp_host_type);
  }
#endif
    error ("kdp_set_trace_bit: unknown host type 0x%lx", kdp_host_type);
}

static void
kdp_resume (pid, step, sig)
     int pid, step;
     enum target_signal sig;
{
  kdp_return_t kdpret;

  if (! kdp_is_connected (&c)) {
    error ("kdp: unable to resume (not connected)");
  }

  if (step) {
    kdp_set_trace_bit (1);
  } else {
    kdp_set_trace_bit (0);
  }
    
  c.request->resumecpus_req.hdr.request = KDP_RESUMECPUS;
  c.request->resumecpus_req.cpu_mask = ~0L;
	
  kdpret = kdp_transaction (&c, c.request, c.response, "kdp_resume");
  if (kdpret != RR_SUCCESS) {
    error ("unable to resume processing on host: %s", kdp_return_string (kdpret));
  }

  kdp_stopped = 0;

printf ("jiji\n");
#if 0
  //if (event_loop_p && target_can_async_p ())
    target_async (inferior_event_handler, 0);
#endif

  if (target_is_async_p ())
    target_executing = 1;
}

static int
kdp_wait (pid, status)
     int pid;
     struct target_waitstatus *status;
{
  kdp_return_t kdpret;

  if (pid == -1) { pid = KDP_REMOTE_ID; }
  if (pid != KDP_REMOTE_ID) {
    error ("kdp: unable to switch to process-id %d", pid);
  }
  
  if (! kdp_is_connected (&c)) {
    error ("kdp: unable to wait for activity (not connected)");
  }
  
  if (kdp_stopped) {
    status->kind = TARGET_WAITKIND_STOPPED;
    status->value.sig = TARGET_SIGNAL_TRAP;
    return pid;
  }
  
  kdpret = kdp_exception_wait (&c, c.response, 0);
  if (kdpret != RR_SUCCESS) {
    error ("unable to wait for result from host: %s\n",
	   kdp_return_string (kdpret));
  }
  
  kdp_set_trace_bit (0);

  kdp_stopped = 1;
  select_frame (get_current_frame (), 0);
  
  status->kind = TARGET_WAITKIND_STOPPED;
  status->value.sig = TARGET_SIGNAL_TRAP;

  return pid;
}

#if KDP_TARGET_POWERPC
static void 
kdp_fetch_registers_ppc (regno)
     int regno;
{
  unsigned int i;

  if (! kdp_is_connected (&c)) {
    error ("kdp: unable to fetch registers (not connected)");
  }

  if ((regno == -1) || IS_GP_REGNUM (regno) || IS_GSP_REGNUM (regno)) {
    kdp_return_t kdpret;
    gdb_ppc_thread_state_t gp_regs; 

    c.request->readregs_req.hdr.request = KDP_READREGS;
    c.request->readregs_req.cpu = 0;
    c.request->readregs_req.flavor = GDB_PPC_THREAD_STATE;
  
    kdpret = kdp_transaction (&c, c.request, c.response, "kdp_fetch_registers_ppc");
    if (kdpret != RR_SUCCESS) {
      error ("kdp_fetch_registers_ppc: unable to fetch PPC_THREAD_STATE: %s",
	     kdp_return_string (kdpret));
    }
    if (c.response->readregs_reply.nbytes != (GDB_PPC_THREAD_STATE_COUNT * 4)) {
      error ("kdp_fetch_registers_ppc: kdp returned %d bytes of register data (expected %d)", 
	     c.response->readregs_reply.nbytes, (GDB_PPC_THREAD_STATE_COUNT * 4));
    }

    memcpy (&gp_regs, c.response->readregs_reply.data, (GDB_PPC_THREAD_STATE_COUNT * 4));
    ppc_next_fetch_gp_registers (registers, &gp_regs);
    ppc_next_fetch_sp_registers (registers, &gp_regs);
    for (i = FIRST_GP_REGNUM; i <= LAST_GP_REGNUM; i++) {
      register_valid[i] = 1;
    }
    for (i = FIRST_GSP_REGNUM; i <= LAST_GSP_REGNUM; i++) {
      register_valid[i] = 1;
    }
  }

  if ((regno == -1) || IS_FP_REGNUM (regno)) {
    kdp_return_t kdpret;
    gdb_ppc_thread_fpstate_t fp_regs;

    c.request->readregs_req.hdr.request = KDP_READREGS;
    c.request->readregs_req.cpu = 0;
    c.request->readregs_req.flavor = GDB_PPC_THREAD_FPSTATE;
  
    kdpret = kdp_transaction (&c, c.request, c.response, "kdp_fetch_registers_ppc");
    if (kdpret != RR_SUCCESS) {
      error ("kdp_fetch_registers_ppc: unable to fetch PPC_THREAD_FPSTATE: %s",
	     kdp_return_string (kdpret));
    }
    if (c.response->readregs_reply.nbytes != (GDB_PPC_THREAD_FPSTATE_COUNT * 4)) {
      error ("kdp_fetch_registers_ppc: kdp returned %d bytes of register data (expected %d)", 
	     c.response->readregs_reply.nbytes, (GDB_PPC_THREAD_FPSTATE_COUNT * 4));
    }

    memcpy (&fp_regs, c.response->readregs_reply.data, (GDB_PPC_THREAD_FPSTATE_COUNT * 4));
    ppc_next_fetch_fp_registers (registers, &fp_regs);
    for (i = FIRST_FP_REGNUM; i <= LAST_FP_REGNUM; i++) {
      register_valid[i] = 1;
    }
  }

  if ((regno == -1) || (regno >= FIRST_VP_REGNUM))
    {
      /* Accesses to the vector, fpscr and vrsave registers aren't currently 
	 supported in the kernel */
      for (i = FIRST_VP_REGNUM; i <= LAST_VP_REGNUM; i++)
	register_valid[i] = 1;
      for (i = FIRST_FSP_REGNUM; i <= LAST_FSP_REGNUM; i++)
	register_valid[i] = 1;
      for (i = FIRST_VSP_REGNUM; i <= LAST_VSP_REGNUM; i++)
	register_valid[i] = 1;
    }
}
#endif /* KDP_TARGET_POWERPC */

#if KDP_TARGET_POWERPC
static void
kdp_store_registers_ppc (regno)
     int regno;
{
  if (! kdp_is_connected (&c)) {
    error ("kdp: unable to store registers (not connected)");
  }

  if ((regno == -1) || IS_GP_REGNUM (regno) || IS_GSP_REGNUM (regno)) {

    gdb_ppc_thread_state_t gp_regs; 
    kdp_return_t kdpret;

    ppc_next_store_gp_registers (registers, &gp_regs);
    ppc_next_store_sp_registers (registers, &gp_regs);

    memcpy (c.request->writeregs_req.data, &gp_regs, (GDB_PPC_THREAD_STATE_COUNT * 4));

    c.request->writeregs_req.hdr.request = KDP_WRITEREGS;
    c.request->writeregs_req.cpu = 0;
    c.request->writeregs_req.flavor = GDB_PPC_THREAD_STATE;
    c.request->writeregs_req.nbytes = GDB_PPC_THREAD_STATE_COUNT * 4;

    kdpret = kdp_transaction (&c, c.request, c.response, "kdp_store_registers_ppc");
    if (kdpret != RR_SUCCESS) {
      error ("kdp_store_registers_ppc: unable to store PPC_THREAD_STATE: %s",
	     kdp_return_string (kdpret));
    }
  }

  if ((regno == -1) || IS_FP_REGNUM (regno)) {

    gdb_ppc_thread_fpstate_t fp_regs;
    kdp_return_t kdpret;

    ppc_next_store_fp_registers (registers, &fp_regs);

    memcpy (c.response->readregs_reply.data, &fp_regs, (GDB_PPC_THREAD_FPSTATE_COUNT * 4));
    
    c.request->writeregs_req.hdr.request = KDP_WRITEREGS;
    c.request->writeregs_req.cpu = 0;
    c.request->writeregs_req.flavor = GDB_PPC_THREAD_FPSTATE;
    c.request->writeregs_req.nbytes = GDB_PPC_THREAD_FPSTATE_COUNT * 4;
  
    kdpret = kdp_transaction (&c, c.request, c.response, "kdp_store_registers_ppc");
    if (kdpret != RR_SUCCESS) {
      error ("kdp_store_registers_ppc: unable to store PPC_THREAD_FPSTATE: %s",
	     kdp_return_string (kdpret));
    }
  }
}
#endif /* KDP_TARGET_POWERPC */

#if KDP_TARGET_I386
static void 
kdp_fetch_registers_i386 (regno)
     int regno;
{
  if (! kdp_is_connected (&c)) {
    error ("kdp: unable to fetch registers (not connected)");
  }

  if ((regno == -1) || IS_GP_REGNUM (regno) || IS_GSP_REGNUM (regno)) {
    kdp_return_t kdpret;
    gdb_i386_thread_state_t gp_regs; 
    unsigned int i;

    c.request->readregs_req.hdr.request = KDP_READREGS;
    c.request->readregs_req.cpu = 0;
    c.request->readregs_req.flavor = GDB_i386_THREAD_STATE;
  
    kdpret = kdp_transaction (&c, c.request, c.response, "kdp_fetch_registers_i386");
    if (kdpret != RR_SUCCESS) {
      error ("kdp_fetch_registers_i386: unable to fetch i386_THREAD_STATE: %s",
	     kdp_return_string (kdpret));
    }
    if (c.response->readregs_reply.nbytes != (GDB_i386_THREAD_STATE_COUNT * 4)) {
      error ("kdp_fetch_registers_i386: kdp returned %d bytes of register data (expected %d)", 
	     c.response->readregs_reply.nbytes, (GDB_i386_THREAD_STATE_COUNT * 4));
    }

    memcpy (&gp_regs, c.response->readregs_reply.data, (GDB_i386_THREAD_STATE_COUNT * 4));
    i386_next_fetch_gp_registers (registers, &gp_regs);
    i386_next_fetch_sp_registers (registers, &gp_regs);
    for (i = FIRST_GP_REGNUM; i <= LAST_GP_REGNUM; i++) {
      register_valid[i] = 1;
    }
    for (i = FIRST_GSP_REGNUM; i <= LAST_GSP_REGNUM; i++) {
      register_valid[i] = 1;
    }
  }

  if ((regno == -1) || IS_FP_REGNUM (regno)) {
    kdp_return_t kdpret;
    gdb_i386_thread_fpstate_t fp_regs;
    unsigned int i;

    c.request->readregs_req.hdr.request = KDP_READREGS;
    c.request->readregs_req.cpu = 0;
    c.request->readregs_req.flavor = GDB_i386_THREAD_FPSTATE;
  
    kdpret = kdp_transaction (&c, c.request, c.response, "kdp_fetch_registers_i386");
    if (kdpret != RR_SUCCESS) {
      error ("kdp_fetch_registers_i386: unable to fetch GDB_i386_THREAD_FPSTATE: %s",
	     kdp_return_string (kdpret));
    }
    if (c.response->readregs_reply.nbytes != (GDB_i386_THREAD_FPSTATE_COUNT * 4)) {
      error ("kdp_fetch_registers_i386: kdp returned %d bytes of register data (expected %d)", 
	     c.response->readregs_reply.nbytes, (GDB_i386_THREAD_FPSTATE_COUNT * 4));
    }

    memcpy (&fp_regs, c.response->readregs_reply.data, (GDB_i386_THREAD_FPSTATE_COUNT * 4));
    i386_next_fetch_fp_registers (registers, &fp_regs);
    for (i = FIRST_FP_REGNUM; i <= LAST_FP_REGNUM; i++) {
      register_valid[i] = 1;
    }
  }
}
#endif /* KDP_TARGET_I386 */

#if KDP_TARGET_I386
static void
kdp_store_registers_i386 (regno)
     int regno;
{
  if (! kdp_is_connected (&c)) {
    error ("kdp: unable to store registers (not connected)");
  }

  if ((regno == -1) || IS_GP_REGNUM (regno) || IS_GSP_REGNUM (regno)) {

    gdb_i386_thread_state_t gp_regs; 
    kdp_return_t kdpret;

    i386_next_store_gp_registers (registers, &gp_regs);
    i386_next_store_sp_registers (registers, &gp_regs);

    memcpy (c.request->writeregs_req.data, &gp_regs, (GDB_i386_THREAD_STATE_COUNT * 4));

    c.request->writeregs_req.hdr.request = KDP_WRITEREGS;
    c.request->writeregs_req.cpu = 0;
    c.request->writeregs_req.flavor = GDB_i386_THREAD_STATE;
    c.request->writeregs_req.nbytes = GDB_i386_THREAD_STATE_COUNT * 4;

    kdpret = kdp_transaction (&c, c.request, c.response, "kdp_store_registers_i386");
    if (kdpret != RR_SUCCESS) {
      error ("kdp_store_registers_i386: unable to store i386_THREAD_STATE: %s",
	     kdp_return_string (kdpret));
    }
  }

  if ((regno == -1) || IS_FP_REGNUM (regno)) {

    gdb_i386_thread_fpstate_t fp_regs;
    kdp_return_t kdpret;

    i386_next_store_fp_registers (registers, &fp_regs);

    memcpy (c.response->readregs_reply.data, &fp_regs, (GDB_i386_THREAD_FPSTATE_COUNT * 4));
    
    c.request->writeregs_req.hdr.request = KDP_WRITEREGS;
    c.request->writeregs_req.cpu = 0;
    c.request->writeregs_req.flavor = GDB_i386_THREAD_FPSTATE;
    c.request->writeregs_req.nbytes = GDB_i386_THREAD_FPSTATE_COUNT * 4;
  
    kdpret = kdp_transaction (&c, c.request, c.response, "kdp_store_registers_i386");
    if (kdpret != RR_SUCCESS) {
      error ("kdp_store_registers_i386: unable to store i386_THREAD_FPSTATE: %s",
	     kdp_return_string (kdpret));
    }
  }
}
#endif /* KDP_TARGET_I386 */

static void
kdp_store_registers (regno)
     int regno;
{
  if (! kdp_is_connected (&c)) {
    error ("kdp: unable to store registers (not connected)");
  }


#if 0
  switch (kdp_host_type) {
  case bfd_arch_powerpc:
#if KDP_TARGET_POWERPC
    kdp_store_registers_ppc (regno);
#else
    error ("kdp_store_registers: not configured to support powerpc");
#endif
    break;

  case bfd_arch_i386:
#if KDP_TARGET_I386
    kdp_store_registers_i386 (regno);
#else
    error ("kdp_store_registers: not configured to support i386");
#endif
    break;

  default:
    error ("kdp_store_registers: unknown host type 0x%lx", kdp_host_type);
  }
#endif
    kdp_store_registers_i386 (regno);

}
    
static void
kdp_fetch_registers (int regno)
{
  if (! kdp_is_connected (&c)) {
    error ("kdp: unable to fetch registers (not connected)");
  }

#if 0
  switch (kdp_host_type) {

  case bfd_arch_powerpc:
#if KDP_TARGET_POWERPC
    kdp_fetch_registers_ppc (regno);
#else
    error ("kdp_fetch_registers: not configured to support powerpc");
#endif
    break;

  case bfd_arch_i386:
#if KDP_TARGET_I386
    kdp_fetch_registers_i386 (regno);
#else
    error ("kdp_fetch_registers: not configured to support i386");
#endif
    break;

  default:
    error ("kdp_fetch_registers: unknown host type 0x%lx", kdp_host_type);
  }
#endif
}

static void
kdp_prepare_to_store ()
{
  kdp_fetch_registers (-1);
}

static int
kdp_xfer_memory (memaddr, myaddr, len, write)
     CORE_ADDR memaddr;
     char *myaddr;
     int len;
     int write;
{
  kdp_return_t kdpret;

  if (! kdp_is_connected (&c)) {
    logger (KDP_LOG_DEBUG, "kdp: unable to transfer memory (not connected)");
    return 0;
  }

  if (len > KDP_MAX_DATA_SIZE) { len = KDP_MAX_DATA_SIZE; }

  if (write) {
    c.request->writemem_req.hdr.request = KDP_WRITEMEM;
    c.request->writemem_req.address = memaddr;
    c.request->writemem_req.nbytes = len;
    memcpy (c.request->writemem_req.data, myaddr, len);
    
    kdpret = kdp_transaction (&c, c.request, c.response, "kdp_xfer_memory");
    if (c.response->writemem_reply.error != RR_SUCCESS) {
      kdpret = c.response->writemem_reply.error;
    }
    if (kdpret != RR_SUCCESS) {
      logger (KDP_LOG_DEBUG, "kdp_xfer_memory: unable to store %d bytes at 0x%lx: %s\n", 
	      len, memaddr, kdp_return_string (kdpret));
      return 0;
    }
  } else {
    c.request->readmem_req.hdr.request = KDP_READMEM;
    c.request->readmem_req.address = memaddr;
    c.request->readmem_req.nbytes = len;

    kdpret = kdp_transaction (&c, c.request, c.response, "kdp_xfer_memory");
    if (c.response->readmem_reply.error != RR_SUCCESS) {
      kdpret = c.response->readmem_reply.error;
    }
    if (kdpret != RR_SUCCESS) {
      logger (KDP_LOG_DEBUG, "kdp_xfer_memory: unable to fetch %d bytes from 0x%lx: %s\n", 
	      len, memaddr, kdp_return_string (kdpret));
      return 0;
    }
    if (c.response->readmem_reply.nbytes != len) {
      logger (KDP_LOG_DEBUG, "kdp_xfer_memory: kdp read only %d bytes of data (expected %d)\n", 
	      c.response->readmem_reply.nbytes, len);
      return 0;
    } 
    memcpy (myaddr, c.response->readregs_reply.data, len);
  }
  
  return len;
}

static void
kdp_files_info ()
{
  printf ("\tNo connection information available.\n");
}

static void
kdp_kill (args, from_tty)
     char *args;
     int from_tty;
{
  kdp_detach (args, from_tty);
}

static void
kdp_load (args, from_tty)
     char *args;
     int from_tty;
{
  error ("unsupported operation kdp_load");
}

static void
kdp_create_inferior (execfile, args, env)
     char *execfile;
     char *args;
     char **env;
{
  error ("unsupported operation kdp_create_inferior");
}

static void
kdp_mourn_inferior ()
{
  //unpush_target (&kdp_ops);
  //generic_mourn_inferior ();
}

static int remote_async_terminal_ours_p = 1;
static void (*ofunc) (int);
static PTR sigint_remote_twice_token;
static PTR sigint_remote_token;

static void remote_interrupt_twice (int signo); 
static void remote_interrupt (int signo);
static void handle_remote_sigint_twice (int sig);
static void handle_remote_sigint (int sig);
static void async_remote_interrupt_twice (gdb_client_data arg);
static void async_remote_interrupt (gdb_client_data arg);

static void
interrupt_query (void)
{
  target_terminal_ours ();

  if (query ("Interrupted while waiting for the program.\n\
Give up (and stop debugging it)? "))
    {
      target_mourn_inferior ();
      return_to_top_level (RETURN_QUIT);
    }

  target_terminal_inferior ();
}

static void
remote_interrupt_twice (int signo)
{
  signal (signo, ofunc);
  interrupt_query ();
  signal (signo, remote_interrupt);
}

static void
remote_interrupt (int signo)
{
  signal (signo, remote_interrupt_twice);
  target_stop ();
}

static void
handle_remote_sigint_twice (int sig)
{
  signal (sig, handle_sigint);
printf ("SIGINT REMOTE TWICE\n");
#if 0
  sigint_remote_twice_token =
    create_async_signal_handler (inferior_event_handler_wrapper, NULL);
  mark_async_signal_handler_wrapper (sigint_remote_twice_token);
#endif
}

static void
handle_remote_sigint (int sig)
{
  signal (sig, handle_remote_sigint_twice);
  sigint_remote_twice_token =
    create_async_signal_handler (async_remote_interrupt_twice, NULL);
  mark_async_signal_handler_wrapper (sigint_remote_token);
}

static void
async_remote_interrupt_twice (gdb_client_data arg)
{
  if (target_executing)
    {
      interrupt_query ();
      signal (SIGINT, handle_remote_sigint);
    }
}

static void
async_remote_interrupt (gdb_client_data arg)
{
  target_stop ();
}

static void
cleanup_sigint_signal_handler (void *dummy)
{
  signal (SIGINT, handle_sigint);
  if (sigint_remote_twice_token)
    delete_async_signal_handler ((struct async_signal_handler **) &sigint_remote_twice_token);
  if (sigint_remote_token)
    delete_async_signal_handler ((struct async_signal_handler **) &sigint_remote_token);
}

static void
initialize_sigint_signal_handler (void)
{
  sigint_remote_token =
    create_async_signal_handler (async_remote_interrupt, NULL);
  signal (SIGINT, handle_remote_sigint);
}

static void
kdp_terminal_inferior (void)
{
  /* terminal_inferior (); */

  if (!sync_execution)
    return;
  if (!remote_async_terminal_ours_p)
    return;
  CHECK_FATAL (sync_execution);
  CHECK_FATAL (remote_async_terminal_ours_p);
  delete_file_handler (input_fd);
  remote_async_terminal_ours_p = 0;
  initialize_sigint_signal_handler ();
}

static void
kdp_terminal_ours (void)
{
  /* terminal_ours (); */

  if (!sync_execution)
    return;
  if (remote_async_terminal_ours_p)
    return;
  CHECK_FATAL (sync_execution);
  CHECK_FATAL (!remote_async_terminal_ours_p);
  cleanup_sigint_signal_handler (NULL);

  add_file_handler (input_fd, stdin_event_handler, 0);

  remote_async_terminal_ours_p = 1;
}

static void (*async_client_callback) (enum inferior_event_type event_type, void *context);
static void *async_client_context;

static void
kdp_file_handler (int error, gdb_client_data client_data)
{
  async_client_callback (INF_REG_EVENT, async_client_context);
}

typedef struct gdb_event gdb_event;
typedef void (event_handler_func) (int);

struct gdb_event
  {
    event_handler_func *proc;	/* Procedure to call to service this event. */
    int fd;			/* File descriptor that is ready. */
    struct gdb_event *next_event;	/* Next in list of events or NULL. */
  };

static void
kdp_async (void (*callback) (enum inferior_event_type event_type, 
			      void *context), void *context)
{
  if (current_target.to_async_mask_value == 0)
    internal_error ("Calling remote_async when async is masked");

  if (callback != NULL)
    {
      async_client_callback = callback;
      async_client_context = context;
      if (c.reqfd > 0)
	add_file_handler (c.reqfd, kdp_file_handler, NULL);
      if (c.excfd > 0)
	add_file_handler (c.excfd, kdp_file_handler, NULL);
    }
  else
    {
      if (c.reqfd > 0)
	delete_file_handler (c.reqfd);
      if (c.excfd > 0)
	delete_file_handler (c.excfd);
    }

  if ((callback != NULL) && (c.saved_exception_pending)) {

    gdb_event *event;

    event = (gdb_event *) malloc (sizeof (gdb_event));
    event->proc = kdp_file_handler;
    event->fd = 0;
    async_queue_event (event, TAIL);
  }
}

#if 0
static void
init_kdp_ops ()
{
  kdp_ops.to_shortname = "remote-kdp";
  kdp_ops.to_longname = "Remote NeXT or Mac OS X system via KDP";
  kdp_ops.to_doc = "Remotely debug a NeXT or Mac OS X system using KDP\n\
Arguments are\n\
`hostname [port-number]'\n\
    To connect via the network, where hostname and port-number specify the\n\
    host and port where you can connect via KDP.";
  kdp_ops.to_open = kdp_open;
  kdp_ops.to_close = kdp_close;
  kdp_ops.to_attach = kdp_attach;
  kdp_ops.to_resume = kdp_resume;
  kdp_ops.to_wait = kdp_wait;
  kdp_ops.to_fetch_registers = kdp_fetch_registers;
  kdp_ops.to_store_registers = kdp_store_registers;
  kdp_ops.to_prepare_to_store = kdp_prepare_to_store;
  kdp_ops.to_xfer_memory = kdp_xfer_memory;
  kdp_ops.to_files_info = kdp_files_info;
  kdp_ops.to_insert_breakpoint = memory_insert_breakpoint;
  kdp_ops.to_remove_breakpoint = memory_remove_breakpoint;
  kdp_ops.to_detach = kdp_kill;
  kdp_ops.to_kill = kdp_kill;
  kdp_ops.to_load = kdp_load;
  kdp_ops.to_create_inferior = kdp_create_inferior;
  kdp_ops.to_mourn_inferior = kdp_mourn_inferior;
  kdp_ops.to_stratum = process_stratum;
  kdp_ops.to_can_async_p = standard_can_async_p;
  kdp_ops.to_is_async_p = standard_is_async_p;
  kdp_ops.to_terminal_inferior = kdp_terminal_inferior;
  kdp_ops.to_terminal_ours = kdp_terminal_ours;
  kdp_ops.to_async = kdp_async; 
  kdp_ops.to_async_mask_value = 1;
  kdp_ops.to_magic = OPS_MAGIC;
}
#endif

static void update_kdp_default_host_type (args, from_tty, c)
     char *args;
     int from_tty;
     struct cmd_list_element *c;
{
  int htype;

  if (args == NULL) { args = kdp_default_host_type_str; }
  htype = parse_host_type (args);
  if (htype < 0) {
    if (htype == -2) {
      error ("Known but unsupported host type: \"%s\".", args);
    } else {
      error ("Unknown host type: \"%s\".", args);
    }
  }

  kdp_default_host_type = htype;
}

void
_initialize_remote_kdp ()
{
#if 0
  static char *archlist[] = { "powerpc", "ia32", NULL };

  struct cmd_list_element *cmd = NULL;

  init_kdp_ops ();
  add_target (&kdp_ops);

  add_com ("kdp-detach", class_run, kdp_detach_command,
	   "Reset a (possibly disconnected) remote NeXT or Mac OS X kernel.\n");

  cmd = add_set_enum_cmd 
    ("kdp-default-host-type", class_obscure, archlist,
     (char *) &kdp_default_host_type_str,
     "Set CPU type to be used for hosts providing incorect information (powerpc/ia32).",
     &setlist);
  cmd->function.sfunc = update_kdp_default_host_type;
  add_show_from_set (cmd, &showlist);		

  cmd = add_set_cmd
    ("kdp-timeout", class_obscure, var_zinteger,
     (char *) &kdp_timeout,
     "Set UDP timeout in milliseconds for (non-exception) KDP transactions.",
     &setlist);
  add_show_from_set (cmd, &showlist);		
  cmd->function.sfunc = set_timeouts;
  
  cmd = add_set_cmd
    ("kdp-retries", class_obscure, var_zinteger,
     (char *) &kdp_retries,
     "Set number of UDP retries for (non-exception) KDP transactions.",
     &setlist);
  add_show_from_set (cmd, &showlist);		
  cmd->function.sfunc = set_timeouts;

  cmd = add_set_cmd
    ("kdp-default-port", class_obscure, var_zinteger,
     (char *) &kdp_default_port,
     "Set default UDP port on which to attempt to contact KDP.",
     &setlist);
  add_show_from_set (cmd, &showlist);		

  cmd = add_set_cmd
    ("kdp-debug-level", class_obscure, var_zinteger, 
     (char *) &kdp_debug_level,
     "Set level of verbosity for KDP debugging information.",
     &setlist);
  add_show_from_set (cmd, &showlist);		

  cmd = add_set_cmd
    ("kdp-sequence-number", class_obscure, var_zinteger,
     (char *) &c.seqno,
     "Set current sequence number for KDP transactions.",
     &setlist);
  add_show_from_set  (cmd, &showlist);

  cmd = add_set_cmd
    ("kdp-exception-sequence-number", class_obscure, var_zinteger,
     (char *) &c.exc_seqno,
     "Set current sequence number for KDP exception transactions.",
     &setlist);
  add_show_from_set  (cmd, &showlist);

  kdp_reset (&c);
#endif
}
