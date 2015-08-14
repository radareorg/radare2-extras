/* Definitions used by the GDB event loop.
   Copyright 1999 Free Software Foundation, Inc.
   Written by Elena Zannoni <ezannoni@cygnus.com> of Cygnus Solutions.

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
   Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.  */

/* An event loop listens for events from multiple event sources. When
   an event arrives, it is queued and processed by calling the
   appropriate event handler. The event loop then continues to listen
   for more events. An event loop completes when there are no event
   sources to listen on.  External event sources can be plugged into
   the loop.

   There are 3 main components: 
   - a list of file descriptors to be monitored, GDB_NOTIFIER.  
   - a list of events that have occurred, EVENT_QUEUE.  
   - a list of signal handling functions, SIGHANDLER_LIST.

   GDB_NOTIFIER keeps track of the event sources. Event sources for
   gdb are currently the UI and the target.  Gdb communicates with the
   command line user interface via the readline library and usually
   communicates with remote targets via a serial port. Serial ports
   are represented in GDB as file descriptors and select/poll calls.
   For native targets instead, the communication consists of calls to
   ptrace and waits (via signals) or calls to poll/select (via file
   descriptors). In the current gdb, the code handling events related
   to the target resides in the wait_for_inferior function and in
   various target specific files (*-tdep.c).

   EVENT_QUEUE keeps track of the events that have happened during the
   last iteration of the event loop, and need to be processed.  An
   event is represented by a procedure to be invoked in order to
   process the event.  The queue is scanned head to tail.  If the
   event of interest is a change of state in a file descriptor, then a
   call to poll or select will be made to detect it.

   If the events generate signals, they are also queued by special
   functions that are invoked through traditional signal handlers.
   The actions to be taken is response to such events will be executed
   when the SIGHANDLER_LIST is scanned, the next time through the
   infinite loop.  

   Corollary tasks are the creation and deletion of event sources. */
#ifndef _INCLUDE_EVENT_LOOP_
#define _INCLUDE_EVENT_LOOP_ 1


typedef struct gdb_event2 gdb_event2;
typedef void (event_handler_func) (int);
typedef void *gdb_client_data;
typedef void (handler_func) (int, gdb_client_data);
typedef void (sig_handler_func) (gdb_client_data);
typedef void (timer_handler_func) (gdb_client_data);

/* Event for the GDB event system.  Events are queued by calling
   async_queue_event and serviced later on by gdb_do_one_event. An
   event can be, for instance, a file descriptor becoming ready to be
   read. Servicing an event simply means that the procedure PROC will
   be called.  We have 2 queues, one for file handlers that we listen
   to in the event loop, and one for the file handlers+events that are
   ready. The procedure PROC associated with each event is always the
   same (handle_file_event).  Its duty is to invoke the handler
   associated with the file descriptor whose state change generated
   the event, plus doing other cleanups and such. */

struct gdb_event2
  {
    event_handler_func *proc;	/* Procedure to call to service this event. */
    int fd;			/* File descriptor that is ready. */
    struct gdb_event2 *next_event;	/* Next in list of events or NULL. */
  };

/* Information about each file descriptor we register with the event
   loop. */

typedef struct file_handler
  {
    int fd;			/* File descriptor. */
    int mask;			/* Events we want to monitor: POLLIN, etc. */
    int ready_mask;		/* Events that have been seen since
				   the last time. */
    handler_func *proc;		/* Procedure to call when fd is ready. */
    gdb_client_data client_data;	/* Argument to pass to proc. */
    int error;			/* Was an error detected on this fd? */
    struct file_handler *next_file;	/* Next registered file descriptor. */
  }
file_handler;

/* PROC is a function to be invoked when the READY flag is set. This
   happens when there has been a signal and the corresponding signal
   handler has 'triggered' this async_signal_handler for
   execution. The actual work to be done in response to a signal will
   be carried out by PROC at a later time, within process_event. This
   provides a deferred execution of signal handlers.
   Async_init_signals takes care of setting up such an
   asyn_signal_handler for each interesting signal. */
typedef struct async_signal_handler
  {
    int ready;			/* If ready, call this handler from the main event loop, 
				   using invoke_async_handler. */
    struct async_signal_handler *next_handler;	/* Ptr to next handler */
    sig_handler_func *proc;	/* Function to call to do the work */
    gdb_client_data client_data;	/* Argument to async_handler_func */
  }
async_signal_handler;

/* Where to add an event onto the event queue, by queue_event. */
typedef enum
  {
    /* Add at tail of queue. It will be processed in first in first
       out order. */
    TAIL,
    /* Add at head of queue. It will be processed in last in first out
       order. */
    HEAD
  }
queue_position;

/* Tell create_file_handler what events we are interested in. 
   This is used by the select version of the event loop. */

#define GDB_READABLE	(1<<1)
#define GDB_WRITABLE	(1<<2)
#define GDB_EXCEPTION	(1<<3)

/* Exported functions from event-loop.c */
extern void start_event_loop (void);
extern void delete_file_handler (int fd);
extern void add_file_handler (int fd, handler_func * proc, gdb_client_data client_data);
extern void mark_async_signal_handler (struct async_signal_handler *async_handler_ptr);
extern struct async_signal_handler *
  create_async_signal_handler (sig_handler_func * proc, gdb_client_data client_data);
extern void delete_async_signal_handler (struct async_signal_handler **async_handler_ptr);
extern int create_timer (int milliseconds, timer_handler_func * proc, gdb_client_data client_data);
extern void delete_timer (int id);

#endif
