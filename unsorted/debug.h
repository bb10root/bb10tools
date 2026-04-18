/* QNX Neutrino debug interface.

   Copyright 2003 Free Software Foundation, Inc.

   Contributed by QNX Software Systems Ltd.

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

/* __DEBUG_H_INCLUDED is Neutrino's native debug.h header.  We don't want
   these duplicate definitions if we're compiling natively and have already
   included it.  */
#ifndef __DEBUG_H_INCLUDED
#define __DEBUG_H_INCLUDED

#define QNX_NOTE_NAME	"QNX"

typedef char qnx_64[8];

enum Elf_nto_note_types
{
  QNT_NULL = 0,
  QNT_DEBUG_FULLPATH,
  QNT_DEBUG_RELOC,
  QNT_STACK,
  QNT_GENERATOR,
  QNT_DEFAULT_LIB,
  QNT_CORE_SYSINFO,
  QNT_CORE_INFO,
  QNT_CORE_STATUS,
  QNT_CORE_GREG,
  QNT_CORE_FPREG,
  QNT_NUM
};

typedef struct
{
  long bits[2];
} nto_sigset_t;

union nto_sigval
{
  int sival_int;
  void *sival_ptr;
};

typedef struct nto_siginfo
{
  int si_signo;
  int si_code;
  void (*si_handler) ();
  union
  {
    int _pad[6];
    struct
    {
      pid_t _pid;
      union
      {
	struct
	{
	  union nto_sigval _value;
	  uid_t _uid;
	} _kill;
	struct
	{
	  int _status;
	  clock_t _utime;
	  clock_t _stime;
	} _chld;
      } _pdata;
    } _proc;
    struct
    {
      int _fltno;
      void *_addr;
      void *_fltip;
    } _fault;
  } _data;
} nto_siginfo_t;

#ifdef __QNX__
__BEGIN_DECLS
#include <_pack64.h>
#endif
#define _DEBUG_FLAG_STOPPED			0x00000001	/* Thread is not running.  */
#define DEBUG_FLAG_ISTOP			0x00000002	/* Stopped at point of interest.  */
#define _DEBUG_FLAG_IPINVAL			0x00000010	/* IP is not valid.  */
#define _DEBUG_FLAG_ISSYS			0x00000020	/* System process.  */
#define _DEBUG_FLAG_SSTEP			0x00000040	/* Stopped because of single step.  */
#define _DEBUG_FLAG_CURTID			0x00000080	/* Thread is current thread.  */
#define DEBUG_FLAG_TRACE_EXEC		0x00000100	/* Stopped because of breakpoint.  */
#define _DEBUG_FLAG_TRACE_RD		0x00000200	/* Stopped because of read access.  */
#define _DEBUG_FLAG_TRACE_WR		0x00000400	/* Stopped because of write access.  */
#define _DEBUG_FLAG_TRACE_MODIFY	0x00000800	/* Stopped because of modified memory.  */
#define _DEBUG_FLAG_RLC				0x00010000	/* Run-on-Last-Close flag is set.  */
#define _DEBUG_FLAG_KLC				0x00020000	/* Kill-on-Last-Close flag is set.  */
#define _DEBUG_FLAG_FORK			0x00040000	/* Child inherits flags (Stop on fork/spawn).  */
#define _DEBUG_FLAG_MASK			0x000f0000	/* Flags that can be changed.  */
  enum
{
  _DEBUG_WHY_REQUESTED,
  _DEBUG_WHY_SIGNALLED,
  _DEBUG_WHY_FAULTED,
  _DEBUG_WHY_JOBCONTROL,
  _DEBUG_WHY_TERMINATED,
  _DEBUG_WHY_CHILD,
  _DEBUG_WHY_EXEC
};

#define _DEBUG_RUN_CLRSIG			0x00000001	/* Clear pending signal */
#define _DEBUG_RUN_CLRFLT			0x00000002	/* Clear pending fault */
#define DEBUG_RUN_TRACE			0x00000004	/* Trace mask flags interesting signals */
#define DEBUG_RUN_HOLD				0x00000008	/* Hold mask flags interesting signals */
#define DEBUG_RUN_FAULT			0x00000010	/* Fault mask flags interesting faults */
#define _DEBUG_RUN_VADDR			0x00000020	/* Change ip before running */
#define _DEBUG_RUN_STEP				0x00000040	/* Single step only one thread */
#define _DEBUG_RUN_STEP_ALL			0x00000080	/* Single step one thread, other threads run */
#define _DEBUG_RUN_CURTID			0x00000100	/* Change current thread (target thread) */
#define DEBUG_RUN_ARM				0x00000200	/* Deliver event at point of interest */

typedef struct _debug_process_info
{
  pid_t pid;
  pid_t parent;
  unsigned flags;
  unsigned umask;
  pid_t child;
  pid_t sibling;
  pid_t pgrp;
  pid_t sid;
  int base_address;
  int initial_stack;
  uid_t uid;
  gid_t gid;
  uid_t euid;
  gid_t egid;
  uid_t suid;
  gid_t sgid;
  nto_sigset_t sig_ignore;
  nto_sigset_t sig_queue;
  nto_sigset_t sig_pending;
  unsigned num_chancons;
  unsigned num_fdcons;
  unsigned num_threads;
  unsigned num_timers;
  qnx_64 reserved[20];
} nto_procfs_info;

typedef struct _debug_thread_info
{
  pid_t pid;
  unsigned tid;
  unsigned flags;
  unsigned short why;
  unsigned short what;
  int ip;
  int sp;
  int stkbase;
  int tls;
  unsigned stksize;
  unsigned tid_flags;
  unsigned char priority;
  unsigned char real_priority;
  unsigned char policy;
  unsigned char state;
  short syscall;
  unsigned short last_cpu;
  unsigned timeout;
  int last_chid;
  nto_sigset_t sig_blocked;
  nto_sigset_t sig_pending;
  nto_siginfo_t info;
  unsigned reserved1;
  union
  {
    struct
    {
      unsigned tid;
    } join;
    struct
    {
      int id;
      int sync;
    } sync;
    struct
    {
      unsigned nid;
      pid_t pid;
      int coid;
      int chid;
      int scoid;
    } connect;
    struct
    {
      int chid;
    } channel;
    struct
    {
      pid_t pid;
      int vaddr;
      unsigned flags;
    } waitpage;
    struct
    {
      unsigned size;
    } stack;
    qnx_64 filler[4];
  } blocked;
  qnx_64 reserved2[8];
} nto_procfs_status;

#ifdef __QNX__
#include <_packpop.h>

__END_DECLS
#endif
#endif /* __DEBUG_H_INCLUDED */
