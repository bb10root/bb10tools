/* Remote target communications with QNX Neutrino pdebug protocol.

   This file was derived from remote.c. It communicates with a
   target talking the Neutrino remote debug protocol.
   See nto-share/dsmsgs.h for details.

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

#include <fcntl.h>
#include <signal.h>

#include "defs.h"
#include "gdb_string.h"
#include "terminal.h"
#include "inferior.h"
#include "target.h"
#include "gdbcmd.h"
#include "objfiles.h"
#include "gdbthread.h"
#include "completer.h"
#include "cli/cli-decode.h"
#include "regcache.h"
#include "gdbcore.h"
#include "serial.h"

#include "nto-share/dsmsgs.h"
#include "nto-share/debug.h"
#include "nto-tdep.h"

#ifdef __CYGWIN__
#include <sys/cygwin.h>
#endif

#ifndef EOK
#define EOK 0
#endif

#define QNX_READ_MODE	0x0
#define QNX_WRITE_MODE	0x301
#define QNX_WRITE_PERMS	0x1ff

#ifdef __CYGWIN__
#define HOST_READ_MODE  O_RDONLY|O_BINARY
#define HOST_WRITE_MODE  O_WRONLY|O_CREAT|O_TRUNC|O_BINARY
#else
#define HOST_READ_MODE  O_RDONLY
#define HOST_WRITE_MODE  O_WRONLY|O_CREAT|O_TRUNC
#endif

#ifndef O_BINARY
#define O_BINARY 0
#endif

int (*target_created_hook) (pid_t);

static void init_nto_ops (void);

static int putpkt (unsigned);

static int readchar (int timeout);

static int getpkt (int forever);

static unsigned nto_send (unsigned, int);

static int nto_write_bytes (CORE_ADDR memaddr, char *myaddr, int len);

static int nto_read_bytes (CORE_ADDR memaddr, char *myaddr, int len);

static void nto_files_info (struct target_ops *ignore);

static void nto_parse_notify (struct target_waitstatus *status);

static int nto_xfer_memory (CORE_ADDR memaddr, char *myaddr, int len,
			    int should_write, struct mem_attrib *attrib,
			    struct target_ops *target);

static int nto_incoming_text (int len);

void nto_outgoing_text (char *buf, int nbytes);

void nto_fetch_registers (int regno);

static void nto_prepare_to_store (void);

static void nto_store_registers (int regno);

static void nto_resume (ptid_t ptid, int step, enum target_signal sig);

static int nto_start_remote (char *dummy);

static void nto_open (char *name, int from_tty);

static void nto_close (int quitting);

static void nto_mourn (void);

static ptid_t nto_wait (ptid_t ptid, struct target_waitstatus *status);

static void nto_kill (void);

static void nto_detach (char *args, int from_tty);

static void nto_interrupt (int signo);

static void nto_interrupt_twice (int signo);

static void interrupt_query (void);

static void upload_command (char *args, int from_tty);

static void download_command (char *args, int from_tty);

static void nto_add_commands (void);

static void nto_remove_commands (void);

static int nto_fileopen (char *fname, int mode, int perms);

static void nto_fileclose (int);

static int nto_fileread (char *buf, int size);

static int nto_filewrite (char *buf, int size);

static void nto_find_new_threads (void);

static int nto_insert_hw_breakpoint (CORE_ADDR addr, char *contents_cache);

static int nto_stopped_by_watchpoint (void);

static int nto_remove_hw_watchpoint (CORE_ADDR addr, int len, int type);

static int nto_insert_hw_watchpoint (CORE_ADDR addr, int len, int type);

char *nto_pid_to_str (ptid_t ptid);

enum target_signal target_signal_from_nto (int sig);

enum target_signal target_signal_to_nto (int sig);

static struct target_ops nto_ops;

/* Number of seconds to wait for a timeout on the remote side.  */
static int nto_timeout = 10;
static int nto_inherit_env = 1;
int nto_target_has_stack_frame = 0;
static char *nto_remote_cwd = NULL;
static char *nto_remote_file = NULL;
static int upload_sets_exec = 1;

/* Descriptor for I/O to remote machine.  Initialize it to NULL so that
   nto_open knows that we don't have a file open when the program
   starts.  */
struct serial *nto_desc = NULL;
int nto_cputype = -1;
unsigned nto_cpuid = 0;

static int host_endian;
static unsigned channelrd = SET_CHANNEL_DEBUG;	/* Set in getpkt().  */
static unsigned channelwr = SET_CHANNEL_DEBUG;	/* Set in putpkt(). */

/* These store the version of the protocol used by the pdebug we connect to.  */
static int TargetQNXProtoverMajor = 0;	/* Set in nto_start_remote().  */
static int TargetQNXProtoverMinor = 0;	/* Set in nto_start_remote().  */

/* These define the version of the protocol implemented here.  */
#define HOST_QNX_PROTOVER_MAJOR	0
#define HOST_QNX_PROTOVER_MINOR	3

static union
{
  unsigned char buf[DS_DATA_MAX_SIZE];
  DSMsg_union_t pkt;
} tran, recv;

#define SWAP64( val ) ( \
				(((val) >> 56) & 0x00000000000000ff) \
			|	(((val) >> 40) & 0x000000000000ff00) \
			|	(((val) >> 24) & 0x0000000000ff0000) \
			|	(((val) >> 8)  & 0x00000000ff000000) \
			|	(((val) << 8)  & 0x000000ff00000000) \
			|	(((val) << 24) & 0x0000ff0000000000) \
			|	(((val) << 40) & 0x00ff000000000000) \
			|	(((val) << 56) & 0xff00000000000000) )

#define SWAP32( val ) ( (((val) >> 24) & 0x000000ff)	\
			  | (((val) >> 8)  & 0x0000ff00)\
			  | (((val) << 8)  & 0x00ff0000)\
			  | (((val) << 24) & 0xff000000) )

#define SWAP16( val ) ( (((val) >> 8) & 0xff) | (((val) << 8) & 0xff00) )


short int
nto_swap16 (int val)
{
  return (host_endian != TARGET_BYTE_ORDER ? SWAP16 (val) : val);
}


long int
nto_swap32 (long int val)
{
  return (host_endian != TARGET_BYTE_ORDER ? SWAP32 (val) : val);
}

long long int
nto_swap64 (long long int val)
{
  return (host_endian != TARGET_BYTE_ORDER ? SWAP64 (val) : val);
}

/* Stuff for dealing with the packets which are part of this protocol.  */

#define MAX_TRAN_TRIES 3
#define MAX_RECV_TRIES 3

#define FRAME_CHAR	0x7e
#define ESC_CHAR	0x7d

static unsigned char nak_packet[] =
  { FRAME_CHAR, SET_CHANNEL_NAK, 0, FRAME_CHAR };
static unsigned char ch_reset_packet[] =
  { FRAME_CHAR, SET_CHANNEL_RESET, 0xff, FRAME_CHAR };
static unsigned char ch_debug_packet[] =
  { FRAME_CHAR, SET_CHANNEL_DEBUG, 0xfe, FRAME_CHAR };
static unsigned char ch_text_packet[] =
  { FRAME_CHAR, SET_CHANNEL_TEXT, 0xfd, FRAME_CHAR };

#define SEND_NAK         serial_write(nto_desc,nak_packet,sizeof(nak_packet))
#define SEND_CH_RESET    serial_write(nto_desc,ch_reset_packet,sizeof(ch_reset_packet))
#define SEND_CH_DEBUG    serial_write(nto_desc,ch_debug_packet,sizeof(ch_debug_packet))
#define SEND_CH_TEXT     serial_write(nto_desc,ch_text_packet,sizeof(ch_text_packet))

/* Send a packet to the remote machine.  Also sets channelwr and informs
   target if channelwr has changed.  */
static int
putpkt (unsigned len)
{
  int i;
  unsigned char csum = 0;
  unsigned char buf2[DS_DATA_MAX_SIZE * 2];
  unsigned char *p;

  /* Copy the packet into buffer BUF2, encapsulating it
     and giving it a checksum.  */

  p = buf2;
  *p++ = FRAME_CHAR;

  if (nto_internal_debugging == 1)
    {
      printf_unfiltered ("putpkt() - cmd %d, subcmd %d, mid %d\n",
			 tran.pkt.hdr.cmd, tran.pkt.hdr.subcmd,
			 tran.pkt.hdr.mid);
    }

  if (remote_debug)
    printf_unfiltered ("Sending packet (len %d): ", len);

  for (i = 0; i < len; i++)
    {
      unsigned char c = tran.buf[i];

      if (remote_debug)
	printf_unfiltered ("%2.2x", c);
      csum += c;

      switch (c)
	{
	case FRAME_CHAR:
	case ESC_CHAR:
	  if (remote_debug)
	    printf_unfiltered ("[escape]");
	  *p++ = ESC_CHAR;
	  c ^= 0x20;
	  break;
	}
      *p++ = c;
    }

  csum ^= 0xff;

  if (remote_debug)
    {
      printf_unfiltered ("%2.2x\n", csum);
      gdb_flush (gdb_stdout);
    }
  switch (csum)
    {
    case FRAME_CHAR:
    case ESC_CHAR:
      *p++ = ESC_CHAR;
      csum ^= 0x20;
      break;
    }
  *p++ = csum;
  *p++ = FRAME_CHAR;

  /* GP added - June 17, 1999.  There used to be only 'channel'.
     Now channelwr and channelrd keep track of the state better.
     If channelwr is not in the right state, notify target and set channelwr.  */
  if (channelwr != tran.pkt.hdr.channel)
    {
      switch (tran.pkt.hdr.channel)
	{
	case SET_CHANNEL_TEXT:
	  SEND_CH_TEXT;
	  break;
	case SET_CHANNEL_DEBUG:
	  SEND_CH_DEBUG;
	  break;
	}
      channelwr = tran.pkt.hdr.channel;
    }

  if (serial_write (nto_desc, buf2, p - buf2))
    perror_with_name ("putpkt: write failed");

  return len;
}

/* Read a single character from the remote end, masking it down to 8 bits.  */
static int
readchar (int timeout)
{
  int ch;

  ch = serial_readchar (nto_desc, timeout);

  switch (ch)
    {
    case SERIAL_EOF:
      error ("Remote connection closed");
    case SERIAL_ERROR:
      perror_with_name ("Remote communication error");
    case SERIAL_TIMEOUT:
      return ch;
    default:
      return ch & 0xff;
    }
}

/* Come here after finding the start of the frame.  Collect the rest into BUF,
   verifying the checksum, length, and handling run-length compression.
   Returns 0 on any error, 1 on success.  */
static int
read_frame ()
{
  unsigned char csum;
  unsigned char *bp;
  unsigned char modifier = 0;
  int c;

  if (remote_debug)
    printf_filtered ("Receiving data: ");

  csum = 0;
  bp = recv.buf;

  memset (bp, -1, sizeof recv.buf);
  for (;;)
    {
      c = readchar (nto_timeout);

      switch (c)
	{
	case SERIAL_TIMEOUT:
	  puts_filtered ("Timeout in mid-packet, retrying\n");
	  return -1;
	case ESC_CHAR:
	  modifier = 0x20;
	  continue;
	case FRAME_CHAR:
	  if (bp == recv.buf)
	    continue;		/* Ignore multiple start frames.  */
	  if (csum != 0xff)	/* Checksum error.  */
	    return -1;
	  return bp - recv.buf - 1;
	default:
	  c ^= modifier;
	  if (remote_debug)
	    printf_filtered ("%2.2x", c);
	  csum += c;
	  *bp++ = c;
	  break;
	}
      modifier = 0;
    }
}

/* Read a packet from the remote machine, with error checking,
   and store it in recv.buf.
   If FOREVER, wait forever rather than timing out; this is used
   while the target is executing user code.  */
static int
getpkt (int forever)
{
  int c;
  int tries;
  int timeout;
  unsigned len;

  if (nto_internal_debugging == 1)
    {
      printf_unfiltered ("getpkt(%d)\n", forever);
    }

  if (forever)
    {
      timeout = watchdog > 0 ? watchdog : -1;
    }
  else
    {
      timeout = nto_timeout;
    }

  for (tries = 0; tries < MAX_RECV_TRIES; tries++)
    {
      /* This can loop forever if the remote side sends us characters
         continuously, but if it pauses, we'll get a zero from readchar
         because of timeout.  Then we'll count that as a retry.

         Note that we will only wait forever prior to the start of a packet.
         After that, we expect characters to arrive at a brisk pace.  They
         should show up within nto_timeout intervals.  */
      do
	{
	  c = readchar (timeout);

	  if (c == SERIAL_TIMEOUT)
	    {
	      /* Watchdog went off.  Kill the target.  */
	      if (forever && watchdog > 0)
		{
		  target_mourn_inferior ();
		  error ("Watchdog has expired.  Target detached.");
		}
	      puts_filtered ("Timed out.\n");
	      return -1;
	    }
	}
      while (c != FRAME_CHAR);

      /* We've found the start of a packet, now collect the data.  */
      len = read_frame ();

      if (remote_debug)
	printf_filtered ("\n");

      if (len >= sizeof (struct DShdr))
	{
	  if (recv.pkt.hdr.channel)	/* If hdr.channel is not 0, then hdr.channel is supported.  */
	    channelrd = recv.pkt.hdr.channel;

	  if (nto_internal_debugging == 2)
	    {
	      printf_unfiltered ("getpkt() - len %d, channelrd %d,", len,
				 channelrd);
	      switch (channelrd)
		{
		case SET_CHANNEL_DEBUG:
		  printf_unfiltered (" cmd = %d, subcmd = %d, mid = %d\n",
				     recv.pkt.hdr.cmd, recv.pkt.hdr.subcmd,
				     recv.pkt.hdr.mid);
		  break;
		case SET_CHANNEL_TEXT:
		  printf_unfiltered (" text message\n");
		  break;
		case SET_CHANNEL_RESET:
		  printf_unfiltered (" set_channel_reset\n");
		  break;
		default:
		  printf_unfiltered (" unknown channel!\n");
		  break;
		}
	    }
	  return len;
	}
      if (len >= 1)
	{
	  /* Packet too small to be part of the debug protocol,
	     must be a transport level command.  */
	  if (recv.buf[0] == SET_CHANNEL_NAK)
	    {
	      /* Our last transmission didn't make it - send it again.  */
	      channelrd = SET_CHANNEL_NAK;
	      return -1;
	    }
	  if (recv.buf[0] <= SET_CHANNEL_TEXT)
	    channelrd = recv.buf[0];

	  if (nto_internal_debugging == 2)
	    {
	      printf_unfiltered ("set channelrd to %d\n", channelrd);
	    }
	  --tries;		/* Doesn't count as a retry.  */
	  continue;
	}
      SEND_NAK;
    }

  /* We have tried hard enough, and just can't receive the packet.  Give up.  */
  printf_unfiltered ("Ignoring packet error, continuing...");
  return 0;
}

void
nto_send_init (unsigned cmd, unsigned subcmd, unsigned chan)
{
  static unsigned char mid;

  if (nto_internal_debugging == 1)
    {
      printf_unfiltered ("    nto_send_init(cmd %d, subcmd %d)\n", cmd,
			 subcmd);
    }

  if (TARGET_BYTE_ORDER == BFD_ENDIAN_BIG)
    cmd |= DSHDR_MSG_BIG_ENDIAN;

  tran.pkt.hdr.cmd = cmd;	/* TShdr.cmd.  */
  tran.pkt.hdr.subcmd = subcmd;	/* TShdr.console.  */
  tran.pkt.hdr.mid = ((chan == SET_CHANNEL_DEBUG) ? mid++ : 0);	/* TShdr.spare1.  */
  tran.pkt.hdr.channel = chan;	/* TShdr.channel.  */
}


/* Send text to remote debug daemon - Pdebug.  */
void
nto_outgoing_text (char *buf, int nbytes)
{
  TSMsg_text_t *msg;

  msg = (TSMsg_text_t *) & tran;

  msg->hdr.cmd = TSMsg_text;
  msg->hdr.console = 0;
  msg->hdr.spare1 = 0;
  msg->hdr.channel = SET_CHANNEL_TEXT;

  memcpy (msg->text, buf, nbytes);

  putpkt (nbytes + offsetof (TSMsg_text_t, text));
}


/* Display some text that came back across the text channel.  */
static int
nto_incoming_text (int len)
{
  int textlen;
  TSMsg_text_t *text;
  char fmt[20];
  char buf[TS_TEXT_MAX_SIZE];

  text = (void *) &recv.buf[0];
  textlen = len - offsetof (TSMsg_text_t, text);

  switch (text->hdr.cmd)
    {
    case TSMsg_text:
      sprintf (fmt, "%%%d.%ds", textlen, textlen);
      sprintf (buf, fmt, text->text);
      ui_file_write (gdb_stdtarg, buf, textlen);
      return 0;
    default:
      return -1;
    }
}

/* Send the command in tran.buf to the remote machine,
   and read the reply into recv.buf.  */
static unsigned
nto_send (unsigned len, int report_errors)
{
  int rlen;
  unsigned tries;

  if (nto_desc == NULL)
    {
      errno = ENOTCONN;
      return 0;
    }

  for (tries = 0;; tries++)
    {
      if (tries >= MAX_TRAN_TRIES)
	{
	  unsigned char err = DSrMsg_err;

	  printf_unfiltered ("Remote exhausted %d retries.\n", tries);
	  if (TARGET_BYTE_ORDER == BFD_ENDIAN_BIG)
	    err |= DSHDR_MSG_BIG_ENDIAN;
	  recv.pkt.hdr.cmd = err;
	  recv.pkt.err.err = nto_swap32 (EIO);
	  rlen = sizeof (recv.pkt.err);
	  break;
	}
      putpkt (len);
      for (;;)
	{
	  rlen = getpkt (0);
	  if ((channelrd != SET_CHANNEL_TEXT) || (rlen == -1))
	    break;
	  nto_incoming_text (rlen);
	}
      if (rlen == -1)		/* Getpkt returns -1 if MsgNAK received.  */
	{
	  printf_unfiltered ("MsgNak received - resending\n");
	  continue;
	}
      if ((rlen >= 0) && (recv.pkt.hdr.mid == tran.pkt.hdr.mid))
	break;

      if (nto_internal_debugging == 2)
	{
	  printf_unfiltered ("mid mismatch!\n");
	}
    }
  /* Getpkt() sets channelrd to indicate where the message came from.
     now we switch on the channel (/type of message) and then deal
     with it.  */
  switch (channelrd)
    {
    case SET_CHANNEL_DEBUG:
      if (((recv.pkt.hdr.cmd & DSHDR_MSG_BIG_ENDIAN) != 0))
	{
	  sprintf (tran.buf, "set endian big");
	  if (TARGET_BYTE_ORDER != BFD_ENDIAN_BIG)
	    execute_command (tran.buf, 0);
	}
      else
	{
	  sprintf (tran.buf, "set endian little");
	  if (TARGET_BYTE_ORDER != BFD_ENDIAN_LITTLE)
	    execute_command (tran.buf, 0);
	}
      recv.pkt.hdr.cmd &= ~DSHDR_MSG_BIG_ENDIAN;
      if (recv.pkt.hdr.cmd == DSrMsg_err)
	{
	  errno = nto_swap32 (recv.pkt.err.err);
	  if (report_errors)
	    {
	      switch (recv.pkt.hdr.subcmd)
		{
		case PDEBUG_ENOERR:
		  break;
		case PDEBUG_ENOPTY:
		  perror_with_name ("Remote (no ptys available)");
		  break;
		case PDEBUG_ETHREAD:
		  perror_with_name ("Remote (thread start error)");
		  break;
		case PDEBUG_ECONINV:
		  perror_with_name ("Remote (invalid console number)");
		  break;
		case PDEBUG_ESPAWN:
		  perror_with_name ("Remote (spawn error)");
		  break;
		case PDEBUG_EPROCFS:
		  perror_with_name ("Remote (procfs [/proc] error)");
		  break;
		case PDEBUG_EPROCSTOP:
		  perror_with_name ("Remote (devctl PROC_STOP error)");
		  break;
		case PDEBUG_EQPSINFO:
		  perror_with_name ("Remote (psinfo error)");
		  break;
		case PDEBUG_EQMEMMODEL:
		  perror_with_name
		    ("Remote (invalid memory model [not flat] )");
		  break;
		case PDEBUG_EQPROXY:
		  perror_with_name ("Remote (proxy error)");
		  break;
		case PDEBUG_EQDBG:
		  perror_with_name ("Remote (__nto_debug_* error)");
		  break;
		default:
		  perror_with_name ("Remote");
		}
	    }
	}
      break;
    case SET_CHANNEL_TEXT:
    case SET_CHANNEL_RESET:
      break;
    }
  return rlen;
}

static void
set_thread (int th)
{
  if (nto_internal_debugging == 1)
    {
      printf_unfiltered
	("set_thread(th %d pid %d, prev tid %ld)\n", th,
	 ptid_get_pid (inferior_ptid), ptid_get_tid (inferior_ptid));
    }
  nto_send_init (DStMsg_select, DSMSG_SELECT_SET, SET_CHANNEL_DEBUG);
  tran.pkt.select.pid = nto_swap32 (ptid_get_pid (inferior_ptid));
  tran.pkt.select.tid = nto_swap32 (th);
  nto_send (sizeof (tran.pkt.select), 1);
}

static void
set_exec_bfd (char *filename)
{
  char *scratch_pathname;
  int scratch_chan;

  scratch_chan = openp (getenv ("PATH"), 1, filename,
			write_files ? O_RDWR | O_BINARY : O_RDONLY | O_BINARY,
			0, &scratch_pathname);
  if (scratch_chan >= 0)
    exec_bfd = bfd_fdopenr (scratch_pathname, gnutarget, scratch_chan);
}

/* Return nonzero if the thread TH is still alive on the remote system.  */
static int
nto_thread_alive (ptid_t th)
{
  if (nto_internal_debugging == 1)
    {
      printf_unfiltered ("nto_thread_alive -- pid %d, tid %ld\n",
			 ptid_get_pid (th), ptid_get_tid (th));
    }

  nto_send_init (DStMsg_select, DSMSG_SELECT_QUERY, SET_CHANNEL_DEBUG);
  tran.pkt.select.pid = nto_swap32 (ptid_get_pid (th));
  tran.pkt.select.tid = nto_swap32 (ptid_get_tid (th));
  nto_send (sizeof (tran.pkt.select), 0);
  return recv.pkt.hdr.cmd != DSrMsg_err;
}

/* Clean up connection to a remote debugger.  */
static int
nto_close_1 (char *dummy)
{
  nto_send_init (DStMsg_disconnect, 0, SET_CHANNEL_DEBUG);
  nto_send (sizeof (tran.pkt.disconnect), 0);
  serial_close (nto_desc);

  return 0;
}

static void
nto_close (int quitting)
{
  if (nto_internal_debugging == 1)
    {
      printf_unfiltered ("nto_close(quitting %d)\n", quitting);
    }

  if (nto_desc)
    {
      catch_errors ((catch_errors_ftype *) nto_close_1, NULL, "",
		    RETURN_MASK_ALL);
      nto_desc = NULL;
      nto_remove_commands ();
    }
}

static int
nto_start_remote (char *dummy)
{
  int orig_target_endian;

  if (nto_internal_debugging == 1)
    {
      printf_unfiltered
	("nto_start_remote, recv.pkt.hdr.cmd %d, (dummy %s)\n",
	 recv.pkt.hdr.cmd, dummy);
    }

  immediate_quit = 1;		/* Allow user to interrupt it.  */
  for (;;)
    {
      orig_target_endian = (TARGET_BYTE_ORDER == BFD_ENDIAN_BIG);

      /* Reset remote pdebug.  */
      SEND_CH_RESET;

      nto_send_init (DStMsg_connect, 0, SET_CHANNEL_DEBUG);

      tran.pkt.connect.major = HOST_QNX_PROTOVER_MAJOR;
      tran.pkt.connect.minor = HOST_QNX_PROTOVER_MINOR;

      nto_send (sizeof (tran.pkt.connect), 0);

      if (recv.pkt.hdr.cmd != DSrMsg_err)
	break;
      if (orig_target_endian == (TARGET_BYTE_ORDER == BFD_ENDIAN_BIG))
	break;
      /* Send packet again, with opposite endianness.  */
    }
  if (recv.pkt.hdr.cmd == DSrMsg_err)
    {
      error ("Connection failed: %ld.", nto_swap32 (recv.pkt.err.err));
    }
  /* NYI: need to size transmit/receive buffers to allowed size in connect response.  */
  immediate_quit = 0;

  printf_unfiltered ("Remote target is %s-endian\n",
		     (TARGET_BYTE_ORDER ==
		      BFD_ENDIAN_BIG) ? "big" : "little");
  target_byte_order_auto = 1;

  nto_init_solib_absolute_prefix ();

  /* Try to query pdebug for their version of the protocol.  */
  nto_send_init (DStMsg_protover, 0, SET_CHANNEL_DEBUG);
  tran.pkt.protover.major = HOST_QNX_PROTOVER_MAJOR;
  tran.pkt.protover.minor = HOST_QNX_PROTOVER_MINOR;
  nto_send (sizeof (tran.pkt.protover), 0);
  if ((recv.pkt.hdr.cmd == DSrMsg_err) && (nto_swap32 (recv.pkt.err.err) == EINVAL))	/* old pdebug protocol version 0.0 */
    {
      TargetQNXProtoverMajor = 0;
      TargetQNXProtoverMinor = 0;
    }
  else if (recv.pkt.hdr.cmd == DSrMsg_okstatus)
    {
      TargetQNXProtoverMajor = nto_swap32 (recv.pkt.okstatus.status);
      TargetQNXProtoverMinor = nto_swap32 (recv.pkt.okstatus.status);
      TargetQNXProtoverMajor =
	(TargetQNXProtoverMajor >> 8) & DSMSG_PROTOVER_MAJOR;
      TargetQNXProtoverMinor = TargetQNXProtoverMinor & DSMSG_PROTOVER_MINOR;
    }
  else
    {
      error ("Connection failed (Protocol Version Query): %ld.",
	     nto_swap32 (recv.pkt.err.err));
    }

  if (nto_internal_debugging == 1)
    {
      printf_unfiltered ("Pdebug protover %d.%d, GDB protover %d.%d\n",
			 TargetQNXProtoverMajor, TargetQNXProtoverMinor,
			 HOST_QNX_PROTOVER_MAJOR, HOST_QNX_PROTOVER_MINOR);
    }

  target_has_execution = 0;
  target_has_stack = 0;
  nto_target_has_stack_frame = 0;
  start_remote ();		/* Initialize gdb process mechanisms.  */

  nto_send_init (DStMsg_cpuinfo, 0, SET_CHANNEL_DEBUG);
  nto_send (sizeof (tran.pkt.cpuinfo), 1);
  if (recv.pkt.hdr.cmd == DSrMsg_err)
    {
      nto_cpuinfo_valid = 0;
    }
  else
    {
      struct dscpuinfo foo;
      memcpy (&foo, recv.pkt.okdata.data, sizeof (struct dscpuinfo));
      nto_cpuinfo_flags = nto_swap32 (foo.cpuflags);
      nto_cpuinfo_valid = 1;
    }

  return 1;
}

static void
nto_semi_init (void)
{
  nto_send_init (DStMsg_disconnect, 0, SET_CHANNEL_DEBUG);
  nto_send (sizeof (tran.pkt.disconnect), 0);

  inferior_ptid = null_ptid;
  init_thread_list ();

  if (!catch_errors ((catch_errors_ftype *) nto_start_remote, (char *) 0,
		     "Couldn't establish connection to remote target\n",
		     RETURN_MASK_ALL))
    {
      flush_cached_frames ();
      pop_target ();
      if (nto_internal_debugging == 3)
	{
	  printf_unfiltered ("nto_semi_init() - pop_target\n");
	}
    }
}

/* Open a connection to a remote debugger.
   NAME is the filename used for communication.  */
static void
nto_open (char *name, int from_tty)
{
  if (nto_internal_debugging == 1)
    {
      printf_unfiltered ("nto_open(name '%s', from_tty %d)\n", name,
			 from_tty);
    }

  if (name == 0)
    error
      ("To open a remote debug connection, you need to specify what serial\ndevice is attached to the remote system (e.g. /dev/ttya).");

  immediate_quit = 1;		/* Allow user to interrupt it.  */

  target_preopen (from_tty);
  unpush_target (&nto_ops);

  if (nto_internal_debugging == 3)
    {
      printf_unfiltered ("nto_open() - unpush_target\n");
    }

  nto_desc = serial_open (name);

  if (!nto_desc)
    {
      immediate_quit = 0;
      perror_with_name (name);
    }

  if (baud_rate != -1)
    {
      if (serial_setbaudrate (nto_desc, baud_rate))
	{
	  immediate_quit = 0;
	  serial_close (nto_desc);
	  perror_with_name (name);
	}
    }

  serial_raw (nto_desc);

  /* If there is something sitting in the buffer we might take it as a
     response to a command, which would be bad.  */
  serial_flush_input (nto_desc);

  if (from_tty)
    {
      puts_filtered ("Remote debugging using ");
      puts_filtered (name);
      puts_filtered ("\n");
    }
  push_target (&nto_ops);	/* Switch to using remote target now.  */
  nto_add_commands ();
  if (nto_internal_debugging == 3)
    {
      printf_unfiltered ("nto_open() - push_target\n");
    }

  inferior_ptid = null_ptid;
  init_thread_list ();

  /* Start the remote connection; if error (0), discard this target.
     In particular, if the user quits, be sure to discard it
     (we'd be in an inconsistent state otherwise).  */
  if (!catch_errors ((catch_errors_ftype *) nto_start_remote, (char *) 0,
		     "Couldn't establish connection to remote target\n",
		     RETURN_MASK_ALL))
    {
      immediate_quit = 0;
      pop_target ();

      if (nto_internal_debugging == 1)
	{
	  printf_unfiltered ("nto_open() - pop_target\n");
	}
    }
  immediate_quit = 0;
}

/* Attaches to a process on the target side.  Arguments are as passed
   to the `attach' command by the user.  This routine can be called
   when the target is not on the target-stack, if the target_can_run
   routine returns 1; in that case, it must push itself onto the stack.
   Upon exit, the target should be ready for normal operations, and
   should be ready to deliver the status of the process immediately
   (without waiting) to an upcoming target_wait call.  */
static void
nto_attach (char *args, int from_tty)
{
  ptid_t ptid;

  if (!ptid_equal (inferior_ptid, null_ptid))
    nto_semi_init ();

  if (nto_internal_debugging == 1)
    {
      printf_unfiltered ("nto_attach(args '%s', from_tty %d)\n",
			 args ? args : "(null)", from_tty);
    }

  if (!args)
    error_no_arg ("process-id to attach");

  ptid = pid_to_ptid (atoi (args));

  if (symfile_objfile != NULL)
    exec_file_attach (symfile_objfile->name, from_tty);

  if (from_tty)
    {
      printf_unfiltered ("Attaching to %s\n", target_pid_to_str (ptid));
      gdb_flush (gdb_stdout);
    }

  nto_send_init (DStMsg_attach, 0, SET_CHANNEL_DEBUG);
  tran.pkt.attach.pid = nto_swap32 (PIDGET (ptid));
  nto_send (sizeof (tran.pkt.attach), 1);

  /* NYI: add symbol information for process.  */
  /* Turn the PIDLOAD into a STOPPED notification so that when gdb
     calls nto_wait, we won't cycle around.  */
  recv.pkt.hdr.cmd = DShMsg_notify;
  recv.pkt.hdr.subcmd = DSMSG_NOTIFY_STOPPED;

  /* Hack this in here, since we will bypass the notify.  */
  nto_cputype = nto_swap16 (recv.pkt.notify.un.pidload.cputype);
  nto_cpuid = nto_swap32 (recv.pkt.notify.un.pidload.cpuid);
#ifdef QNX_SET_PROCESSOR_TYPE
  QNX_SET_PROCESSOR_TYPE (nto_cpuid);	/* For mips. */
#endif
  inferior_ptid = ptid;
  target_has_execution = 1;
  target_has_stack = 1;
  target_has_registers = 1;
  nto_target_has_stack_frame = 1;
  if (target_created_hook)
    target_created_hook (ptid_get_pid (inferior_ptid));
  attach_flag = 1;
}

static void
nto_post_attach (pid_t pid)
{
#ifdef SOLIB_CREATE_INFERIOR_HOOK
  if (exec_bfd)
    SOLIB_CREATE_INFERIOR_HOOK (pid);
#endif
}

/* This takes a program previously attached to and detaches it.  After
   this is done, GDB can be used to debug some other program.  We
   better not have left any breakpoints in the target program or it'll
   die when it hits one.  */
static void
nto_detach (char *args, int from_tty)
{
  if (nto_internal_debugging == 1)
    {
      printf_unfiltered ("nto_detach(args '%s', from_tty %d)\n",
			 args ? args : "(null)", from_tty);
    }
  if (from_tty)
    {
      char *exec_file = get_exec_file (0);
      if (exec_file == 0)
	exec_file = "";

      printf_unfiltered ("Detaching from program: %s %d\n", exec_file,
			 PIDGET (inferior_ptid));
      gdb_flush (gdb_stdout);
    }
  if (args)
    {
      int sig = target_signal_to_nto (atoi (args));

      nto_send_init (DStMsg_kill, 0, SET_CHANNEL_DEBUG);
      tran.pkt.kill.signo = nto_swap32 (sig);
      nto_send (sizeof (tran.pkt.kill), 1);
    }

  nto_send_init (DStMsg_detach, 0, SET_CHANNEL_DEBUG);
  tran.pkt.detach.pid = nto_swap32 (PIDGET (inferior_ptid));
  nto_send (sizeof (tran.pkt.detach), 1);
  inferior_ptid = null_ptid;
  init_thread_list ();
  target_has_execution = 0;
  target_has_stack = 0;
  target_has_registers = 0;
  nto_target_has_stack_frame = 0;

  attach_flag = 0;
}


/* Tell the remote machine to resume.  */
static void
nto_resume (ptid_t ptid, int step, enum target_signal sig)
{
  int signo;

  if (nto_internal_debugging == 1)
    {
      printf_unfiltered ("nto_resume(pid %d, step %d, sig %d)\n",
			 PIDGET (ptid), step, target_signal_to_nto (sig));
    }

  if (ptid_equal (inferior_ptid, null_ptid))
    return;

  set_thread (ptid_equal (ptid, minus_one_ptid) ? ptid_get_tid (inferior_ptid)
	      : ptid_get_tid (ptid));

  /* The HandleSig stuff is part of the new protover 0.1, but has not
     been implemented in all pdebugs that reflect that version.  If
     the HandleSig comes back with an error, then revert to protover 0.0
     behaviour, regardless of actual protover.
     The handlesig msg sends the signal to pass, and a char array
     'signals', which is the list of signals to notice. */
  nto_send_init (DStMsg_handlesig, 0, SET_CHANNEL_DEBUG);
  tran.pkt.handlesig.sig_to_pass = nto_swap32 (target_signal_to_nto (sig));
  for (signo = 0; signo < QNXNTO_NSIG; signo++)
    {
      if (signal_stop_state (target_signal_from_nto (signo)) == 0 &&
	  signal_print_state (target_signal_from_nto (signo)) == 0 &&
	  signal_pass_state (target_signal_from_nto (signo)) == 1)
	{
	  tran.pkt.handlesig.signals[signo] = 0;
	}
      else
	{
	  tran.pkt.handlesig.signals[signo] = 1;
	}
    }
  nto_send (sizeof (tran.pkt.handlesig), 0);
  if (recv.pkt.hdr.cmd == DSrMsg_err)
    if (sig != TARGET_SIGNAL_0)
      {
	nto_send_init (DStMsg_kill, 0, SET_CHANNEL_DEBUG);
	tran.pkt.kill.signo = nto_swap32 (target_signal_to_nto (sig));
	nto_send (sizeof (tran.pkt.kill), 1);
      }

  nto_send_init (DStMsg_run, step ? DSMSG_RUN_COUNT : DSMSG_RUN,
		 SET_CHANNEL_DEBUG);
  tran.pkt.run.step.count = nto_swap32 (1);
  nto_send (sizeof (tran.pkt.run), 1);
}

static void (*ofunc) ();
static void (*ofunc_alrm) ();

/* Yucky but necessary globals used to track state in nto_wait() as a
   result of things done in nto_interrupt(), nto_interrupt_twice(),
   and nto_interrupt_retry().  */
static sig_atomic_t SignalCount = 0;	/* Used to track ctl-c retransmits.  */
static sig_atomic_t InterruptedTwice = 0;	/* Set in nto_interrupt_twice().  */
static sig_atomic_t WaitingForStopResponse = 0;	/* Set in nto_interrupt(), cleared in nto_wait().  */

#define QNX_TIMER_TIMEOUT 5
#define QNX_CTL_C_RETRIES 3

static void
nto_interrupt_retry (signo)
{
  SignalCount++;
  if (SignalCount >= QNX_CTL_C_RETRIES)	/* Retry QNX_CTL_C_RETRIES times after original transmission.  */
    {
      printf_unfiltered
	("CTL-C transmit - 3 retries exhausted.  Ending debug session.\n");
      WaitingForStopResponse = 0;
      SignalCount = 0;
      target_mourn_inferior ();
      throw_exception (RETURN_QUIT);
    }
  else
    {
      nto_interrupt (SIGINT);
    }
}


/* Ask the user what to do when an interrupt is received.  */
static void
interrupt_query ()
{
  alarm (0);
  signal (SIGINT, ofunc);
  signal (SIGALRM, ofunc_alrm);
  target_terminal_ours ();
  InterruptedTwice = 0;

  if (query
      ("Interrupted while waiting for the program.\n Give up (and stop debugging it)? "))
    {
      SignalCount = 0;
      target_mourn_inferior ();
      throw_exception (RETURN_QUIT);
    }
  target_terminal_inferior ();
  signal (SIGALRM, nto_interrupt_retry);
  signal (SIGINT, nto_interrupt_twice);
  alarm (QNX_TIMER_TIMEOUT);
}


/* The user typed ^C twice.  */
static void
nto_interrupt_twice (int signo)
{
  InterruptedTwice = 1;
}

/* Send ^C to target to halt it.  Target will respond, and send us a
   packet.  */

/* GP - Dec 21, 2000.  If the target sends a NotifyHost at the same time as
   GDB sends a DStMsg_stop, then we would get into problems as both ends
   would be waiting for a response, and not the sent messages.  Now, we put
   the pkt and set the global flag 'WaitingForStopResponse', and return.
   This then goes back to the the main loop in nto_wait() below where we
   now check against the debug message received, and handle both.
   All retries of the DStMsg_stop are handled via SIGALRM and alarm(timeout).  */
static void
nto_interrupt (int signo)
{
  if (nto_internal_debugging == 1)
    {
      printf_unfiltered ("nto_interrupt(signo %d)\n", signo);
    }

  /* If this doesn't work, try more severe steps.  */
  signal (signo, nto_interrupt_twice);
  signal (SIGALRM, nto_interrupt_retry);

  WaitingForStopResponse = 1;

  nto_send_init (DStMsg_stop, DSMSG_STOP_PIDS, SET_CHANNEL_DEBUG);
  putpkt (sizeof (tran.pkt.stop));

  /* Set timeout.  */
  alarm (QNX_TIMER_TIMEOUT);
}

/* Wait until the remote machine stops, then return,
   storing status in STATUS just as `wait' would.
   Returns "pid". */
static ptid_t
nto_wait (ptid_t ptid, struct target_waitstatus *status)
{
  if (nto_internal_debugging == 1)
    {
      printf_unfiltered ("nto_wait pid %d, inferior pid %d\n",
			 ptid_get_pid (ptid), ptid_get_pid (inferior_ptid));
    }

  status->kind = TARGET_WAITKIND_STOPPED;
  status->value.sig = TARGET_SIGNAL_0;

  if (ptid_equal (inferior_ptid, null_ptid))
    return null_ptid;

  if (recv.pkt.hdr.cmd != DShMsg_notify)
    {
      int len;
      char waiting_for_notify;

      waiting_for_notify = 1;
      SignalCount = 0;
      InterruptedTwice = 0;

      ofunc = (void (*)()) signal (SIGINT, nto_interrupt);
      ofunc_alrm = (void (*)()) signal (SIGALRM, nto_interrupt_retry);
      for (;;)
	{
	  len = getpkt (1);
	  if (len < 0)		/* Error - probably received MSG_NAK.  */
	    {
	      if (WaitingForStopResponse)
		{
		  /* We do not want to get SIGALRM while calling it's handler
		     the timer is reset in the handler.  */
		  alarm (0);
		  nto_interrupt_retry (SIGALRM);
		  continue;
		}
	      else
		{
		  /* Turn off the alarm, and reset the signals, and return.  */
		  alarm (0);
		  signal (SIGINT, ofunc);
		  signal (SIGALRM, ofunc_alrm);
		  return null_ptid;
		}
	    }
	  if (channelrd == SET_CHANNEL_TEXT)
	    nto_incoming_text (len);
	  else			/* DEBUG CHANNEL.  */
	    {
	      recv.pkt.hdr.cmd &= ~DSHDR_MSG_BIG_ENDIAN;
	      /* If we have sent the DStMsg_stop due to a ^C, we expect
	         to get the response, so check and clear the flag
	         also turn off the alarm - no need to retry,
	         we did not lose the packet.  */
	      if ((WaitingForStopResponse) && (recv.pkt.hdr.cmd == DSrMsg_ok))
		{
		  WaitingForStopResponse = 0;
		  status->value.sig = TARGET_SIGNAL_INT;
		  alarm (0);
		  if (!waiting_for_notify)
		    break;
		}
	      /* Else we get the Notify we are waiting for.  */
	      else if (recv.pkt.hdr.cmd == DShMsg_notify)
		{
		  waiting_for_notify = 0;
		  /* Send an OK packet to acknowledge the notify.  */
		  tran.pkt.hdr.cmd = DSrMsg_ok;
		  if ((TARGET_BYTE_ORDER == BFD_ENDIAN_BIG))
		    tran.pkt.hdr.cmd |= DSHDR_MSG_BIG_ENDIAN;
		  tran.pkt.hdr.channel = SET_CHANNEL_DEBUG;
		  tran.pkt.hdr.mid = recv.pkt.hdr.mid;
		  SEND_CH_DEBUG;
		  putpkt (sizeof (tran.pkt.ok));
		  /* Handle old pdebug protocol behavior, where out of order msgs get dropped
		     version 0.0 does this, so we must resend after a notify.  */
		  if ((TargetQNXProtoverMajor == 0)
		      && (TargetQNXProtoverMinor == 0))
		    {
		      if (WaitingForStopResponse)
			{
			  alarm (0);
			  /* Change the command to something other than notify
			     so we don't loop in here again - leave the rest of
			     the packet alone for nto_parse_notify() below!!!  */
			  recv.pkt.hdr.cmd = DSrMsg_ok;
			  nto_interrupt (SIGINT);
			}
		    }
		  nto_parse_notify (status);

		  if (!WaitingForStopResponse)
		    break;
		}
	    }
	}
      alarm (0);

      /* Hitting Ctl-C sends a stop request, a second ctl-c means quit,
         so query here, after handling the results of the first ctl-c
         We know we were interrupted twice because the yucky global flag
         'InterruptedTwice' is set in the handler, and cleared in
         interrupt_query().  */
      if (InterruptedTwice)
	interrupt_query ();

      signal (SIGINT, ofunc);
      signal (SIGALRM, ofunc_alrm);
    }

  recv.pkt.hdr.cmd = DSrMsg_ok;	/* To make us wait the next time.  */
  return inferior_ptid;
}

static void
nto_parse_notify (struct target_waitstatus *status)
{
  pid_t pid, tid;

  if (nto_internal_debugging == 1)
    {
      printf_unfiltered ("nto_parse_notify(status) - subcmd %d\n",
			 recv.pkt.hdr.subcmd);
    }
  pid = nto_swap32 (recv.pkt.notify.pid);
  tid = nto_swap32 (recv.pkt.notify.tid);
  if (tid == 0)
    tid = 1;

  /* This was added for arm.  See arm_init_extra_frame_info()
     in arm-tdep.c.  arm_scan_prologue() causes a memory_error()
     if there is not a valid stack frame, and when the inferior
     is loaded, but has not started executing, the stack frame
     is invalid.  The default is to assume a stack frame, and
     this is set to 0 if we have a DSMSG_NOTIFY_PIDLOAD
     GP July 5, 2001.  */
  nto_target_has_stack_frame = 1;

  switch (recv.pkt.hdr.subcmd)
    {
    case DSMSG_NOTIFY_PIDUNLOAD:
      /* Added a new struct pidunload_v3 to the notify.un.  This includes a
         faulted flag so we can tell if the status value is a signo or an
         exit value.  See dsmsgs.h, protoverminor bumped to 3. GP Oct 31 2002.  */
      if ((TargetQNXProtoverMajor == 0) && (TargetQNXProtoverMinor >= 3))
	{
	  if (recv.pkt.notify.un.pidunload_v3.faulted)
	    {
	      status->value.integer =
		target_signal_from_nto (nto_swap32
					(recv.pkt.notify.un.pidunload_v3.
					 status));
	      if (status->value.integer)
		status->kind = TARGET_WAITKIND_SIGNALLED;	/* Abnormal death.  */
	      else
		status->kind = TARGET_WAITKIND_EXITED;	/* Normal death.  */
	    }
	  else
	    {
	      status->value.integer =
		nto_swap32 (recv.pkt.notify.un.pidunload_v3.status);
	      status->kind = TARGET_WAITKIND_EXITED;	/* Normal death, possibly with exit value.  */
	    }
	}
      else
	{
	  status->value.integer =
	    target_signal_from_nto (nto_swap32
				    (recv.pkt.notify.un.pidunload.status));
	  if (status->value.integer)
	    status->kind = TARGET_WAITKIND_SIGNALLED;	/* Abnormal death.  */
	  else
	    status->kind = TARGET_WAITKIND_EXITED;	/* Normal death.  */
	}
      target_has_execution = 0;
      target_has_stack = 0;
      target_has_registers = 0;
      nto_target_has_stack_frame = 0;
      break;
    case DSMSG_NOTIFY_BRK:
    case DSMSG_NOTIFY_STEP:
      /* NYI: could update the CPU's IP register here.  */
      status->kind = TARGET_WAITKIND_STOPPED;
      status->value.sig = TARGET_SIGNAL_TRAP;
      break;
    case DSMSG_NOTIFY_SIGEV:
      status->kind = TARGET_WAITKIND_STOPPED;
      status->value.sig =
	target_signal_from_nto (nto_swap32 (recv.pkt.notify.un.sigev.signo));
      break;
    case DSMSG_NOTIFY_PIDLOAD:
      nto_cputype = nto_swap16 (recv.pkt.notify.un.pidload.cputype);
      nto_cpuid = nto_swap32 (recv.pkt.notify.un.pidload.cpuid);
#ifdef QNX_SET_PROCESSOR_TYPE
      QNX_SET_PROCESSOR_TYPE (nto_cpuid);	/* For mips.  */
#endif
      target_has_execution = 1;
      target_has_stack = 1;
      target_has_registers = 1;
      nto_target_has_stack_frame = 0;
      if (target_created_hook)
	target_created_hook (pid);
      status->kind = TARGET_WAITKIND_LOADED;
      break;
    case DSMSG_NOTIFY_DLLLOAD:
    case DSMSG_NOTIFY_TIDLOAD:
    case DSMSG_NOTIFY_TIDUNLOAD:
    case DSMSG_NOTIFY_DLLUNLOAD:
      status->kind = TARGET_WAITKIND_SPURIOUS;
      break;
    case DSMSG_NOTIFY_STOPPED:
      status->kind = TARGET_WAITKIND_STOPPED;
      break;
    default:
      warning ("Unexpected notify type %d", recv.pkt.hdr.subcmd);
      break;
    }
  inferior_ptid = ptid_build (pid, tid, 0);
}

/* Fetch the regset, returning true if successful.  If supply is true,
   then supply these registers to gdb as well.  */
static int
fetch_regset (int regset, int supply)
{
  unsigned offset;
  int len;
  int rlen;

  len = nto_register_area (-1, regset, &offset);
  if (len < 1)
    return 0;

  nto_send_init (DStMsg_regrd, regset, SET_CHANNEL_DEBUG);
  tran.pkt.regrd.offset = nto_swap16 (0);	/* Always get whole set.  */
  tran.pkt.regrd.size = nto_swap16 (len);

  rlen = nto_send (sizeof (tran.pkt.regrd), 0);

  if (recv.pkt.hdr.cmd == DSrMsg_err)
    return 0;

/* FIXME: this i386 specific stuff should be taken out once we move
   to the new procnto which has a long enough structure to hold
   floating point registers.  */
  if (strcmp (TARGET_ARCHITECTURE->arch_name, "i386") == 0 &&
      regset == NTO_REG_FLOAT && rlen <= 128)
    {
      return 0;			/* Trying to get x86 fpregs from an old proc.  */
    }

  if (supply)
    nto_supply_regset (regset, recv.pkt.okdata.data);
  return 1;
}

/* Read register REGNO, or all registers if REGNO == -1, from the contents
   of REGISTERS.  */
void
nto_fetch_registers (int regno)
{
  int regset;

  if (nto_internal_debugging == 1)
    {
      printf_unfiltered ("nto_fetch_registers(regno %d)\n", regno);
    }

  if (ptid_equal (inferior_ptid, null_ptid))
    return;

  set_thread (ptid_get_tid (inferior_ptid));

  if (regno == -1)
    {				/* Get all regsets.  */
      for (regset = NTO_REG_GENERAL; regset < NTO_REG_END; regset++)
	{
	  fetch_regset (regset, 1);
	}
    }
  else
    {
      regset = nto_regset_id (regno);
      if (regset > -1 && regset < NTO_REG_END)
	fetch_regset (regset, 1);
    }
}

/* Prepare to store registers.  Don't have to do anything.  */
static void
nto_prepare_to_store ()
{
  if (nto_internal_debugging == 1)
    {
      printf_unfiltered ("nto_prepare_to_store()\n");
    }
}


/* Store register REGNO, or all registers if REGNO == -1, from the contents
   of REGISTERS.  */
void
nto_store_registers (int regno)
{
  int off, len, regset;

  if (nto_internal_debugging == 1)
    {
      printf_unfiltered ("nto_store_registers(regno %d)\n", regno);
    }

  if (ptid_equal (inferior_ptid, null_ptid))
    return;

  set_thread (ptid_get_tid (inferior_ptid));

  if (regno == -1)		/* Send them all.  */
    {
      for (regset = NTO_REG_GENERAL; regset < NTO_REG_END; regset++)
	{
	  len = nto_register_area (-1, regset, &off);
	  if (len < 1)
	    continue;

	  /* Fetch the regset and copy it to our outgoing data before we fill
	     it with gdb's registers.  This avoids the possibility of sending
	     garbage to the remote.  */
	  if (!fetch_regset (regset, 0))
	    continue;

	  memcpy (tran.pkt.regwr.data, recv.pkt.okdata.data,
		  sizeof (recv.pkt.okdata.data));

	  if (nto_regset_fill (regset, tran.pkt.regwr.data) == -1)
	    continue;

	  nto_send_init (DStMsg_regwr, regset, SET_CHANNEL_DEBUG);
	  tran.pkt.regwr.offset = 0;
	  nto_send (offsetof (DStMsg_regwr_t, data) + len, 1);
	}
      return;
    }

  /* Only sending one register.  */
  regset = nto_regset_id (regno);
  len = nto_register_area (regno, regset, &off);
  if (len < 1)			/* Don't know about this register.  */
    return;

  nto_send_init (DStMsg_regwr, regset, SET_CHANNEL_DEBUG);
  tran.pkt.regwr.offset = nto_swap16 (off);
  regcache_collect (regno, tran.pkt.regwr.data);
  nto_send (offsetof (DStMsg_regwr_t, data) + len, 1);
}

/* Use of the data cache *used* to be disabled because it loses for looking at
   and changing hardware I/O ports and the like.  Accepting `volatile'
   would perhaps be one way to fix it.  Another idea would be to use the
   executable file for the text segment (for all SEC_CODE sections?
   For all SEC_READONLY sections?).  This has problems if you want to
   actually see what the memory contains (e.g. self-modifying code,
   clobbered memory, user downloaded the wrong thing).

   Because it speeds so much up, it's now enabled, if you're playing
   with registers you turn it off (set remotecache 0).  */

/* Write memory data directly to the remote machine.
   This does not inform the data cache; the data cache uses this.
   MEMADDR is the address in the remote memory space.
   MYADDR is the address of the buffer in our space.
   LEN is the number of bytes.

   Returns number of bytes transferred, or 0 for error.  */
static int
nto_write_bytes (CORE_ADDR memaddr, char *myaddr, int len)
{
  long long addr;
  if (nto_internal_debugging == 1)
    {
      printf_unfiltered ("nto_write_bytes(to %llx, from %p, len %d)\n",
			 memaddr, myaddr, len);
    }

  /* NYI: need to handle requests bigger than largest allowed packet.  */
  nto_send_init (DStMsg_memwr, 0, SET_CHANNEL_DEBUG);
  addr = memaddr;
  tran.pkt.memwr.addr = nto_swap64 (addr);
  memcpy (tran.pkt.memwr.data, myaddr, len);
  nto_send (offsetof (DStMsg_memwr_t, data) + len, 0);

  switch (recv.pkt.hdr.cmd)
    {
    case DSrMsg_ok:
      return len;
    case DSrMsg_okstatus:
      return nto_swap32 (recv.pkt.okstatus.status);
    }
  return 0;
}

/* Read memory data directly from the remote machine.
   This does not use the data cache; the data cache uses this.
   MEMADDR is the address in the remote memory space.
   MYADDR is the address of the buffer in our space.
   LEN is the number of bytes.

   Returns number of bytes transferred, or 0 for error.  */
static int
nto_read_bytes (CORE_ADDR memaddr, char *myaddr, int len)
{
  int rcv_len, tot_len, ask_len;
  long long addr;

  if (nto_internal_debugging == 1)
    {
      printf_unfiltered ("nto_read_bytes(from %llx, to %p, len %d)\n",
			 memaddr, myaddr, len);
    }

  tot_len = rcv_len = ask_len = 0;

  /* NYI: Need to handle requests bigger than largest allowed packet.  */
  do
    {
      nto_send_init (DStMsg_memrd, 0, SET_CHANNEL_DEBUG);
      addr = memaddr + tot_len;
      tran.pkt.memrd.addr = nto_swap64 (addr);
      ask_len =
	((len - tot_len) >
	 DS_DATA_MAX_SIZE) ? DS_DATA_MAX_SIZE : (len - tot_len);
      tran.pkt.memrd.size = nto_swap16 (ask_len);
      rcv_len = nto_send (sizeof (tran.pkt.memrd), 0) - sizeof (recv.pkt.hdr);
      if (rcv_len <= 0)
	break;
      if (recv.pkt.hdr.cmd == DSrMsg_okdata)
	{
	  memcpy (myaddr + tot_len, recv.pkt.okdata.data, rcv_len);
	  tot_len += rcv_len;
	}
      else
	break;
    }
  while (tot_len != len);

  return (tot_len);
}

/* Read or write LEN bytes from inferior memory at MEMADDR, transferring
   to or from debugger address MYADDR.  Write to inferior if SHOULD_WRITE is
   nonzero.  Returns length of data written or read; 0 for error.  */
static int
nto_xfer_memory (CORE_ADDR memaddr, char *myaddr, int len, int should_write,
		 struct mem_attrib *attrib, struct target_ops *ignore)
{
  int res;
  if (nto_internal_debugging == 1)
    {
      printf_unfiltered
	("nto_xfer_memory(memaddr %llx, myaddr %p, len %d, should_write %d, target %p)\n",
	 memaddr, myaddr, len, should_write, ignore);
    }
  if (ptid_equal (inferior_ptid, null_ptid))
    {
      /* Pretend to read if no inferior but fail on write.  */
      if (should_write)
	return 0;
      memset (myaddr, 0, len);
      return len;
    }
  if (should_write)
    res = nto_write_bytes (memaddr, myaddr, len);
  else
    res = nto_read_bytes (memaddr, myaddr, len);
  return res;
}


static void
nto_files_info (struct target_ops *ignore)
{
  if (nto_internal_debugging == 1)
    {
      printf_unfiltered ("nto_files_info(ignore %p)\n", ignore);
    }
  puts_filtered ("Debugging a target over a serial line.\n");
}


static int
nto_kill_1 (char *dummy)
{
  if (nto_internal_debugging == 1)
    {
      printf_unfiltered ("nto_kill_1(dummy %p)\n", dummy);
    }

  if (!ptid_equal (inferior_ptid, null_ptid))
    {
      nto_send_init (DStMsg_kill, DSMSG_KILL_PID, SET_CHANNEL_DEBUG);
      tran.pkt.kill.signo = nto_swap32 (9);	/* SIGKILL */
      nto_send (sizeof (tran.pkt.kill), 0);
    }
  return 0;
}

static void
nto_kill ()
{
  if (nto_internal_debugging == 1)
    {
      printf_unfiltered ("nto_kill()\n");
    }

  /* Use catch_errors so the user can quit from gdb even when we aren't on
     speaking terms with the remote system.  */
  if (catch_errors
      ((catch_errors_ftype *) nto_kill_1, (char *) 0, "", RETURN_MASK_ERROR))
    target_mourn_inferior ();
}

static void
nto_mourn ()
{
  extern int show_breakpoint_hit_counts;

  if (nto_internal_debugging == 1)
    {
      printf_unfiltered ("nto_mourn()\n");
    }

  init_thread_list ();

  attach_flag = 0;
  breakpoint_init_inferior (inf_exited);
  registers_changed ();

  inferior_ptid = null_ptid;

  reopen_exec_file ();
  reinit_frame_cache ();

  /* It is confusing to the user for ignore counts to stick around
     from previous runs of the inferior.  So clear them.  However, it
     is more confusing for the ignore counts to disappear when using
     hit counts.  So don't clear them if we're counting hits.  */
  if (!show_breakpoint_hit_counts)
    breakpoint_clear_ignore_counts ();

}

int
nto_fd_raw (int fd)
{
  struct termios termios_p;

  if (tcgetattr (fd, &termios_p))
    return (-1);

  termios_p.c_cc[VMIN] = 1;
  termios_p.c_cc[VTIME] = 0;
  termios_p.c_lflag &= ~(ECHO | ICANON | ISIG | ECHOE | ECHOK | ECHONL);
  termios_p.c_oflag &= ~(OPOST);
  return (tcsetattr (fd, TCSADRAIN, &termios_p));
}

static void
nto_create (char *exec_file, char *args, char **env)
{
  unsigned argc;
  unsigned envc;
  char **start_argv, **argv, *p;
  int fd;
  struct target_waitstatus status;
  char *in, *out, *err;
  int len = 0;
  int totlen = 0;

  if (nto_remote_file && nto_remote_file[0] != '\0')
    {
      exec_file = nto_remote_file;
      fprintf_unfiltered (gdb_stdout, "Remote: %s\n", exec_file);
    }

  if (nto_desc == NULL)
    nto_open ("pty", 0);

  if (!ptid_equal (inferior_ptid, null_ptid))
    nto_semi_init ();

  if (nto_internal_debugging == 1)
    {
      printf_unfiltered ("nto_create(exec_file '%s', args '%s', environ)\n",
			 exec_file ? exec_file : "(null)",
			 args ? args : "(null)");
    }

  nto_send_init (DStMsg_env, DSMSG_ENV_CLEARENV, SET_CHANNEL_DEBUG);
  nto_send (sizeof (DStMsg_env_t), 1);

  if (!nto_inherit_env)
    {
      for (envc = 0; *env; env++, envc++)
	{
	  len = strlen (*env);
	  totlen = 0;
	  if (TargetQNXProtoverMinor >= 2)
	    {
	      if (len > DS_DATA_MAX_SIZE)
		{
		  while (len > DS_DATA_MAX_SIZE)
		    {
		      nto_send_init (DStMsg_env, DSMSG_ENV_SETENV_MORE,
				     SET_CHANNEL_DEBUG);
		      memcpy (tran.pkt.env.data, *env + totlen,
			      DS_DATA_MAX_SIZE);
		      nto_send (offsetof (DStMsg_env_t, data) +
				DS_DATA_MAX_SIZE, 1);
		      len -= DS_DATA_MAX_SIZE;
		      totlen += DS_DATA_MAX_SIZE;
		    }
		}
	    }
	  else if (len > DS_DATA_MAX_SIZE)
	    {
	      printf_unfiltered
		("** Skipping env var \"%.40s .....\" <cont>\n", *env);
	      printf_unfiltered
		("** Protovers under 0.2 do not handle env vars longer than %d\n",
		 DS_DATA_MAX_SIZE);
	      continue;
	    }
	  nto_send_init (DStMsg_env, DSMSG_ENV_SETENV, SET_CHANNEL_DEBUG);
	  strcpy (tran.pkt.env.data, *env + totlen);
	  nto_send (offsetof (DStMsg_env_t, data) +
		    strlen (tran.pkt.env.data) + 1, 1);
	}
    }

  if (nto_remote_cwd != NULL)
    {
      nto_send_init (DStMsg_cwd, DSMSG_CWD_SET, SET_CHANNEL_DEBUG);
      strcpy (tran.pkt.cwd.path, nto_remote_cwd);
      nto_send (offsetof (DStMsg_cwd_t, path) + strlen (tran.pkt.cwd.path) +
		1, 1);
    }

  nto_send_init (DStMsg_env, DSMSG_ENV_CLEARARGV, SET_CHANNEL_DEBUG);
  nto_send (sizeof (DStMsg_env_t), 1);

  start_argv = buildargv (args);
  if (start_argv == NULL)
    nomem (0);
  start_argv = nto_parse_redirection (start_argv, &in, &out, &err);

  if (in[0])
    {
      if ((fd = open (in, O_RDONLY)) == -1)
	perror (in);
      else
	nto_fd_raw (fd);
    }

  if (out[0])
    {
      if ((fd = open (out, O_WRONLY)) == -1)
	perror (out);
      else
	nto_fd_raw (fd);
    }

  if (err[0])
    {
      if ((fd = open (err, O_WRONLY)) == -1)
	perror (err);
      else
	nto_fd_raw (fd);
    }

  in = "";
  out = "";
  err = "";
  argc = 0;
  if (exec_file != NULL)
    {
      nto_send_init (DStMsg_env, DSMSG_ENV_ADDARG, SET_CHANNEL_DEBUG);
      strcpy (tran.pkt.env.data, exec_file);
      /* Send it twice - first as cmd, second as argv[0]. */
      nto_send (offsetof (DStMsg_env_t, data) + strlen (tran.pkt.env.data) +
		1, 1);
      nto_send_init (DStMsg_env, DSMSG_ENV_ADDARG, SET_CHANNEL_DEBUG);
      strcpy (tran.pkt.env.data, exec_file);
      nto_send (offsetof (DStMsg_env_t, data) + strlen (tran.pkt.env.data) +
		1, 1);
    }
  else if (*start_argv == NULL)
    {
      error ("No executable specified.");
      freeargv (start_argv);
      return;
    }
  else
    {
      if (symfile_objfile != NULL)
	exec_file_attach (symfile_objfile->name, 0);

      exec_file = *start_argv;
      nto_send_init (DStMsg_env, DSMSG_ENV_ADDARG, SET_CHANNEL_DEBUG);
      strcpy (tran.pkt.env.data, *start_argv);
      nto_send (offsetof (DStMsg_env_t, data) + strlen (tran.pkt.env.data) +
		1, 1);
    }

  for (argv = start_argv; *argv && **argv; argv++, argc++)
    {
      nto_send_init (DStMsg_env, DSMSG_ENV_ADDARG, SET_CHANNEL_DEBUG);
      strcpy (tran.pkt.env.data, *argv);
      nto_send (offsetof (DStMsg_env_t, data) + strlen (tran.pkt.env.data) +
		1, 1);
    }
  freeargv (start_argv);

  /* NYI: msg too big for buffer.  */
  if (nto_inherit_env)
    nto_send_init (DStMsg_load, DSMSG_LOAD_DEBUG | DSMSG_LOAD_INHERIT_ENV,
		   SET_CHANNEL_DEBUG);
  else
    nto_send_init (DStMsg_load, DSMSG_LOAD_DEBUG, SET_CHANNEL_DEBUG);

  p = tran.pkt.load.cmdline;

  tran.pkt.load.envc = 0;
  tran.pkt.load.argc = 0;

  strcpy (p, exec_file);
  p += strlen (p);
  *p++ = '\0';			/* load_file */

  strcpy (p, in);
  p += strlen (p);
  *p++ = '\0';			/* stdin */

  strcpy (p, out);
  p += strlen (p);
  *p++ = '\0';			/* stdout */

  strcpy (p, err);
  p += strlen (p);
  *p++ = '\0';			/* stderr */

  nto_send (offsetof (DStMsg_load_t, cmdline) + p - tran.pkt.load.cmdline + 1,
	    1);
  /* Comes back as an DSrMsg_okdata, but it's really a DShMsg_notify. */
  if (recv.pkt.hdr.cmd == DSrMsg_okdata)
    {
      nto_parse_notify (&status);
      add_thread (inferior_ptid);
    }

  /* NYI: add the symbol info somewhere? */
#ifdef SOLIB_CREATE_INFERIOR_HOOK
  if (exec_bfd)
    SOLIB_CREATE_INFERIOR_HOOK (pid);
#endif
  attach_flag = 0;
}

static int
nto_insert_breakpoint (CORE_ADDR addr, char *contents_cache)
{
  if (nto_internal_debugging == 1)
    {
      printf_unfiltered
	("nto_insert_breakpoint(addr %llx, contents_cache %p)\n", addr,
	 contents_cache);
    }

  nto_send_init (DStMsg_brk, DSMSG_BRK_EXEC, SET_CHANNEL_DEBUG);
  tran.pkt.brk.addr = nto_swap32 (addr);
  tran.pkt.brk.size = 0;
  nto_send (sizeof (tran.pkt.brk), 0);
  return recv.pkt.hdr.cmd == DSrMsg_err;
}

static int
nto_remove_breakpoint (CORE_ADDR addr, char *contents_cache)
{
  if (nto_internal_debugging == 1)
    {
      printf_unfiltered
	("nto_remove_breakpoint(addr %llx, contents_cache %p)\n", addr,
	 contents_cache);
    }

  /* This got changed to send DSMSG_BRK_EXEC with a size of -1
     nto_send_init(DStMsg_brk, DSMSG_BRK_REMOVE, SET_CHANNEL_DEBUG).  */
  nto_send_init (DStMsg_brk, DSMSG_BRK_EXEC, SET_CHANNEL_DEBUG);
  tran.pkt.brk.addr = nto_swap32 (addr);
  tran.pkt.brk.size = nto_swap32 (-1);
  nto_send (sizeof (tran.pkt.brk), 0);
  return recv.pkt.hdr.cmd == DSrMsg_err;
}

#ifdef __CYGWIN__
void
slashify (char *buf)
{
  int i = 0;
  while (buf[i])
    {
      /* Not sure why we would want to leave an escaped '\', but seems
         safer.  */
      if (buf[i] == '\\')
	{
	  if (buf[i + 1] == '\\')
	    i++;
	  else
	    buf[i] = '/';
	}
      i++;
    }
}
#endif

static void
upload_command (char *args, int fromtty)
{
#ifdef __CYGWIN__
  char cygbuf[PATH_MAX];
#endif
  int fd;
  int len;
  char buf[DS_DATA_MAX_SIZE];
  char *from, *to;
  char **argv;

  if (args == 0)
    {
      printf_unfiltered ("You must specify a filename to send.\n");
      return;
    }

#ifdef __CYGWIN__
  /* We need to convert back slashes to forward slashes for DOS
     style paths, else buildargv will remove them.  */
  slashify (args);
#endif
  argv = buildargv (args);

  if (argv == NULL)
    nomem (0);

#ifdef __CYGWIN__
  cygwin_conv_to_posix_path (argv[0], cygbuf);
  from = cygbuf;
#else
  from = argv[0];
#endif
  to = argv[1] ? argv[1] : from;

  if ((fd = open (from, HOST_READ_MODE)) == -1)
    {
      printf_unfiltered ("Unable to open '%s': %s\n", from, strerror (errno));
      return;
    }

  if (nto_fileopen (to, QNX_WRITE_MODE, QNX_WRITE_PERMS) == -1)
    {
      printf_unfiltered ("Remote was unable to open '%s': %s\n", to,
			 strerror (errno));
      close (fd);
      return;
    }

  while ((len = read (fd, buf, sizeof buf)) > 0)
    {
      if (nto_filewrite (buf, len) == -1)
	{
	  printf_unfiltered ("Remote was unable to complete write: %s\n",
			     strerror (errno));
	  goto exit;
	}
    }
  if (len == -1)
    {
      printf_unfiltered ("Local read failed: %s\n", strerror (errno));
      goto exit;
    }

  /* Everything worked so set remote exec file. */
  if (upload_sets_exec)
    {
      xfree (nto_remote_file);
      nto_remote_file = xstrdup (to);
    }

exit:
  nto_fileclose (fd);
  close (fd);
}

static void
download_command (char *args, int fromtty)
{
#ifdef __CYGWIN__
  char cygbuf[PATH_MAX];
#endif
  int fd;
  int len;
  char buf[DS_DATA_MAX_SIZE];
  char *from, *to;
  char **argv;

  if (args == 0)
    {
      printf_unfiltered ("You must specify a filename to get.\n");
      return;
    }

#ifdef __CYGWIN__
  slashify (args);
#endif

  argv = buildargv (args);
  if (argv == NULL)
    nomem (0);

  from = argv[0];
#ifdef __CYGWIN__
  if (argv[1])
    {
      cygwin_conv_to_posix_path (argv[1], cygbuf);
      to = cygbuf;
    }
  else
    to = from;
#else
  to = argv[1] ? argv[1] : from;
#endif

  if ((fd = open (to, HOST_WRITE_MODE, 0666)) == -1)
    {
      printf_unfiltered ("Unable to open '%s': %s\n", to, strerror (errno));
      return;
    }

  if (nto_fileopen (from, QNX_READ_MODE, 0) == -1)
    {
      printf_unfiltered ("Remote was unable to open '%s': %s\n", from,
			 strerror (errno));
      close (fd);
      return;
    }

  while ((len = nto_fileread (buf, sizeof buf)) > 0)
    {
      if (write (fd, buf, len) == -1)
	{
	  printf_unfiltered ("Local write failed: %s\n", strerror (errno));
	  close (fd);
	  return;
	}
    }

  if (len == -1)
    printf_unfiltered ("Remote read failed: %s\n", strerror (errno));
  nto_fileclose (fd);
  close (fd);
}

static void
nto_add_commands ()
{
  struct cmd_list_element *c;

  c =
    add_com ("upload", class_obscure, upload_command,
	     "Send a file to the target (upload {local} [{remote}])");
  c->completer = filename_completer;
  add_com ("download", class_obscure, download_command,
	   "Get a file from the target (download {remote} [{local}])");
}

static void
nto_remove_commands ()
{
  extern struct cmd_list_element *cmdlist;

  delete_cmd ("upload", &cmdlist);
  delete_cmd ("download", &cmdlist);
}

static int nto_remote_fd = -1;

static int
nto_fileopen (char *fname, int mode, int perms)
{
  if (nto_remote_fd != -1)
    {
      printf_unfiltered
	("Remote file currently open, it must be closed before you can open another.\n");
      errno = EAGAIN;
      return -1;
    }

  nto_send_init (DStMsg_fileopen, 0, SET_CHANNEL_DEBUG);
  strcpy (tran.pkt.fileopen.pathname, fname);
  tran.pkt.fileopen.mode = nto_swap32 (mode);
  tran.pkt.fileopen.perms = nto_swap32 (perms);
  nto_send (sizeof tran.pkt.fileopen, 0);

  if (recv.pkt.hdr.cmd == DSrMsg_err)
    {
      errno = nto_swap32 (recv.pkt.err.err);
      return -1;
    }
  return nto_remote_fd = 0;
}

static void
nto_fileclose (int fd)
{
  if (nto_remote_fd == -1)
    return;

  nto_send_init (DStMsg_fileclose, 0, SET_CHANNEL_DEBUG);
  tran.pkt.fileclose.mtime = 0;
  nto_send (sizeof tran.pkt.fileclose, 1);
  nto_remote_fd = -1;
}

static int
nto_fileread (char *buf, int size)
{
  int len;

  nto_send_init (DStMsg_filerd, 0, SET_CHANNEL_DEBUG);
  tran.pkt.filerd.size = nto_swap16 (size);
  len = nto_send (sizeof tran.pkt.filerd, 0);

  if (recv.pkt.hdr.cmd == DSrMsg_err)
    {
      errno = recv.pkt.err.err;
      return -1;
    }

  len -= sizeof recv.pkt.okdata.hdr;
  memcpy (buf, recv.pkt.okdata.data, len);
  return len;
}

static int
nto_filewrite (char *buf, int size)
{
  int len, siz;

  for (siz = size; siz > 0; siz -= len, buf += len)
    {
      len =
	siz < sizeof tran.pkt.filewr.data ? siz : sizeof tran.pkt.filewr.data;
      nto_send_init (DStMsg_filewr, 0, SET_CHANNEL_DEBUG);
      memcpy (tran.pkt.filewr.data, buf, len);
      nto_send (sizeof (tran.pkt.filewr.hdr) + len, 0);

      if (recv.pkt.hdr.cmd == DSrMsg_err)
	{
	  errno = recv.pkt.err.err;
	  return size - siz;
	}
    }
  return size;
}

static int
nto_can_run (void)
{
  return 0;
}

static void
init_nto_ops ()
{
  nto_ops.to_shortname = "qnx";
  nto_ops.to_longname =
    "Remote serial target using the QNX Debugging Protocol";
  nto_ops.to_doc =
    "Debug a remote machine using the QNX Debugging Protocol.\n\
Specify the device it is connected to (e.g. /dev/ser1, <rmt_host>:<port>)\n\
or `pty' to launch `pdebug' for debugging.";
  nto_ops.to_open = nto_open;
  nto_ops.to_close = nto_close;
  nto_ops.to_attach = nto_attach;
  nto_ops.to_post_attach = nto_post_attach;
  nto_ops.to_detach = nto_detach;
  nto_ops.to_resume = nto_resume;
  nto_ops.to_wait = nto_wait;
  nto_ops.to_fetch_registers = nto_fetch_registers;
  nto_ops.to_store_registers = nto_store_registers;
  nto_ops.to_prepare_to_store = nto_prepare_to_store;
  nto_ops.to_xfer_memory = nto_xfer_memory;
  nto_ops.to_files_info = nto_files_info;
  nto_ops.to_insert_breakpoint = nto_insert_breakpoint;
  nto_ops.to_remove_breakpoint = nto_remove_breakpoint;
  nto_ops.to_insert_hw_breakpoint = nto_insert_hw_breakpoint;
  nto_ops.to_remove_hw_breakpoint = nto_remove_breakpoint;
  nto_ops.to_insert_watchpoint = nto_insert_hw_watchpoint;
  nto_ops.to_remove_watchpoint = nto_remove_hw_watchpoint;
  nto_ops.to_stopped_by_watchpoint = nto_stopped_by_watchpoint;
  nto_ops.to_kill = nto_kill;
  nto_ops.to_load = generic_load;
  nto_ops.to_create_inferior = nto_create;
  nto_ops.to_mourn_inferior = nto_mourn;
  nto_ops.to_can_run = nto_can_run;
  nto_ops.to_thread_alive = nto_thread_alive;
  nto_ops.to_find_new_threads = nto_find_new_threads;
  nto_ops.to_stop = 0;
  /* nto_ops.to_query = nto_query; */
  nto_ops.to_stratum = process_stratum;
  nto_ops.to_has_all_memory = 1;
  nto_ops.to_has_memory = 1;
  nto_ops.to_has_stack = 0;
  nto_ops.to_has_registers = 1;
  nto_ops.to_has_execution = 0;
  nto_ops.to_pid_to_str = nto_pid_to_str;
  /* nto_ops.to_has_thread_control = tc_schedlock; *//* can lock scheduler */
  nto_ops.to_magic = OPS_MAGIC;
  nto_ops.to_have_continuable_watchpoint = 1;
}

void
nto_find_new_threads (void)
{
  pid_t pid, start_tid, total_tid;
  ptid_t ptid;
  struct dspidlist *pidlist = (void *) recv.pkt.okdata.data;
  struct tidinfo *tip;
  char subcmd;

  pid = ptid_get_pid (inferior_ptid);
  start_tid = 1;
  total_tid = 1;
  subcmd = DSMSG_PIDLIST_SPECIFIC_TID;

  do
    {
      tran.pkt.pidlist.tid = nto_swap32 (start_tid);
      nto_send_init (DStMsg_pidlist, subcmd, SET_CHANNEL_DEBUG);
      tran.pkt.pidlist.pid = nto_swap32 (pid);
      nto_send (sizeof (tran.pkt.pidlist), 0);

      if (recv.pkt.hdr.cmd == DSrMsg_err)
	{
	  if (subcmd == DSMSG_PIDLIST_SPECIFIC_TID)
	    {
	      subcmd = DSMSG_PIDLIST_SPECIFIC;
	      start_tid = 0;
	      tran.pkt.pidlist.tid = nto_swap32 (start_tid);
	      nto_send_init (DStMsg_pidlist, subcmd, SET_CHANNEL_DEBUG);
	      tran.pkt.pidlist.pid = nto_swap32 (pid);
	      nto_send (sizeof (tran.pkt.pidlist), 1);	/* No need to check error, as '1' means no return on error.  */
	    }
	  else
	    {
	      errno = recv.pkt.err.err;
	      return;
	    }
	}
      if (nto_internal_debugging == 1)
	{
	  printf_unfiltered ("pid = %ld\n", nto_swap32 (pidlist->pid));
	  printf_unfiltered ("start tid = %ld, total tid = %ld\n",
			     nto_swap32 (start_tid),
			     nto_swap32 (pidlist->num_tids));
	  printf_unfiltered ("name = %s\n", pidlist->name);
	}

      for (tip =
	   (void *) &pidlist->name[(strlen (pidlist->name) + 1 + 3) & ~3];
	   tip->tid != 0; tip++)
	{
	  total_tid++;
	  ptid = ptid_build (pid, 0, nto_swap16 (tip->tid));
	  if (nto_internal_debugging == 1)
	    {
	      printf_unfiltered ("%s - %d/%d\n", pidlist->name, pid,
				 nto_swap16 (tip->tid));
	    }
	  if (!in_thread_list (ptid))
	    add_thread (ptid);
	}
      start_tid = total_tid + 1;
      if (nto_internal_debugging == 1)
	{
	  printf_unfiltered ("total_tids = %x, pidlist->num_tids = %lx\n",
			     total_tid, nto_swap32 (pidlist->num_tids));
	}
    }
  while ((total_tid < nto_swap32 (pidlist->num_tids))
	 && (subcmd == DSMSG_PIDLIST_SPECIFIC_TID));

  return;
}


void
nto_pidlist (char *args, int from_tty)
{
  struct dspidlist *pidlist = (void *) recv.pkt.okdata.data;
  struct tidinfo *tip;
  char specific_tid_supported = 0;
  pid_t pid, start_tid, total_tid;
  char subcmd;

  start_tid = 1;
  total_tid = 0;
  pid = 1;
  subcmd = DSMSG_PIDLIST_BEGIN;

  /* Send a DSMSG_PIDLIST_SPECIFIC_TID to see if it is supported.  */
  nto_send_init (DStMsg_pidlist, DSMSG_PIDLIST_SPECIFIC_TID,
		 SET_CHANNEL_DEBUG);
  tran.pkt.pidlist.pid = nto_swap32 (pid);
  tran.pkt.pidlist.tid = nto_swap32 (start_tid);
  nto_send (sizeof (tran.pkt.pidlist), 0);

  if (recv.pkt.hdr.cmd == DSrMsg_err)
    specific_tid_supported = 0;
  else
    specific_tid_supported = 1;

  while (1)
    {
      nto_send_init (DStMsg_pidlist, subcmd, SET_CHANNEL_DEBUG);
      tran.pkt.pidlist.pid = nto_swap32 (pid);
      tran.pkt.pidlist.tid = nto_swap32 (start_tid);
      nto_send (sizeof (tran.pkt.pidlist), 0);
      if (recv.pkt.hdr.cmd == DSrMsg_err)
	{
	  errno = nto_swap32 (recv.pkt.err.err);
	  return;
	}
      if (recv.pkt.hdr.cmd != DSrMsg_okdata)
	{
	  errno = EOK;
	  return;
	}

      for (tip =
	   (void *) &pidlist->name[(strlen (pidlist->name) + 1 + 3) & ~3];
	   tip->tid != 0; tip++)
	{
	  printf_filtered ("%s - %ld/%d\n", pidlist->name,
			   nto_swap32 (pidlist->pid), nto_swap16 (tip->tid));
	  total_tid++;
	}
      pid = nto_swap32 (pidlist->pid);
      if (specific_tid_supported)
	{
	  if (total_tid < nto_swap32 (pidlist->num_tids))
	    {
	      subcmd = DSMSG_PIDLIST_SPECIFIC_TID;
	      start_tid = total_tid + 1;
	      continue;
	    }
	}
      start_tid = 1;
      total_tid = 0;
      subcmd = DSMSG_PIDLIST_NEXT;
    }
  return;
}

struct dsmapinfo *
nto_mapinfo (unsigned addr, int first, int elfonly)
{
  struct dsmapinfo map;
  static struct dsmapinfo dmap;
  DStMsg_mapinfo_t *mapinfo = (DStMsg_mapinfo_t *) & tran.pkt;
  char subcmd;

  if (core_bfd != NULL)
    {				/* Have to implement corefile mapinfo.  */
      errno = EOK;
      return NULL;
    }

  subcmd = addr ? DSMSG_MAPINFO_SPECIFIC :
    first ? DSMSG_MAPINFO_BEGIN : DSMSG_MAPINFO_NEXT;
  if (elfonly)
    subcmd |= DSMSG_MAPINFO_ELF;

  nto_send_init (DStMsg_mapinfo, subcmd, SET_CHANNEL_DEBUG);
  mapinfo->addr = nto_swap32 (addr);
  nto_send (sizeof (*mapinfo), 0);
  if (recv.pkt.hdr.cmd == DSrMsg_err)
    {
      errno = nto_swap32 (recv.pkt.err.err);
      return NULL;
    }
  if (recv.pkt.hdr.cmd != DSrMsg_okdata)
    {
      errno = EOK;
      return NULL;
    }

  memset (&dmap, 0, sizeof (dmap));
  memcpy (&map, &recv.pkt.okdata.data[0], sizeof (map));
  dmap.ino = nto_swap64 (map.ino);
  dmap.dev = nto_swap32 (map.dev);

  dmap.text.addr = nto_swap32 (map.text.addr);
  dmap.text.size = nto_swap32 (map.text.size);
  dmap.text.flags = nto_swap32 (map.text.flags);
  dmap.text.debug_vaddr = nto_swap32 (map.text.debug_vaddr);
  dmap.text.offset = nto_swap64 (map.text.offset);

  dmap.data.addr = nto_swap32 (map.data.addr);
  dmap.data.size = nto_swap32 (map.data.size);
  dmap.data.flags = nto_swap32 (map.data.flags);
  dmap.data.debug_vaddr = nto_swap32 (map.data.debug_vaddr);
  dmap.data.offset = nto_swap64 (map.data.offset);

  strcpy (dmap.name, map.name);

  return &dmap;
}

void
nto_meminfo (char *args, int from_tty)
{
  struct dsmapinfo *dmp;
  int first = 1;

  while ((dmp = nto_mapinfo (0, first, 0)) != NULL)
    {
      first = 0;
      printf_filtered ("%s\n", dmp->name);
      printf_filtered ("\ttext=%08x bytes @ 0x%08x\n", dmp->text.size,
		       dmp->text.addr);
      printf_filtered ("\t\tflags=%08x\n", dmp->text.flags);
      printf_filtered ("\t\tdebug=%08x\n", dmp->text.debug_vaddr);
      printf_filtered ("\t\toffset=%016llx\n", dmp->text.offset);
      if (dmp->data.size)
	{
	  printf_filtered ("\tdata=%08x bytes @ 0x%08x\n", dmp->data.size,
			   dmp->data.addr);
	  printf_filtered ("\t\tflags=%08x\n", dmp->data.flags);
	  printf_filtered ("\t\tdebug=%08x\n", dmp->data.debug_vaddr);
	  printf_filtered ("\t\toffset=%016llx\n", dmp->data.offset);
	}
      printf_filtered ("\tdev=0x%x\n", dmp->dev);
      printf_filtered ("\tino=0x%llx\n", dmp->ino);
    }
}

void
_initialize_nto ()
{
  int endian = 1;

  if (*(char *) &endian != 1)
    host_endian = BFD_ENDIAN_BIG;
  else
    host_endian = BFD_ENDIAN_LITTLE;

  init_nto_ops ();
  add_target (&nto_ops);
  add_show_from_set (add_set_cmd ("qnxtimeout", no_class,
				  var_integer, (char *) &nto_timeout,
				  "Set timeout value for remote read.\n",
				  &setlist), &showlist);

  add_show_from_set (add_set_cmd ("qnxinheritenv", no_class,
				  var_boolean, (char *) &nto_inherit_env,
				  "Set where remote process inherits env from pdebug, or has it set by gdb\n",
				  &setlist), &showlist);

  add_show_from_set (add_set_cmd ("qnxremotecwd", class_support, var_string,
				  (char *) &nto_remote_cwd,
				  "Set the working directory for the remote process",
				  &setlist), &showlist);

  add_setshow_cmd ("nto-remote-file", class_files, var_string,
		   &nto_remote_file, "Set the remote file to be executed \
when a user issues the 'run'\ncommand to a QNX \
Neutrino remote target.\n", "Show the file to be executed on the remote\n\
QNX Neutrino target.\n", NULL, NULL, &setlist, &showlist);

  add_setshow_cmd ("upload-sets-exec", class_files, var_integer,
		   &upload_sets_exec,
		   "If set, upload will set nto_remote_file.\n",
		   "Show the flag for upload to set nto_remote_file.\n", NULL,
		   NULL, &setlist, &showlist);

  add_info ("pidlist", nto_pidlist, "pidlist");
  add_info ("meminfo", nto_meminfo, "memory information");
}

static int
nto_insert_hw_breakpoint (CORE_ADDR addr, char *contents_cache)
{
  if (nto_desc == NULL)
    return -1;

  if (nto_internal_debugging == 1)
    {
      printf_unfiltered
	("nto_insert_hw_breakpoint(addr %llx, contents_cache %p)\n", addr,
	 contents_cache);
    }

  nto_send_init (DStMsg_brk, DSMSG_BRK_EXEC | DSMSG_BRK_HW,
		 SET_CHANNEL_DEBUG);
  tran.pkt.brk.addr = nto_swap32 (addr);
  nto_send (sizeof (tran.pkt.brk), 0);
  return recv.pkt.hdr.cmd == DSrMsg_err;
}

static int
nto_stopped_by_watchpoint (void)
{
  return 0;
}

static int
nto_hw_watchpoint (CORE_ADDR addr, int len, int type)
{
  unsigned subcmd;

  if (nto_internal_debugging == 1)
    {
      printf_unfiltered ("nto_hw_watchpoint(addr %llx, len %x, type %x)\n",
			 addr, len, type);
    }

  switch (type)
    {
    case 1:			/* Read.  */
      subcmd = DSMSG_BRK_RD;
      break;
    case 2:			/* Read/Write.  */
      subcmd = DSMSG_BRK_WR;
      break;
    default:			/* Modify.  */
      subcmd = DSMSG_BRK_MODIFY;
    }
  subcmd |= DSMSG_BRK_HW;

  nto_send_init (DStMsg_brk, subcmd, SET_CHANNEL_DEBUG);
  tran.pkt.brk.addr = nto_swap32 (addr);
  tran.pkt.brk.size = nto_swap32 (len);
  nto_send (sizeof (tran.pkt.brk), 0);
  return recv.pkt.hdr.cmd == DSrMsg_err ? -1 : 0;
}

static int
nto_remove_hw_watchpoint (CORE_ADDR addr, int len, int type)
{
  return nto_hw_watchpoint (addr, -1, type);
}

static int
nto_insert_hw_watchpoint (CORE_ADDR addr, int len, int type)
{
  return nto_hw_watchpoint (addr, len, type);
}

static struct tidinfo *
nto_thread_info (pid_t pid, short tid)
{
  struct dspidlist *pidlist = (void *) recv.pkt.okdata.data;
  struct tidinfo *tip;

  tran.pkt.pidlist.tid = tid;
  nto_send_init (DStMsg_pidlist, DSMSG_PIDLIST_SPECIFIC_TID,
		 SET_CHANNEL_DEBUG);
  tran.pkt.pidlist.pid = nto_swap32 (pid);
  nto_send (sizeof (tran.pkt.pidlist), 0);

  if (recv.pkt.hdr.cmd == DSrMsg_err)
    {
      nto_send_init (DStMsg_pidlist, DSMSG_PIDLIST_SPECIFIC,
		     SET_CHANNEL_DEBUG);
      tran.pkt.pidlist.pid = nto_swap32 (pid);
      nto_send (sizeof (tran.pkt.pidlist), 1);
      if (recv.pkt.hdr.cmd == DSrMsg_err)
	{
	  errno = recv.pkt.err.err;
	  return NULL;
	}
    }

  for (tip = (void *) &pidlist->name[(strlen (pidlist->name) + 1 + 3) & ~3];
       tip->tid != 0; tip++)
    {
      if (tid == nto_swap16 (tip->tid))
	return tip;
    }

  return NULL;
}

char *
nto_pid_to_str (ptid_t ptid)
{
  static char buf[1024];
  int pid, tid, n;
  struct tidinfo *tip;

  pid = ptid_get_pid (ptid);
  tid = ptid_get_tid (ptid);

  n = sprintf (buf, "process %d", pid);

  tip = nto_thread_info (pid, tid);
  if (tip != NULL)
    sprintf (&buf[n], " (state = 0x%02x)", tip->state);

  return buf;
}

#ifndef __QNXNTO__

#define QNXSIGHUP      1	/* Hangup.  */
#define QNXSIGINT      2	/* Interrupt.  */
#define QNXSIGQUIT     3	/* Quit.  */
#define QNXSIGILL      4	/* Illegal instruction (not reset when caught).  */
#define QNXSIGTRAP     5	/* Trace trap (not reset when caught).  */
#define QNXSIGIOT      6	/* IOT instruction.  */
#define QNXSIGABRT     6	/* Used by abort.  */
#define QNXSIGEMT      7	/* EMT instruction.  */
#define QNXSIGDEADLK   7	/* Mutex deadlock.  */
#define QNXSIGFPE      8	/* Floating point exception.  */
#define QNXSIGKILL     9	/* Kill (cannot be caught or ignored).  */
#define QNXSIGBUS      10	/* Bus error.  */
#define QNXSIGSEGV     11	/* Segmentation violation.  */
#define QNXSIGSYS      12	/* Bad argument to system call.  */
#define QNXSIGPIPE     13	/* Write on pipe with no reader.  */
#define QNXSIGALRM     14	/* Real-time alarm clock.  */
#define QNXSIGTERM     15	/* Software termination signal from kill.  */
#define QNXSIGUSR1     16	/* User defined signal 1.  */
#define QNXSIGUSR2     17	/* User defined signal 2.  */
#define QNXSIGCHLD     18	/* Death of child.  */
#define QNXSIGPWR      19	/* Power-fail restart.  */
#define QNXSIGWINCH    20	/* Window change.  */
#define QNXSIGURG      21	/* Urgent condition on I/O channel.  */
#define QNXSIGPOLL     22	/* System V name for QNXSIGIO.  */
#define QNXSIGIO       QNXSIGPOLL
#define QNXSIGSTOP     23	/* Sendable stop signal not from tty.  */
#define QNXSIGTSTP     24	/* Stop signal from tty.  */
#define QNXSIGCONT     25	/* Continue a stopped process.  */
#define QNXSIGTTIN     26	/* Attempted background tty read.  */
#define QNXSIGTTOU     27	/* Attempted background tty write.  */
#define QNXSIGVTALRM   28	/* Virtual timer expired.  */
#define QNXSIGPROF     29	/* Profileing timer expired.  */
#define QNXSIGXCPU     30	/* Exceded cpu limit.  */
#define QNXSIGXFSZ     31	/* Exceded file size limit.  */

#endif

/* Convert nto signal to gdb signal.  */
enum target_signal
target_signal_from_nto (int sig)
{
#ifndef __QNXNTO__
  switch (sig)
    {
    case 0:
      return 0;
      break;
    case QNXSIGHUP:
      return TARGET_SIGNAL_HUP;
      break;
    case QNXSIGINT:
      return TARGET_SIGNAL_INT;
      break;
    case QNXSIGQUIT:
      return TARGET_SIGNAL_QUIT;
      break;
    case QNXSIGILL:
      return TARGET_SIGNAL_ILL;
      break;
    case QNXSIGTRAP:
      return TARGET_SIGNAL_TRAP;
      break;
    case QNXSIGABRT:
      return TARGET_SIGNAL_ABRT;
      break;
    case QNXSIGEMT:
      return TARGET_SIGNAL_EMT;
      break;
    case QNXSIGFPE:
      return TARGET_SIGNAL_FPE;
      break;
    case QNXSIGKILL:
      return TARGET_SIGNAL_KILL;
      break;
    case QNXSIGBUS:
      return TARGET_SIGNAL_BUS;
      break;
    case QNXSIGSEGV:
      return TARGET_SIGNAL_SEGV;
      break;
    case QNXSIGSYS:
      return TARGET_SIGNAL_SYS;
      break;
    case QNXSIGPIPE:
      return TARGET_SIGNAL_PIPE;
      break;
    case QNXSIGALRM:
      return TARGET_SIGNAL_ALRM;
      break;
    case QNXSIGTERM:
      return TARGET_SIGNAL_TERM;
      break;
    case QNXSIGUSR1:
      return TARGET_SIGNAL_USR1;
      break;
    case QNXSIGUSR2:
      return TARGET_SIGNAL_USR2;
      break;
    case QNXSIGCHLD:
      return TARGET_SIGNAL_CHLD;
      break;
    case QNXSIGPWR:
      return TARGET_SIGNAL_PWR;
      break;
    case QNXSIGWINCH:
      return TARGET_SIGNAL_WINCH;
      break;
    case QNXSIGURG:
      return TARGET_SIGNAL_URG;
      break;
    case QNXSIGPOLL:
      return TARGET_SIGNAL_POLL;
      break;
/*      case QNXSIGIO: return TARGET_SIGNAL_IO; break; */
    case QNXSIGSTOP:
      return TARGET_SIGNAL_STOP;
      break;
    case QNXSIGTSTP:
      return TARGET_SIGNAL_TSTP;
      break;
    case QNXSIGCONT:
      return TARGET_SIGNAL_CONT;
      break;
    case QNXSIGTTIN:
      return TARGET_SIGNAL_TTIN;
      break;
    case QNXSIGTTOU:
      return TARGET_SIGNAL_TTOU;
      break;
    case QNXSIGVTALRM:
      return TARGET_SIGNAL_VTALRM;
      break;
    case QNXSIGPROF:
      return TARGET_SIGNAL_PROF;
      break;
    case QNXSIGXCPU:
      return TARGET_SIGNAL_XCPU;
      break;
    case QNXSIGXFSZ:
      return TARGET_SIGNAL_XFSZ;
      break;
    default:
      break;
    }
#endif /* __QNXNTO__ */
  return target_signal_from_host (sig);
}


/* Convert gdb signal to nto signal.  */
enum target_signal
target_signal_to_nto (int sig)
{
#ifndef __QNXNTO__
  switch (sig)
    {
    case 0:
      return 0;
      break;
    case TARGET_SIGNAL_HUP:
      return QNXSIGHUP;
      break;
    case TARGET_SIGNAL_INT:
      return QNXSIGINT;
      break;
    case TARGET_SIGNAL_QUIT:
      return QNXSIGQUIT;
      break;
    case TARGET_SIGNAL_ILL:
      return QNXSIGILL;
      break;
    case TARGET_SIGNAL_TRAP:
      return QNXSIGTRAP;
      break;
    case TARGET_SIGNAL_ABRT:
      return QNXSIGABRT;
      break;
    case TARGET_SIGNAL_EMT:
      return QNXSIGEMT;
      break;
    case TARGET_SIGNAL_FPE:
      return QNXSIGFPE;
      break;
    case TARGET_SIGNAL_KILL:
      return QNXSIGKILL;
      break;
    case TARGET_SIGNAL_BUS:
      return QNXSIGBUS;
      break;
    case TARGET_SIGNAL_SEGV:
      return QNXSIGSEGV;
      break;
    case TARGET_SIGNAL_SYS:
      return QNXSIGSYS;
      break;
    case TARGET_SIGNAL_PIPE:
      return QNXSIGPIPE;
      break;
    case TARGET_SIGNAL_ALRM:
      return QNXSIGALRM;
      break;
    case TARGET_SIGNAL_TERM:
      return QNXSIGTERM;
      break;
    case TARGET_SIGNAL_USR1:
      return QNXSIGUSR1;
      break;
    case TARGET_SIGNAL_USR2:
      return QNXSIGUSR2;
      break;
    case TARGET_SIGNAL_CHLD:
      return QNXSIGCHLD;
      break;
    case TARGET_SIGNAL_PWR:
      return QNXSIGPWR;
      break;
    case TARGET_SIGNAL_WINCH:
      return QNXSIGWINCH;
      break;
    case TARGET_SIGNAL_URG:
      return QNXSIGURG;
      break;
    case TARGET_SIGNAL_IO:
      return QNXSIGIO;
      break;
    case TARGET_SIGNAL_POLL:
      return QNXSIGPOLL;
      break;
    case TARGET_SIGNAL_STOP:
      return QNXSIGSTOP;
      break;
    case TARGET_SIGNAL_TSTP:
      return QNXSIGTSTP;
      break;
    case TARGET_SIGNAL_CONT:
      return QNXSIGCONT;
      break;
    case TARGET_SIGNAL_TTIN:
      return QNXSIGTTIN;
      break;
    case TARGET_SIGNAL_TTOU:
      return QNXSIGTTOU;
      break;
    case TARGET_SIGNAL_VTALRM:
      return QNXSIGVTALRM;
      break;
    case TARGET_SIGNAL_PROF:
      return QNXSIGPROF;
      break;
    case TARGET_SIGNAL_XCPU:
      return QNXSIGXCPU;
      break;
    case TARGET_SIGNAL_XFSZ:
      return QNXSIGXFSZ;
      break;
    default:
      break;
    }
#endif /* __QNXNTO__ */
  return target_signal_to_host (sig);
}
