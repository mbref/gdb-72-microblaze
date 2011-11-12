/* GNU/Linux on ARM native support.
   Copyright (C) 1999, 2000, 2001, 2002, 2004, 2005, 2006, 2007, 2008, 2009,
   2010 Free Software Foundation, Inc.

   This file is part of GDB.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

#include <elf/common.h>
#include <sys/user.h>
#include <sys/ptrace.h>
#include <sys/utsname.h>
#include <sys/procfs.h>

#include "defs.h"
#include "arch-utils.h"
#include "dis-asm.h"
#include "frame.h"
#include "trad-frame.h"
#include "symtab.h"
#include "value.h"
#include "gdbcmd.h"
#include "breakpoint.h"
#include "inferior.h"
#include "regcache.h"
#include "target.h"
#include "frame.h"
#include "frame-base.h"
#include "frame-unwind.h"
#include "dwarf2-frame.h"
#include "osabi.h"

#include "gdb_assert.h"
#include "gdb_string.h"
#include "target-descriptions.h"
#include "opcodes/microblaze-opcm.h"
#include "opcodes/microblaze-dis.h"
#include "microblaze-tdep.h"

#include "linux-nat.h"
#include "microblaze-linux-nat.h"
#include "target-descriptions.h"
#include "auxv.h"

#include "microblaze-tdep.h"

/* Prototypes for supply_gregset etc. */
#include "gregset.h"

/* Defines ps_err_e, struct ps_prochandle.  */
#include "gdb_proc_service.h"

#ifndef PTRACE_GET_THREAD_AREA
#define PTRACE_GET_THREAD_AREA 22
#endif

/* The following variables are used to determine the version of the
   underlying GNU/Linux operating system.  Examples:

   GNU/Linux 2.0.35             GNU/Linux 2.2.12
   os_version = 0x00020023      os_version = 0x0002020c
   os_major = 2                 os_major = 2
   os_minor = 0                 os_minor = 2
   os_release = 35              os_release = 12

   Note: os_version = (os_major << 16) | (os_minor << 8) | os_release

   These are initialized using get_linux_version() from
   _initialize_microblaze_linux_nat().  */

static unsigned int os_version, os_major, os_minor, os_release;

/* On GNU/Linux, threads are implemented as pseudo-processes, in which
   case we may be tracing more than one process at a time.  In that
   case, inferior_ptid will contain the main process ID and the
   individual thread (process) ID.  get_thread_id () is used to get
   the thread id if it's available, and the process id otherwise.  */

int
get_thread_id (ptid_t ptid)
{
  int tid = TIDGET (ptid);
  if (0 == tid)
    tid = PIDGET (ptid);
  return tid;
}

#define GET_THREAD_ID(PTID)	get_thread_id (PTID)

/* Fetch a general register of the process and store into
   regcache.  */

static void
fetch_register (struct regcache *regcache, int regno)
{

  int ret, tid;
  elf_gregset_t regs;

  /* Get the thread id for the ptrace call.  */
  tid = GET_THREAD_ID (inferior_ptid);
  
  ret = ptrace (PTRACE_GETREGS, tid, 0, &regs);
  if (ret < 0)
    {
      warning (_("Unable to fetch general register."));
      return;
    } else {
//      warning (_("GOT general registers."));
    }

  /* Retrieve the general purpose registers */
  if (regno >= MICROBLAZE_R0_REGNUM && regno <= MICROBLAZE_FSR_REGNUM) {
    regs[regno] = gdbarch_addr_bits_remove
                              (get_regcache_arch (regcache),
                               regs[regno]);
    regcache_raw_supply (regcache, regno, (char *) &regs[regno]);
  }

  /* Processor status register */
     /* Not yet implemented */
 
  /* Processor counter register */ 
/* PC should be grabbed above. PC is reg 32, FSR is reg 37 relative to index 0
  if (MICROBLAZE_FSR_REGNUM == regno)
    { 
      regs[MICROBLAZE_PC_REGNUM] = gdbarch_addr_bits_remove
			      (get_regcache_arch (regcache),
			       regs[MICROBLAZE_PC_REGNUM]);
      regcache_raw_supply (regcache, MICROBLAZE_PC_REGNUM,
			   (char *) &regs[MICROBLAZE_PC_REGNUM]);
    }
*/
}

/* Fetch all general registers of the process and store into
   regcache.  */

static void
fetch_regs (struct regcache *regcache)
{

  int ret, regno, tid;
  elf_gregset_t regs;

  /* Get the thread id for the ptrace call.  */
  tid = GET_THREAD_ID (inferior_ptid);
  
  ret = ptrace (PTRACE_GETREGS, tid, 0, &regs);
  if (ret < 0)
    {
      warning (_("Unable to fetch general registers."));
      return;
    } else {
//      warning (_("GOT general registers."));
    }

  for (regno = MICROBLAZE_R0_REGNUM; regno <= MICROBLAZE_FSR_REGNUM; regno++)
    regcache_raw_supply (regcache, regno, (char *) &regs[regno]);

  regs[MICROBLAZE_FSR_REGNUM] = gdbarch_addr_bits_remove
			  (get_regcache_arch (regcache), regs[MICROBLAZE_FSR_REGNUM]);
  regcache_raw_supply (regcache, MICROBLAZE_FSR_REGNUM,
		       (char *) &regs[MICROBLAZE_FSR_REGNUM]);
}

/* Store all general registers of the process from the values in
   regcache.  */

static void
store_register (const struct regcache *regcache, int regno)
{

  int ret, tid;
  elf_gregset_t regs;
  
  if (!regcache_valid_p (regcache, regno))
    return;

  /* Get the thread id for the ptrace call.  */
  tid = GET_THREAD_ID (inferior_ptid);
  
  /* Get the general registers from the process.  */
  ret = ptrace (PTRACE_GETREGS, tid, 0, &regs);
  if (ret < 0)
    {
      warning (_("Unable to fetch general registers."));
      return;
    }

  if (regno >= MICROBLAZE_R0_REGNUM && regno <= MICROBLAZE_FSR_REGNUM)
    regcache_raw_collect (regcache, regno, (char *) &regs[regno]);

  ret = ptrace (PTRACE_SETREGS, tid, 0, &regs);
  if (ret < 0)
    {
      warning (_("Unable to store general register."));
      return;
    }
}

static void
store_regs (const struct regcache *regcache)
{

  int ret, regno, tid;
  elf_gregset_t regs;

  /* Get the thread id for the ptrace call.  */
  tid = GET_THREAD_ID (inferior_ptid);
  
  /* Fetch the general registers.  */
  ret = ptrace (PTRACE_GETREGS, tid, 0, &regs);
  if (ret < 0)
    {
      warning (_("Unable to fetch general registers."));
      return;
    }

  for (regno = MICROBLAZE_R0_REGNUM; regno <= MICROBLAZE_FSR_REGNUM; regno++)
    {
      if (regcache_valid_p (regcache, regno))
	regcache_raw_collect (regcache, regno, (char *) &regs[regno]);
    }

  ret = ptrace (PTRACE_SETREGS, tid, 0, &regs);

  if (ret < 0)
    {
      warning (_("Unable to store general registers."));
      return;
    }
}

/* Fetch registers from the child process.  Fetch all registers if
   regno == -1, otherwise fetch all general registers or all floating
   point registers depending upon the value of regno.  */

static void
microblaze_linux_fetch_inferior_registers (struct target_ops *ops,
				    struct regcache *regcache, int regno)
{
  if (-1 == regno)
    {
      fetch_regs (regcache);
    }
  else 
    {
      if ((regno >= MICROBLAZE_R0_REGNUM && regno <= MICROBLAZE_PC_REGNUM))
        fetch_register (regcache, regno);
    }
}

/* Store registers back into the inferior.  Store all registers if
   regno == -1, otherwise store all general registers or all floating
   point registers depending upon the value of regno.  */

static void
microblaze_linux_store_inferior_registers (struct target_ops *ops,
				    struct regcache *regcache, int regno)
{
  if (-1 == regno)
    {
      store_regs (regcache);
    }
  else
    {
      if ((regno >= MICROBLAZE_R0_REGNUM && regno <= MICROBLAZE_PC_REGNUM))
        store_register (regcache, regno);
    }
}

/* Wrapper functions for the standard regset handling, used by
   thread debugging.  */

void
fill_gregset (const struct regcache *regcache,	
	      gdb_gregset_t *gregsetp, int regno)
{
  microblaze_linux_collect_gregset (NULL, regcache, regno, gregsetp, 0);
}

void
supply_gregset (struct regcache *regcache, const gdb_gregset_t *gregsetp)
{
  microblaze_linux_supply_gregset (NULL, regcache, -1, gregsetp, 0);
}

void
fill_fpregset (const struct regcache *regcache,	
	      gdb_fpregset_t *fpregsetp, int regno)
{
  microblaze_linux_collect_fpregset (NULL, regcache, regno, fpregsetp, 0);
}

void
supply_fpregset (struct regcache *regcache, const gdb_fpregset_t *fpregsetp)
{
  microblaze_linux_supply_fpregset (NULL, regcache, -1, fpregsetp, 0);
}


/* Fetch the thread-local storage pointer for libthread_db.  */

ps_err_e
ps_get_thread_area (const struct ps_prochandle *ph,
                    lwpid_t lwpid, int idx, void **base)
{
  if (ptrace (PTRACE_GET_THREAD_AREA, lwpid, NULL, base) != 0)
    return PS_ERR;

  /* IDX is the bias from the thread pointer to the beginning of the
     thread descriptor.  It has to be subtracted due to implementation
     quirks in libthread_db.  */
  *base = (void *) ((char *)*base - idx);

  return PS_OK;
}

static unsigned int
get_linux_version (unsigned int *vmajor,
		   unsigned int *vminor,
		   unsigned int *vrelease)
{
  struct utsname info;
  char *pmajor, *pminor, *prelease, *tail;

  if (-1 == uname (&info))
    {
      warning (_("Unable to determine GNU/Linux version."));
      return -1;
    }

  pmajor = strtok (info.release, ".");
  pminor = strtok (NULL, ".");
  prelease = strtok (NULL, ".");

  *vmajor = (unsigned int) strtoul (pmajor, &tail, 0);
  *vminor = (unsigned int) strtoul (pminor, &tail, 0);
  *vrelease = (unsigned int) strtoul (prelease, &tail, 0);

  return ((*vmajor << 16) | (*vminor << 8) | *vrelease);
}

static const struct target_desc *
microblaze_linux_read_description (struct target_ops *ops)
{
  CORE_ADDR microblaze_hwcap = 0;

  if (target_auxv_search (ops, AT_HWCAP, &microblaze_hwcap) != 1)
    {
      return NULL;
    }

  return NULL;
}

void _initialize_microblaze_linux_nat (void);

void
_initialize_microblaze_linux_nat (void)
{
  struct target_ops *t;

  os_version = get_linux_version (&os_major, &os_minor, &os_release);

  /* Fill in the generic GNU/Linux methods.  */
  t = linux_target ();

  /* Add our register access methods.  */
  t->to_fetch_registers = microblaze_linux_fetch_inferior_registers;
  t->to_store_registers = microblaze_linux_store_inferior_registers;

  t->to_read_description = microblaze_linux_read_description;

  /* Register the target.  */
  linux_nat_add_target (t);
}
