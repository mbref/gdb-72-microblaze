/* Target-dependent code for Xilinx MicroBlaze.

   Copyright 2009, 2010 Free Software Foundation, Inc.

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

#include "defs.h"
#include "frame.h"
#include "inferior.h"
#include "symtab.h"
#include "target.h"
#include "gdbcore.h"
#include "gdbcmd.h"
#include "symfile.h"
#include "objfiles.h"
#include "regcache.h"
#include "value.h"
#include "osabi.h"
#include "regset.h"
#include "solib-svr4.h"
#include "microblaze-tdep.h"
#include "trad-frame.h"
#include "frame-unwind.h"
#include "tramp-frame.h"

#include "microblaze-linux-nat.h"

static int
microblaze_linux_memory_insert_breakpoint (struct gdbarch *gdbarch, 
					   struct bp_target_info *bp_tgt)
{


  /* adapted from mem-break.c */
 /* The microblaze allows software breaks, but only with 0x8 or 0x18 as the
 * imm address.  Any other address whilst in usermode will cause a SIGILL
 * exception, thus stopping our ability to debug the program. */
  int val;
  const unsigned char *bp;

  /* Determine appropriate breakpoint contents and size for this address.  */
  //bp = gdbarch_breakpoint_from_pc
  //     (gdbarch, &bp_tgt->placed_address, &bp_tgt->placed_size);
  //
  bp = gdbarch_breakpoint_from_pc
       (gdbarch, &bp_tgt->placed_address, &bp_tgt->placed_size);
  if (bp == NULL)
    error (_("Software breakpoints not implemented for this target."));

  /* Save the memory contents.  */
  bp_tgt->shadow_len = bp_tgt->placed_size;
  val = target_read_memory (bp_tgt->placed_address, bp_tgt->shadow_contents,
                            bp_tgt->placed_size);

  /* Write the breakpoint.  */
  if (val == 0)
    val = target_write_memory (bp_tgt->placed_address, bp,
                               bp_tgt->placed_size);

  //if (val == 0)
    //val = target_write_memory (bp_tgt->placed_address, bp,
    //                           bp_tgt->placed_size);

  return val;

}

static int
microblaze_linux_memory_remove_breakpoint (struct gdbarch *gdbarch, 
					   struct bp_target_info *bp_tgt)
{
  CORE_ADDR addr = bp_tgt->placed_address;
  const gdb_byte *bp;
  int val;
  int bplen;
  gdb_byte old_contents[BREAKPOINT_MAX];

  /* Determine appropriate breakpoint contents and size for this address.  */
  bp = gdbarch_breakpoint_from_pc (gdbarch, &addr, &bplen);
  if (bp == NULL)
    error (_("Software breakpoints not implemented for this target."));

  val = target_read_memory (addr, old_contents, bplen);

  val = target_write_memory (addr, bp_tgt->shadow_contents, bplen);

  return val;
}

static void
microblaze_linux_sigtramp_cache (struct frame_info *next_frame,
				 struct trad_frame_cache *this_cache,
				 CORE_ADDR func, LONGEST offset,
				 int bias)
{
  CORE_ADDR base;
  CORE_ADDR gpregs;
  int regnum;
  struct gdbarch *gdbarch = get_frame_arch (next_frame);
  struct gdbarch_tdep *tdep = gdbarch_tdep (gdbarch);

  base = frame_unwind_register_unsigned (next_frame, MICROBLAZE_SP_REGNUM);
  if (bias > 0 && get_frame_address_in_block (next_frame) != func)
    /* See below, some signal trampolines increment the stack as their
       first instruction, need to compensate for that.  */
    base -= bias;

  /* Find the address of the register buffer.  */
  gpregs = base + offset;

  /* Registers saved on stack.  */
  for (regnum = 0; regnum < MICROBLAZE_BTR_REGNUM; regnum++)
    trad_frame_set_reg_addr (this_cache, regnum, 
			     gpregs + regnum * MICROBLAZE_REGISTER_SIZE);
  trad_frame_set_id (this_cache, frame_id_build (base, func));
}


static void
microblaze_linux_sighandler_cache_init (const struct tramp_frame *self,
					struct frame_info *next_frame,
					struct trad_frame_cache *this_cache,
					CORE_ADDR func)
{
  microblaze_linux_sigtramp_cache (next_frame, this_cache, func,
				   0 /* Offset to ucontext_t.  */
				   + 24 /* Offset to .reg.  */,
				   0);
}

static struct tramp_frame microblaze_linux_sighandler_tramp_frame = 
{
  SIGTRAMP_FRAME,
  4,
  {
    { 0x31800077, -1 }, /* addik R12,R0,119.  */
    { 0xb9cc0008, -1 }, /* brki R14,8.  */
    { TRAMP_SENTINEL_INSN },
  },
  microblaze_linux_sighandler_cache_init
};


static void
microblaze_linux_init_abi (struct gdbarch_info info,
			   struct gdbarch *gdbarch)
{
  struct gdbarch_tdep *tdep = gdbarch_tdep (gdbarch);

  set_gdbarch_memory_remove_breakpoint (gdbarch,
					microblaze_linux_memory_remove_breakpoint);

  set_gdbarch_memory_insert_breakpoint (gdbarch,
					microblaze_linux_memory_insert_breakpoint);

  /* Shared library handling.  */
  set_solib_svr4_fetch_link_map_offsets (gdbarch,
					 svr4_ilp32_fetch_link_map_offsets);

  /* Trampolines.  */
  tramp_frame_prepend_unwinder (gdbarch,
				&microblaze_linux_sighandler_tramp_frame);
}

void
microblaze_linux_supply_gregset (const struct regset *regset,
                          struct regcache *regcache,
                          int regnum, const void *gregs_buf, size_t len)
{

  struct gdbarch *gdbarch = get_regcache_arch (regcache);
  enum bfd_endian byte_order = gdbarch_byte_order (gdbarch);
  const gdb_byte *gregs = gregs_buf;
  int regno;
  CORE_ADDR reg_pc;
  gdb_byte pc_buf[MICROBLAZE_REGISTER_SIZE];

  for (regno = MICROBLAZE_R0_REGNUM; regno < MICROBLAZE_PC_REGNUM; regno++)
    if (regnum == -1 || regnum == regno)
      regcache_raw_supply (regcache, regno,
                           gregs + MICROBLAZE_REGISTER_SIZE * regno);

  if (regnum == MICROBLAZE_PC_REGNUM || regnum == -1)
    {
      reg_pc = extract_unsigned_integer (gregs
                                         + MICROBLAZE_REGISTER_SIZE * MICROBLAZE_PC_REGNUM,
                                         MICROBLAZE_REGISTER_SIZE, byte_order);
      reg_pc = gdbarch_addr_bits_remove (gdbarch, reg_pc);
      store_unsigned_integer (pc_buf, MICROBLAZE_REGISTER_SIZE, byte_order, reg_pc);
      regcache_raw_supply (regcache, MICROBLAZE_PC_REGNUM, pc_buf);
    }
}


void
microblaze_linux_collect_gregset (const struct regset *regset,
                           const struct regcache *regcache,
                           int regnum, void *gregs_buf, size_t len)
{

  gdb_byte *gregs = gregs_buf;
  int regno;

  for (regno = MICROBLAZE_R0_REGNUM; regno < MICROBLAZE_PC_REGNUM; regno++)
    if (regnum == -1 || regnum == regno)
      regcache_raw_collect (regcache, regno,
                            gregs + MICROBLAZE_REGISTER_SIZE * regno);

  if (regnum == MICROBLAZE_PC_REGNUM || regnum == -1)
    regcache_raw_collect (regcache, MICROBLAZE_PC_REGNUM,
                          gregs + MICROBLAZE_REGISTER_SIZE * MICROBLAZE_PC_REGNUM);
}

void
microblaze_linux_supply_fpregset (const struct regset *regset,
                          struct regcache *regcache,
                          int regnum, const void *fpregs_buf, size_t len)
{
  /* Not implemented yet */
}

void
microblaze_linux_collect_fpregset (const struct regset *regset,
                           const struct regcache *regcache,
                           int regnum, void *fpregs_buf, size_t len)
{
  /* Not implemented yet */
}

void
_initialize_microblaze_linux_tdep (void)
{
  gdbarch_register_osabi (bfd_arch_microblaze, 0, GDB_OSABI_LINUX, 
			  microblaze_linux_init_abi);
}
