/* Definitions to target GDB to GNU/Linux on PowerPC.

   Copyright 1992, 1993, 2000, 2002 Free Software Foundation, Inc.

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

#ifndef TM_LINUX_H
#define TM_LINUX_H

#include "microblaze/tm-microblaze.h"
/* Avoid warning from redefinition in tm-sysv4.h (included from tm-linux.h) */
#undef SKIP_TRAMPOLINE_CODE
#include "config/tm-linux.h"

/* Enable software single-stepping for Linux. */
#undef SOFTWARE_SINGLE_STEP_P
#undef SOFTWARE_SINGLE_STEP

/* We've multi-arched these.  (Note that this completely undoes the
   effect of config/tm-linux.h #including config/tm-sysv4.h.)  */
#undef SKIP_TRAMPOLINE_CODE

/* N_FUN symbols in shared libaries have 0 for their values and need
   to be relocated. */
#define SOFUN_ADDRESS_MAYBE_MISSING

#endif  /* #ifndef TM_LINUX_H */
