/*
 * IS-IS functions that are shared with BGP-LS
 *
 * Copyright 2023 6WIND S.A.
 *
 * This file is part of Free Range Routing (FRR).
 *
 * FRR is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * FRR is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef _FRR_LIB_ISIS_H_
#define _FRR_LIB_ISIS_H_

const char *lib_isis_format_id(const uint8_t *id, size_t len);
const char *lib_isonet_print(const uint8_t *from, int len);

#endif /* _FRR_LIB_ISIS_H_ */
