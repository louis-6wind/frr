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

#include <zebra.h>
#include "lib/isis.h"

#define FORMAT_ID_SIZE sizeof("0000.0000.0000.00-00")
const char *lib_isis_format_id(const uint8_t *id, size_t len)
{
#define FORMAT_BUF_COUNT 4
	static char buf_ring[FORMAT_BUF_COUNT][FORMAT_ID_SIZE];
	static size_t cur_buf = 0;

	char *rv;

	cur_buf++;
	if (cur_buf >= FORMAT_BUF_COUNT)
		cur_buf = 0;

	rv = buf_ring[cur_buf];

	if (!id) {
		snprintf(rv, FORMAT_ID_SIZE, "unknown");
		return rv;
	}

	if (len < 6) {
		snprintf(rv, FORMAT_ID_SIZE, "Short ID");
		return rv;
	}

	snprintf(rv, FORMAT_ID_SIZE, "%02x%02x.%02x%02x.%02x%02x", id[0], id[1],
		 id[2], id[3], id[4], id[5]);

	if (len > 6)
		snprintf(rv + 14, FORMAT_ID_SIZE - 14, ".%02x", id[6]);
	if (len > 7)
		snprintf(rv + 17, FORMAT_ID_SIZE - 17, "-%02x", id[7]);

	return rv;
}


/* len of xx.xxxx.xxxx.xxxx.xxxx.xxxx.xxxx.xxxx.xxxx.xxxx.xx */
/* + place for #0 termination */
char isonet[51];

/*
 * This converts the isonet to its printable format
 */
const char *lib_isonet_print(const uint8_t *from, int len)
{
	int i = 0;
	char tbuf[4];
	isonet[0] = '\0';

	if (!from)
		return "unknown";

	while (i < len) {
		if (i & 1) {
			snprintf(tbuf, sizeof(tbuf), "%02x", *(from + i));
			strlcat(isonet, tbuf, sizeof(isonet));
		} else {
			if (i == (len - 1)) { /* No dot at the end of address */
				snprintf(tbuf, sizeof(tbuf), "%02x",
					 *(from + i));
				strlcat(isonet, tbuf, sizeof(isonet));
			} else {
				snprintf(tbuf, sizeof(tbuf), "%02x.",
					 *(from + i));
				strlcat(isonet, tbuf, sizeof(isonet));
			}
		}
		i++;
	}

	return isonet;
}
