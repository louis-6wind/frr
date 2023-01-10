/*
 * BGP Link-State VTY
 *
 * Copyright 2022 6WIND S.A.
 *
 * This file is part of FRRouting
 *
 * FRRouting is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * FRRouting is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>
#include "command.h"
#include "prefix.h"
#include "lib/json.h"
#include "lib/printfrr.h"
#include "stream.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_linkstate_vty.h"
#include "bgpd/bgp_linkstate.h"
#include "bgpd/bgp_zebra.h"
#include "bgpd/bgp_vty.h"
#include "bgpd/bgp_debug.h"



DEFUN (debug_bgp_linkstate,
       debug_bgp_linkstate_cmd,
       "debug bgp linkstate",
       DEBUG_STR
       BGP_STR
       "BGP allow linkstate debugging entries\n")
{
	if (vty->node == CONFIG_NODE)
		DEBUG_ON(linkstate, LINKSTATE);
	else {
		TERM_DEBUG_ON(linkstate, LINKSTATE);
		vty_out(vty, "BGP linkstate debugging is on\n");
	}
	return CMD_SUCCESS;
}

DEFUN (no_debug_bgp_linkstate,
       no_debug_bgp_linkstate_cmd,
       "no debug bgp linkstate",
       NO_STR
       DEBUG_STR
       BGP_STR
       "BGP allow linkstate debugging entries\n")
{
	if (vty->node == CONFIG_NODE)
		DEBUG_OFF(linkstate, LINKSTATE);
	else {
		TERM_DEBUG_OFF(linkstate, LINKSTATE);
		vty_out(vty, "BGP linkstate debugging is off\n");
	}
	return CMD_SUCCESS;
}


void bgp_linkstate_vty_init(void)
{
	install_element(ENABLE_NODE, &debug_bgp_linkstate_cmd);
	install_element(CONFIG_NODE, &debug_bgp_linkstate_cmd);
	install_element(ENABLE_NODE, &no_debug_bgp_linkstate_cmd);
	install_element(CONFIG_NODE, &no_debug_bgp_linkstate_cmd);
}
