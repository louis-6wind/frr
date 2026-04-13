#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_isis_level_redistribution.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2026 by 6WIND S.A.
#

"""
test_isis_level_redistribution.py:

Test IS-IS level redistribution
"""

import os
import sys
import json
from functools import partial
import pytest
import time

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.bgp import verify_bgp_convergence_from_running_config
from lib.checkping import check_ping
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

# Required to instantiate the topology builder class.

pytestmark = [pytest.mark.isisd]

def connect_routers(tgen, left, right):
    for rname in [left, right]:
        if rname not in tgen.routers().keys():
            tgen.add_router(rname)

    switch = tgen.add_switch("s-{}-{}".format(left, right))
    switch.add_link(tgen.gears[left], nodeif="eth-{}".format(right))
    switch.add_link(tgen.gears[right], nodeif="eth-{}".format(left))


def build_topo(tgen):
    "Build function"

    # This function only purpose is to define allocation and relationship
    # between routers, switches and hosts.

    connect_routers(tgen, "r1", "r2")
    connect_routers(tgen, "r2", "r3")
    connect_routers(tgen, "r3", "r4")
    connect_routers(tgen, "r4", "r5")


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for rname, router in tgen.routers().items():
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/frr.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_ISIS, os.path.join(CWD, "{}/frr.conf".format(rname))
        )

    tgen.start_router()


def teardown_module(mod):
    "Teardown the pytest environment"
    tgen = get_topogen()

    # This function tears down the whole topology.
    tgen.stop_topology()


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
