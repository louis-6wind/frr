#!/usr/bin/env python
# SPDX-License-Identifier: ISC


"""
Test BGP route-constraint feature for L3VPN
"""

import os
import sys
import json
import pytest
import functools

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.common_config import step

pytestmark = [pytest.mark.bgpd]


def build_topo(tgen):
    def connect_routers(tgen, left, right):
        for rname in [left, right]:
            if rname not in tgen.routers().keys():
                tgen.add_router(rname)

        switch = tgen.add_switch("s-{}-{}".format(left, right))
        switch.add_link(tgen.gears[left], nodeif="eth-{}".format(right))
        switch.add_link(tgen.gears[right], nodeif="eth-{}".format(left))

    def connect_switchs(tgen, rname, switch):
        if rname not in tgen.routers().keys():
            tgen.add_router(rname)

        switch.add_link(tgen.gears[rname], nodeif="eth-{}".format(switch.name))

    # directly connected without switch routers
    connect_routers(tgen, "rr1", "pe1")
    connect_routers(tgen, "rr1", "pe2")
    connect_routers(tgen, "pe1", "ce1")
    connect_routers(tgen, "pe1", "ce2")
    connect_routers(tgen, "pe2", "ce3")
    connect_routers(tgen, "pe2", "ce4")

def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    pe1 = tgen.gears["pe1"]
    pe2 = tgen.gears["pe2"]

    pe1.cmd("""
ip link add RED type vrf table 100
ip link set RED up
ip link set eth-ce1 master RED
ip link add BLUE type vrf table 101
ip link set BLUE up
ip link set eth-ce2 master BLUE
""")

    pe2.cmd("""
ip link add RED type vrf table 100
ip link set RED up
ip link set eth-ce3 master RED
ip link add GREEN type vrf table 102
ip link set GREEN up
ip link set eth-ce4 master GREEN
""")

    router_list = tgen.routers()

    for _, (rname, router) in enumerate(router_list.items(), 1):
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_convergence():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # TODO

    assert False


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
