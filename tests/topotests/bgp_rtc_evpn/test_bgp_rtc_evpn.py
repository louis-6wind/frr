#!/usr/bin/env python
# SPDX-License-Identifier: ISC


"""
Test BGP route-constraint feature
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

    # sw switch is for interconnecting peers on the same subnet
    sw = tgen.add_switch("sw")
    connect_switchs(tgen, "rr", sw)
    connect_switchs(tgen, "r1", sw)
    connect_switchs(tgen, "r2", sw)
    connect_switchs(tgen, "r3", sw)
    connect_switchs(tgen, "r4", sw)


    # directly connected without switch routers
    connect_routers(tgen, "r1", "h1")
    connect_routers(tgen, "r2", "h2")
    connect_routers(tgen, "r3", "h3")
    connect_routers(tgen, "r4", "h4")

def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for r in range(1, 5):
        router = tgen.gears[f"r{r}"]
        i = 100 if r in [1, 2] else 200
        vrf = "RED" if r in [1, 2] else "GREEN"
        router.cmd(f"""
ip link add vxlan{i} type vxlan id {i} dstport 4789 local 10.0.1.{r}0 nolearning
ip link add br{i} type bridge stp_state 0
ip link set vxlan{i} master br{i}
ip link set eth-h{r} master br{i}
ip link set vxlan{i} up
ip link set br{i} up
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
