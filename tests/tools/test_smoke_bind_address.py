#!/usr/bin/env python3
"""CodeQL py/bind-socket-all-network-interfaces (#5, #6, #8): the SIP probe and
the stress tester bind the local address toward the target, never the wildcard.

    python3 -m unittest discover -s tests/tools -p 'test_smoke_bind_address.py'

No network: socket.socket is replaced by a recorder.
"""
import importlib.util
import os
import socket
import sys
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(HERE, "..", "..")
sys.path.insert(0, os.path.join(ROOT, "tests", "load"))
import sip_stress  # noqa: E402

_spec = importlib.util.spec_from_file_location("sip_probe", os.path.join(ROOT, ".smoke", "sip_probe.py"))
sip_probe = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(sip_probe)

WILDCARDS = ("0.0.0.0", "")


class FakeSock:
    """Records bind(); connect() reports `route` (None = no route)."""
    made = []
    route = "10.1.2.3"
    busy_port = None

    def __init__(self, *a, **k):
        self.binds = []
        FakeSock.made.append(self)

    def settimeout(self, t): pass
    def close(self): pass

    def connect(self, addr):
        if FakeSock.route is None:
            raise OSError("unreachable")

    def getsockname(self):
        return (FakeSock.route or "0.0.0.0", 40000)

    def bind(self, addr):
        self.binds.append(addr)
        if addr[1] == FakeSock.busy_port:
            raise OSError("in use")

    def sendto(self, msg, addr):
        raise OSError("stop here")


class BindAddressTest(unittest.TestCase):
    def setUp(self):
        FakeSock.made = []
        FakeSock.route = "10.1.2.3"
        FakeSock.busy_port = None

    def all_binds(self):
        return [b for s in FakeSock.made for b in s.binds]

    def test_probe_binds_the_route_address(self):
        with mock.patch.object(socket, "socket", FakeSock), mock.patch("builtins.print"):
            self.assertFalse(sip_probe.probe("10.1.2.1", 5060))
        self.assertIn(("10.1.2.3", 5061), self.all_binds())
        self.assertTrue(all(b[0] not in WILDCARDS for b in self.all_binds()))

    def test_probe_fallback_port_keeps_the_same_interface(self):
        FakeSock.busy_port = 5061
        with mock.patch.object(socket, "socket", FakeSock), mock.patch("builtins.print"):
            sip_probe.probe("10.1.2.1", 5060)
        binds = self.all_binds()
        self.assertIn(("10.1.2.3", 0), binds)
        self.assertTrue(all(b[0] not in WILDCARDS for b in binds))

    def test_probe_no_route_never_yields_the_wildcard(self):
        FakeSock.route = None
        with mock.patch.object(socket, "socket", FakeSock):
            self.assertEqual(sip_probe.local_ip_for("192.0.2.1"), "127.0.0.1")
        with mock.patch.object(socket, "socket", FakeSock), mock.patch("builtins.print"):
            sip_probe.probe("192.0.2.1", 5060)
        self.assertTrue(all(b[0] not in WILDCARDS for b in self.all_binds()))

    def test_stress_ua_binds_its_source_ip(self):
        with mock.patch.object(socket, "socket", FakeSock):
            sip_stress.UA("1000", "10.1.2.1", 5060, "10.1.2.3")
        self.assertEqual(self.all_binds(), [("10.1.2.3", 0)])

    def test_stress_no_route_never_yields_the_wildcard(self):
        FakeSock.route = None
        with mock.patch.object(socket, "socket", FakeSock):
            self.assertEqual(sip_stress.local_ip_for("192.0.2.1", 5060), "127.0.0.1")


if __name__ == "__main__":
    unittest.main()
