#!/usr/bin/env python3
"""Self-test for the dial guard in tests/load/sip_agent.py: Agent.invite() must never put an
INVITE on the wire for a number that could leave the board through the anchor. Runs in CI:

    python3 -m unittest discover -s tests/tools -p 'test_sip_agent_dial_guard.py'

Why it exists: on 2026-10-19 bench scripts built on sip_agent dialed 6102, which no UA had
registered. In SBC mode the board sends a dialed string that is neither registered nor claimed
by the dial plan out the anchor, so about ten calls went to the carrier.

Nothing here opens a socket or starts a thread. socket.socket is patched to fail the test, each
Agent is built with object.__new__ (Agent.__init__ would bind a socket and start a receive
thread), and an INVITE that passes the guard is cut at Dialog() by a sentinel exception, so
"allowed" means "reached Dialog()" and "refused" means "raised DialRefused with nothing sent".
"""
import os
import re
import sys
import threading
import types
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, os.path.join(HERE, "..", "load"))
import sip_agent  # noqa: E402

RealDialog = sip_agent.Dialog               # GuardCase.setUp swaps the module's Dialog for a sentinel
FAR = "15550104242"                         # a fictional outside number (as test_anchor_scenarios)
NEVER = ("911", "933", "112", "113", "9911", "9933", "9112", "9113", "+911",   # refused constants: only checked
         "555", "+555")                  # 555: the anchored-media bridge; dialing it makes the board place an anchor call
ENV_TARGETS = "SIP_AGENT_ALLOW_TARGETS"
ENV_OUTSIDE = "SIP_AGENT_ALLOW_OUTSIDE"
SERVICE = ("777", "888", "440", "796", "997", "999",
           "700", "701", "702", "703", "704", "705", "706", "707", "708", "709",
           "980", "981", "982", "983", "984", "985", "986", "987", "988", "989",
           "*8", "**6101")


class Reached(Exception):
    """The INVITE got past the guard as far as Dialog()."""


def reset_registry():
    reg = getattr(sip_agent, "_REGISTERED", None)
    if reg is not None:
        reg.clear()


def reply(status, *contacts):
    return types.SimpleNamespace(status=status, body="",
                                 all=lambda name: list(contacts) if name == "contact" else [])


def make_agent(ext="6101"):
    """An Agent with no socket and no thread; everything it would send is recorded in .wire."""
    a = object.__new__(sip_agent.Agent)
    a.ext, a.host, a.lip, a.lport = ext, "192.0.2.1", "192.0.2.2", 5070   # RFC 5737 documentation space
    a.contact = "<sip:%s@%s:%d>" % (ext, a.lip, a.lport)
    a.reg_tag, a.reg_call_id, a.reg_cseq, a.registered = "t", "c@h", 0, False
    a._lock = threading.Lock()
    a._closed = threading.Event()
    a._dialogs, a._acks = {}, {}
    a.sock = types.SimpleNamespace(close=lambda: None)
    a.rtp_pump = None
    a.reply = None
    a.wire = []
    a._send = lambda text, addr=None: a.wire.append(("send", text))

    def txn(text, key, invite, txn=None, timeout=None):
        a.wire.append(("txn", text))
        return a.reply
    a._transaction = txn
    return a


def register(a, status=200, expires=60, echo=True):
    a.reply = reply(status, a.contact if echo else "<sip:other@192.0.2.9:5060>")
    return a.register(expires)


class GuardCase(unittest.TestCase):
    def setUp(self):
        reset_registry()
        self.addCleanup(reset_registry)
        env = mock.patch.dict(os.environ)
        env.start()
        self.addCleanup(env.stop)
        os.environ.pop(ENV_TARGETS, None)
        os.environ.pop(ENV_OUTSIDE, None)
        for p in (mock.patch.object(sip_agent.socket, "socket",
                                    side_effect=AssertionError("a socket was opened")),
                  mock.patch.object(sip_agent, "Dialog", side_effect=Reached("past the guard"))):
            p.start()
            self.addCleanup(p.stop)
        self.caller = make_agent("6101")

    def refuse(self, target, agent=None):
        """invite(target) raises DialRefused and nothing is built or sent. Returns the exception."""
        agent = agent or self.caller
        agent.wire.clear()
        try:
            agent.invite(target)
        except Reached:
            self.fail("INVITE %r got past the guard (it reached Dialog())" % (target,))
        except sip_agent.DialRefused as e:
            self.assertEqual(agent.wire, [], "a refused INVITE sent something")
            return e
        self.fail("INVITE %r was not refused" % (target,))

    def allow(self, target, agent=None):
        """invite(target) gets past the guard (the sentinel at Dialog() stops it there)."""
        agent = agent or self.caller
        agent.wire.clear()
        with self.assertRaises(Reached, msg="INVITE %r was refused" % (target,)):
            agent.invite(target)
        self.assertEqual(agent.wire, [])


class TargetAllowedTest(unittest.TestCase):
    """The pure decision: target_allowed(target, registered, extra, outside) -> (ok, reason)."""

    def test_a_registered_extension_is_allowed(self):
        ok, why = sip_agent.target_allowed("6102", {"6102"}, (), ())
        self.assertTrue(ok)
        self.assertIn("registered", why)

    def test_an_unregistered_four_digit_extension_is_refused(self):
        ok, why = sip_agent.target_allowed("6102", {"6101"}, (), ())
        self.assertFalse(ok)
        self.assertIn("not registered", why)
        self.assertFalse(sip_agent.target_allowed("6102", set(), (), ())[0])

    def test_emergency_and_never_dial_numbers_are_refused_whoever_lists_or_registers_them(self):
        for t in NEVER:
            with self.subTest(target=t):
                ok, why = sip_agent.target_allowed(t, {t}, {t}, {t})
                self.assertFalse(ok)
                self.assertIn("emergency", why)

    def test_the_anchor_bridge_555_is_refused_whoever_lists_or_registers_it(self):
        ok, why = sip_agent.target_allowed("555", {"555"}, {"555"}, {"555"})
        self.assertFalse(ok)
        self.assertIn("anchor", why)
        self.assertTrue(sip_agent.target_allowed("5550", set(), {"5550"}, ())[0], "only 555 itself is the bridge")

    def test_a_plus_number_is_refused_even_when_registered_or_listed_as_a_target(self):
        for t in ("+6102", "+15550104242"):
            with self.subTest(target=t):
                ok, why = sip_agent.target_allowed(t, {t}, {t}, ())
                self.assertFalse(ok)
                self.assertIn("outside", why)

    def test_seven_or_more_digits_are_refused_even_when_registered_or_listed_as_a_target(self):
        self.assertTrue(sip_agent.target_allowed("610212", set(), {"610212"}, ())[0], "6 digits is still an extension")
        for t in ("6102123", FAR, "**1234567", "1234567*", "12345#67"):
            with self.subTest(target=t):
                ok, why = sip_agent.target_allowed(t, {t}, {t}, ())
                self.assertFalse(ok)
                self.assertIn("outside", why)

    def test_an_outside_number_is_allowed_only_by_an_exact_opt_in(self):
        for t in (FAR, "+" + FAR, "6102123", "+6102"):
            with self.subTest(target=t):
                self.assertTrue(sip_agent.target_allowed(t, set(), (), {t})[0])
        out = {FAR}
        for t in ("+" + FAR, FAR[:-1], FAR + "0", "0" + FAR, FAR + " ", FAR + "\n"):
            with self.subTest(near_miss=t):
                self.assertFalse(sip_agent.target_allowed(t, set(), (), out)[0])
        self.assertFalse(sip_agent.target_allowed(FAR, set(), {FAR}, ())[0], "a target list is not an opt-in")

    def test_the_opt_in_is_exact_for_a_short_number_too(self):
        self.assertTrue(sip_agent.target_allowed("61020", set(), (), {"61020"})[0])
        self.assertFalse(sip_agent.target_allowed("61021", set(), (), {"61020"})[0])

    def test_empty_and_malformed_targets_are_refused(self):
        for t in ("", None, " ", "+", "61 02", "6102\n", "abc", "61-02", "6102@host", "sip:6102", "++6102",
                  "61+02", "６１０２", "٦١٠٢"):
            with self.subTest(target=t):
                ok, why = sip_agent.target_allowed(t, {t}, {t}, {t})
                self.assertFalse(ok)

    def test_service_numbers_are_allowed(self):
        for t in SERVICE:
            with self.subTest(target=t):
                ok, why = sip_agent.target_allowed(t, set(), (), ())
                self.assertTrue(ok)
                self.assertIn("service", why)

    def test_numbers_next_to_a_service_range_are_not_service_numbers(self):
        # 555 is the anchored-media bridge: dialing it hands the call to the anchor.
        for t in ("555", "710", "699", "979", "990", "70", "7000", "98", "9800", "**", "*", "#", "**ab", "*80", "88"):
            with self.subTest(target=t):
                self.assertFalse(sip_agent.target_allowed(t, set(), (), ())[0])

    def test_an_explicit_list_allows_what_it_names_and_only_that(self):
        self.assertTrue(sip_agent.target_allowed("6102", set(), {"6102"}, ())[0])
        self.assertFalse(sip_agent.target_allowed("6103", set(), {"6102"}, ())[0])
        self.assertTrue(sip_agent.target_allowed("6102", set(), ["6102"], ())[0], "any iterable of strings")
        self.assertTrue(sip_agent.target_allowed("6102", {"6102"})[0], "extra and outside default to none")

    def test_the_decision_is_pure(self):
        reg, extra, out = {"6102"}, {"6103"}, {FAR}
        sip_agent.target_allowed("6102", reg, extra, out)
        sip_agent.target_allowed("6104", reg, extra, out)
        sip_agent.target_allowed(FAR, reg, extra, out)
        self.assertEqual((reg, extra, out), ({"6102"}, {"6103"}, {FAR}))


class InviteGuardTest(GuardCase):
    def test_an_unregistered_extension_is_refused_before_anything_is_sent(self):
        e = self.refuse("6102")
        self.assertIn("6102", str(e))
        self.assertIn("not registered", str(e))

    def test_an_extension_another_agent_registered_in_this_process_is_allowed(self):
        other = make_agent("6102")
        self.assertEqual(register(other), 200)
        self.assertTrue(other.registered)
        self.allow("6102")

    def test_service_numbers_are_allowed(self):
        for t in SERVICE:
            with self.subTest(target=t):
                self.allow(t)

    def test_emergency_and_never_dial_numbers_are_refused_even_when_listed_everywhere(self):
        self.caller.allow_targets(*NEVER)
        self.caller.allow_outside(*NEVER)
        os.environ[ENV_TARGETS] = ",".join(NEVER)
        os.environ[ENV_OUTSIDE] = ",".join(NEVER)
        for t in NEVER:
            with self.subTest(target=t):
                e = self.refuse(t)
                self.assertIn(t, str(e))

    def test_the_anchor_bridge_555_is_refused_even_when_listed_with_the_env_var_or_the_method(self):
        self.caller.allow_targets("555")
        os.environ[ENV_TARGETS] = "555"
        e = self.refuse("555")
        self.assertIn("anchor", str(e))
        self.assertIn("555", str(e))

    def test_plus_and_long_numbers_are_refused_even_when_listed_as_targets_and_the_digits_are_not_echoed(self):
        self.caller.allow_targets("+6102", FAR, "6102123")
        os.environ[ENV_TARGETS] = "+6102,%s,6102123" % FAR
        for t in ("+6102", FAR, "6102123"):
            with self.subTest(target=t):
                e = self.refuse(t)
                self.assertNotIn(t.lstrip("+"), str(e), "an outside number is not copied into a log line")
                self.assertIn("outside", str(e))
                self.assertIn("allow_outside", str(e), "the message says how to opt in")

    def test_allow_outside_opts_in_that_exact_number_for_that_agent_only(self):
        self.refuse(FAR)
        self.caller.allow_outside(FAR, "+" + FAR)
        self.allow(FAR)
        self.allow("+" + FAR)
        self.refuse(FAR + "0")
        self.refuse(FAR[:-1])
        self.refuse("6102")
        self.refuse(FAR, agent=make_agent("6105"))

    def test_the_outside_env_var_opts_in_exact_numbers_and_is_read_at_call_time(self):
        self.refuse(FAR)
        os.environ[ENV_OUTSIDE] = " %s, +6102 ,," % FAR
        self.allow(FAR)
        self.allow("+6102")
        self.refuse("+" + FAR)
        self.refuse("6102")
        del os.environ[ENV_OUTSIDE]
        self.refuse(FAR)

    def test_allow_outside_does_not_open_the_extension_list_nor_the_other_way_round(self):
        self.caller.allow_outside("6102")
        os.environ[ENV_TARGETS] = FAR
        self.refuse(FAR)
        self.allow("6102")                 # an exact opt-in lets that string through, whatever its shape
        self.refuse("6103")

    def test_malformed_targets_are_refused(self):
        for t in ("", None, "61 02", "6102\n", "abc", "sip:6102", "++6102"):
            with self.subTest(target=t):
                self.refuse(t)

    def test_allow_targets_lists_extensions_for_that_agent_only(self):
        self.refuse("6102")
        self.caller.allow_targets("6102", 6103)
        self.allow("6102")
        self.allow("6103")
        self.refuse("6104")
        self.refuse("6102", agent=make_agent("6105"))

    def test_the_targets_env_var_lists_extensions_and_is_read_at_call_time(self):
        self.refuse("6102")
        os.environ[ENV_TARGETS] = " 6102, 6103 ,,"
        self.allow("6102")
        self.allow("6103")
        self.refuse("6104")
        del os.environ[ENV_TARGETS]
        self.refuse("6102")

    def test_the_cancel_argument_errors_still_come_first_and_are_value_errors(self):
        self.assertFalse(issubclass(sip_agent.DialRefused, ValueError), "a refusal must not read as a bad argument")
        with self.assertRaises(ValueError):
            self.caller.invite("6102", cancel_when=lambda since: None)
        with self.assertRaises(ValueError):
            self.caller.invite("6102", cancel_after_ms=100, cancel_when=lambda since: None, cancel_when_timeout_s=1.0)
        self.assertEqual(self.caller.wire, [])

    def test_a_refusal_survives_the_cancel_options(self):
        self.caller.wire.clear()
        with self.assertRaises(sip_agent.DialRefused):
            self.caller.invite("6102", cancel_after_ms=100, invite_timeout=1.0)
        self.assertEqual(self.caller.wire, [])


class RegistrationTest(GuardCase):
    """Only a REGISTER whose 200 echoes this agent's own binding (#686) makes an extension dialable."""

    def test_a_200_that_does_not_echo_our_binding_adds_nothing(self):
        other = make_agent("6102")
        register(other, echo=False)
        self.assertFalse(other.registered)
        self.refuse("6102")

    def test_a_refused_register_adds_nothing(self):
        other = make_agent("6102")
        register(other, status=403)
        self.refuse("6102")
        other.reply = None                       # no final at all
        other.register(60)
        self.refuse("6102")

    def test_a_deregistration_takes_it_out_again(self):
        other = make_agent("6102")
        register(other)
        self.allow("6102")
        register(other, expires=0)
        self.refuse("6102")

    def test_a_failed_refresh_takes_it_out(self):
        other = make_agent("6102")
        register(other)
        register(other, status=500)
        self.refuse("6102")

    def test_closing_the_agent_takes_it_out(self):
        other = make_agent("6102")
        register(other)
        self.allow("6102")
        other.close()
        self.refuse("6102")


class ReinviteTest(GuardCase):
    def test_a_reinvite_inside_a_dialog_is_not_a_new_call_and_never_asks_the_guard(self):
        agent = make_agent("6101")
        agent._request = lambda method, ruri, dlg, cseq, branch, body="", cseq_method=None: "%s %s" % (method, ruri)
        agent.sdp = lambda dlg, direction="sendrecv": ""
        agent.reply = reply(486)
        dlg = object.__new__(RealDialog)
        dlg.agent, dlg.call_id, dlg.local_cseq, dlg.invite_cseq = agent, "c1", 1, 1
        dlg.remote_target, dlg.remote_uri, dlg.remote_media = "", "sip:6102@192.0.2.1", (None, 0, None)
        with mock.patch.object(sip_agent, "target_allowed", side_effect=AssertionError("asked the guard")):
            self.assertEqual(dlg.reinvite("sendonly"), 486)
        self.assertEqual([w[0] for w in agent.wire], ["txn", "send"], "the re-INVITE and the ACK of its 486")


class FirmwareListTest(unittest.TestCase):
    """The service list is copied from the firmware; a change there must be a decision here."""

    def read(self, rel):
        with open(os.path.join(ROOT, rel), encoding="utf-8", errors="replace") as f:
            return f.read()

    def test_every_reserved_literal_of_the_firmware_is_either_allowed_or_refused_on_purpose(self):
        src = self.read(os.path.join("src", "SIP", "PbxConfig.hpp"))
        m = re.search(r"inline bool isReservedExtension\(.*?\n\t\}", src, re.S)
        self.assertIsNotNone(m, "pbx::isReservedExtension() not found")
        literals = set(re.findall(r'ext == "([0-9]+)"', m.group(0)))
        self.assertEqual(literals, set(sip_agent.SERVICE_LITERALS) | set(sip_agent.FIRMWARE_RESERVED_REFUSED),
                         "a reserved extension was added or removed: decide whether the harness may dial it")
        self.assertFalse(set(sip_agent.SERVICE_LITERALS) & set(sip_agent.FIRMWARE_RESERVED_REFUSED))

    def test_the_park_orbits_and_page_zones_match_the_firmware(self):
        pool = self.read(os.path.join("src", "SIP", "PoolConfig.hpp"))
        slots = int(re.search(r"#define POCKETDIAL_PARK_SLOTS (\d+)", pool).group(1))
        self.assertEqual(set(sip_agent.PARK_ORBITS), {"70%d" % i for i in range(slots)})
        cfg = self.read(os.path.join("src", "SIP", "PbxConfig.hpp"))
        self.assertRegex(cfg, r"ext\.size\(\) == 3 && ext\[0\] == '9' && ext\[1\] == '8'")
        self.assertEqual(set(sip_agent.PAGE_ZONES), {"98%d" % i for i in range(10)})


class AnchorOptInTest(unittest.TestCase):
    """tests/load/anchor_scenarios.py dials its designated far end (an outside number) on purpose, in
    runs desmo has approved. It opts that one value in where it builds its agents, nowhere else."""

    def test_an_anchor_run_opts_in_exactly_its_far_ends_where_it_builds_its_agents(self):
        with open(os.path.join(ROOT, "tests", "load", "anchor_scenarios.py"), encoding="utf-8") as f:
            src = f.read()
        self.assertEqual(len(re.findall(r"\.allow_outside\(", src)), 1, "one opt-in, in one place")
        self.assertRegex(src, r"self\.agents\[role\] = self\.agent_factory\([^\n]*\n"
                              r"\s+self\.agents\[role\]\.allow_outside\(\*self\.far_ends\)")
        for other in ("allow_targets(", "SIP_AGENT_ALLOW"):
            self.assertNotIn(other, src, "the run must not widen the guard any other way")


if __name__ == "__main__":
    unittest.main()
