#!/usr/bin/env python3
"""Self-test for the anchor scenario kind (tests/load/anchor_scenarios.py) and
the sip_agent additions it uses. Runs in CI:

    python3 -m unittest discover -s tests/tools -p 'test_anchor_scenarios.py'

Everything runs on 127.0.0.1 against fakes: a scripted UDP SIP peer, and a fake
board (tests/load/fake_pbx.py's registrar plus a fake anchor route, a fake HTTP
API with the real admin-session gate, and a syslog sender). No board, no phone,
no 3CX, no other network.
"""
import contextlib
import datetime
import io
import json
import os
import re
import secrets
import socket
import sys
import tempfile
import threading
import time
import unittest
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "load"))
import anchor_scenarios as an  # noqa: E402
import sip_agent  # noqa: E402
import sip_stress  # noqa: E402
from fake_pbx import FakePbx  # noqa: E402
from sip_agent import SipMsg, rand_hex, tag_of, uri_of, user_of  # noqa: E402

FAR = "15550104242"            # a fictional far end; never in any output or result
PIN = "Pin-Secret-7731"
TENANT = "acme-test.3cx.us"
CLIENT_ID = "client-XYZ123"
ROUTE_DN = "rcv2"
CHECKOUT = "https://github.com/GlomarGadaffi/pocket-dial/discussions/428#discussioncomment-1"
FAST = {"calls": 3, "cancel_ms": (100, 300), "gap_s": 0.2}
FAST_RUN = {"beep_wait_s": 0.3, "roster_wait_s": 2.0, "tail_s": 0.3}


def expiry(seconds_from_now=7200):
    t = datetime.datetime.fromtimestamp(time.time() + seconds_from_now, datetime.timezone.utc)
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def base_env(**kw):
    env = {"PD_ANCHOR_FAR_END": FAR, "PD_BOARD_ADMIN_PIN": PIN}
    env.update(kw)
    return {k: v for k, v in env.items() if v is not None}


def cli(*extra, host="127.0.0.1", approval=an.APPROVALS[0], checkout=CHECKOUT, exp=None):
    a = ["--scenario", "x4_cancel_ringing", "--host", host]
    if approval:
        a += ["--approval-url", approval]
    if checkout:
        a += ["--checkout-url", checkout]
    a += ["--checkout-expiry", exp or expiry()]
    return a + list(extra)


class NoNetwork:
    """An http client that fails the test if anything touches it."""

    def __getattr__(self, name):
        raise AssertionError("a refused run must not contact the board (%s)" % name)


def run_main(argv, env, **kw):
    lines = []
    rc = an.main(argv, env=env, out=lines.append, **kw)
    return rc, "\n".join(lines)


# ---------------------------------------------------------------- a scripted SIP peer
class Peer:
    """A UDP socket on loopback that hands every message to `on_msg(peer, msg, addr)`."""

    def __init__(self, on_msg):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.settimeout(0.1)
        self.port = self.sock.getsockname()[1]
        self.on_msg = on_msg
        self.log = []           # (monotonic time, SipMsg)
        self._stop = threading.Event()
        self.state = {}
        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self):
        while not self._stop.is_set():
            try:
                data, addr = self.sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                return
            if not data.strip():
                continue
            msg = SipMsg.parse(data)
            self.log.append((time.monotonic(), msg))
            self.on_msg(self, msg, addr)

    def send(self, text, addr):
        self.sock.sendto(text.encode("utf-8"), addr)

    def reply(self, req, code, reason, addr, to_tag="", body="", contact=None):
        lines = ["SIP/2.0 %d %s" % (code, reason)] + ["Via: " + v for v in req.all("via")]
        to = req.get("to")
        if to_tag and not tag_of(to):
            to += ";tag=" + to_tag
        lines += ["From: " + req.get("from"), "To: " + to, "Call-ID: " + req.call_id(),
                  "CSeq: " + req.get("cseq")]
        if contact:
            lines.append("Contact: " + contact)
        if body:
            lines.append("Content-Type: application/sdp")
        lines.append("Content-Length: %d" % len(body))
        self.send("\r\n".join(lines) + "\r\n\r\n" + body, addr)

    def first(self, method):
        return next(((t, m) for t, m in self.log if not m.is_response and m.method == method), (None, None))

    def all(self, method):
        return [m for _, m in self.log if not m.is_response and m.method == method]

    def close(self):
        self._stop.set()
        self.sock.close()


SDP = ("v=0\r\no=peer 1 1 IN IP4 127.0.0.1\r\ns=x\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n"
       "m=audio 40000 RTP/AVP 0\r\na=sendrecv\r\n")


class AgentCase(unittest.TestCase):
    def agent(self, peer, **kw):
        a = sip_agent.Agent("6101", "127.0.0.1", peer.port, local_ip="127.0.0.1", timeout=2.0,
                            invite_timeout=4.0, **kw)
        self.addCleanup(a.close)
        return a

    def peer(self, on_msg):
        p = Peer(on_msg)
        self.addCleanup(p.close)
        return p


def ringing_then_487(peer, msg, addr, provisional_after=0.0):
    """INVITE -> (after `provisional_after` s) 100 + 180; CANCEL -> 200, then 487 to the INVITE."""
    if msg.method == "INVITE" and not msg.is_response:
        if "invite" in peer.state:
            return                      # a Timer A retransmission (s17.1.1.2)
        peer.state["invite"] = (msg, addr)
        peer.state["tag"] = rand_hex(6)

        def ring():
            peer.reply(msg, 100, "Trying", addr)
            peer.reply(msg, 180, "Ringing", addr, to_tag=peer.state["tag"])
        if provisional_after:
            threading.Timer(provisional_after, ring).start()
        else:
            ring()
    elif msg.method == "CANCEL" and not msg.is_response:
        peer.reply(msg, 200, "OK", addr)
        inv, iaddr = peer.state["invite"]
        peer.reply(inv, 487, "Request Terminated", iaddr, to_tag=peer.state["tag"])


class CancelAfterTest(AgentCase):
    def test_cancel_goes_at_the_chosen_time_and_the_487_is_acked(self):
        p = self.peer(ringing_then_487)
        dlg = self.agent(p).invite(FAR, cancel_after_ms=800)
        t_inv, inv = p.first("INVITE")
        t_can, can = p.first("CANCEL")
        self.assertEqual(dlg.final_status, 487)
        self.assertEqual(dlg.cancel_status, 200)
        self.assertAlmostEqual(t_can - t_inv, 0.8, delta=0.15)
        self.assertAlmostEqual(dlg.cancel_sent_at - dlg.invite_sent_at, 0.8, delta=0.1)
        # s9.1: same branch, Call-ID, CSeq number and Request-URI; To without a tag.
        self.assertEqual((can.branch(), can.call_id(), can.cseq()[0], can.ruri),
                         (inv.branch(), inv.call_id(), inv.cseq()[0], inv.ruri))
        self.assertEqual(tag_of(can.get("to")), "")
        self.assertEqual(sorted(s for _, s in dlg.responses), [100, 180, 487])
        deadline = time.monotonic() + 1.0
        while not p.all("ACK") and time.monotonic() < deadline:
            time.sleep(0.02)
        ack = p.all("ACK")[0]
        self.assertEqual((ack.branch(), ack.cseq()), (inv.branch(), (1, "ACK")))

    def test_no_cancel_before_a_provisional(self):
        p = self.peer(lambda peer, m, a: ringing_then_487(peer, m, a, provisional_after=0.6))
        dlg = self.agent(p).invite(FAR, cancel_after_ms=100)
        t_inv, _ = p.first("INVITE")
        t_can, _ = p.first("CANCEL")
        self.assertEqual(dlg.final_status, 487)
        self.assertGreaterEqual(t_can - t_inv, 0.6, "a CANCEL went before any provisional response")

    def test_a_final_before_the_cancel_time_sends_no_cancel(self):
        def answer(peer, msg, addr):
            if msg.method == "INVITE" and not msg.is_response:
                peer.reply(msg, 200, "OK", addr, to_tag="t1", body=SDP, contact="<sip:far@127.0.0.1:%d>" % peer.port)
            elif msg.method == "BYE":
                peer.reply(msg, 200, "OK", addr)
        p = self.peer(answer)
        dlg = self.agent(p).invite(FAR, cancel_after_ms=500)
        time.sleep(0.6)
        self.assertTrue(dlg.ok)
        self.assertIsNone(dlg.cancel_sent_at)
        self.assertEqual(p.all("CANCEL"), [])
        self.assertEqual(dlg.bye(), 200)

    def test_without_cancel_after_a_refusal_is_not_cancelled(self):
        def busy(peer, msg, addr):
            if msg.method == "INVITE" and not msg.is_response:
                peer.reply(msg, 486, "Busy Here", addr, to_tag="b1")
        p = self.peer(busy)
        dlg = self.agent(p).invite("6102")
        time.sleep(0.2)
        self.assertEqual(dlg.final_status, 486)
        self.assertEqual(p.all("CANCEL"), [])


class DialogTest(AgentCase):
    def test_hold_and_resume_are_in_dialog_reinvites(self):
        def answer(peer, msg, addr):
            if msg.method == "INVITE" and not msg.is_response:
                peer.reply(msg, 200, "OK", addr, to_tag="far1", body=SDP,
                           contact="<sip:far@127.0.0.1:%d;line=x>" % peer.port)
        p = self.peer(answer)
        dlg = self.agent(p).invite("6102")
        self.assertTrue(dlg.ok)
        self.assertEqual(dlg.hold(), 200)
        self.assertEqual(dlg.resume(), 200)
        invites = p.all("INVITE")
        self.assertEqual(len(invites), 3)
        for n, (msg, direction) in enumerate(zip(invites[1:], ("sendonly", "sendrecv")), 2):
            self.assertEqual(msg.call_id(), invites[0].call_id())
            self.assertEqual(msg.cseq(), (n, "INVITE"))
            self.assertEqual(tag_of(msg.get("to")), "far1")
            self.assertEqual(tag_of(msg.get("from")), dlg.local_tag)
            self.assertEqual(msg.ruri, "sip:far@127.0.0.1:%d;line=x" % p.port, "s12.2.1.1 remote target")
            self.assertIn("a=%s" % direction, msg.body)
        deadline = time.monotonic() + 1.0
        while len(p.all("ACK")) < 3 and time.monotonic() < deadline:
            time.sleep(0.02)
        self.assertEqual([a.cseq() for a in p.all("ACK")], [(1, "ACK"), (2, "ACK"), (3, "ACK")])

    def test_contact_params_ride_on_register_and_invite(self):
        def ok(peer, msg, addr):
            if msg.method == "REGISTER":
                peer.reply(msg, 200, "OK", addr, contact=msg.get("contact"))
            elif msg.method == "INVITE":
                peer.reply(msg, 486, "Busy Here", addr, to_tag="x")
        p = self.peer(ok)
        a = self.agent(p, contact_params=";line=pd6101")
        self.assertEqual(a.register(60), 200)
        self.assertTrue(a.registered)
        a.invite("6102")
        reg, inv = p.all("REGISTER")[0], p.all("INVITE")[0]
        for m in (reg, inv):
            self.assertEqual(uri_of(m.get("contact")), "sip:6101@127.0.0.1:%d;line=pd6101" % a.lport)

    def test_contact_without_params_is_unchanged(self):
        p = self.peer(lambda *x: None)
        a = self.agent(p)
        self.assertEqual(a.contact, "<sip:6101@127.0.0.1:%d>" % a.lport)


class StrictByeTest(AgentCase):
    """The peer calls the agent, then sends BYEs with chosen tags."""

    def call_in(self, **kw):
        p = self.peer(lambda *x: None)
        a = self.agent(p, **kw)
        cid, ftag = rand_hex(10), "pbxtag"
        addr = ("127.0.0.1", a.lport)
        inv = ("INVITE sip:6101@127.0.0.1:%d SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1:%d;branch=z9hG4bK%s\r\n"
               "From: <sip:6102@127.0.0.1>;tag=%s\r\nTo: <sip:6101@127.0.0.1>\r\nCall-ID: %s\r\n"
               "CSeq: 1 INVITE\r\nContact: <sip:6102@127.0.0.1:%d>\r\nContent-Type: application/sdp\r\n"
               "Content-Length: %d\r\n\r\n%s" % (a.lport, p.port, rand_hex(8), ftag, cid, p.port, len(SDP), SDP))
        p.send(inv, addr)
        dlg = a.wait_incoming(0, 2.0)
        self.assertIsNotNone(dlg)

        def bye(from_tag, to_tag):
            p.log.clear()
            p.send("BYE sip:6101@127.0.0.1:%d SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1:%d;branch=z9hG4bK%s\r\n"
                   "From: <sip:6102@127.0.0.1>;tag=%s\r\nTo: <sip:6101@127.0.0.1>;tag=%s\r\nCall-ID: %s\r\n"
                   "CSeq: 2 BYE\r\nContent-Length: 0\r\n\r\n" % (a.lport, p.port, rand_hex(8), from_tag, to_tag, cid),
                   addr)
            deadline = time.monotonic() + 2.0
            while time.monotonic() < deadline:
                for _, m in list(p.log):
                    if m.is_response and m.method == "BYE":
                        return m.status
                time.sleep(0.01)
            return None
        return a, dlg, ftag, bye

    def test_a_wrong_tag_gets_481_and_is_counted(self):
        a, dlg, ftag, bye = self.call_in(strict_dialogs=True)
        self.assertEqual(bye("not-the-tag", dlg.local_tag), 481)
        self.assertEqual(bye(ftag, "not-mine"), 481)
        self.assertEqual((dlg.bye_mismatches, dlg.byes), (2, 0))
        self.assertFalse(dlg.ended.is_set())
        self.assertEqual(len(a.bye_481), 2)
        self.assertIn("tags do not", a.bye_481[0]["why"])
        self.assertEqual(bye(ftag, dlg.local_tag), 200)
        self.assertEqual(dlg.byes, 1)
        self.assertTrue(dlg.ended.is_set())
        self.assertEqual(bye(ftag, dlg.local_tag), 481, "a second BYE on an ended dialog")
        self.assertEqual(dlg.byes, 2)

    def test_default_matching_is_unchanged(self):
        a, dlg, ftag, bye = self.call_in()
        self.assertEqual(bye("not-the-tag", "nor-this"), 200)
        self.assertEqual(a.bye_481, [])
        self.assertTrue(dlg.ended.is_set())

    def test_reject_invites_refuses_and_records(self):
        p = self.peer(lambda *x: None)
        a = self.agent(p, reject_invites=486)
        p.send("INVITE sip:6104@127.0.0.1 SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1:%d;branch=z9hG4bKr1\r\n"
               "From: \"PSTN\" <sip:%s@127.0.0.1>;tag=a\r\nTo: <sip:%s@127.0.0.1>\r\nCall-ID: ph1\r\n"
               "CSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n" % (p.port, ROUTE_DN, ROUTE_DN), ("127.0.0.1", a.lport))
        deadline = time.monotonic() + 2.0
        while not any(m.is_response for _, m in p.log) and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertEqual([m.status for _, m in p.log if m.is_response], [486])
        self.assertEqual([r["from_user"] for r in a.rejected], [ROUTE_DN])
        self.assertEqual(a.incoming, [])


# ---------------------------------------------------------------- offline refusals
class RefusalTest(unittest.TestCase):
    def refused(self, argv, env, *needles):
        rc, out = run_main(argv, env, http=NoNetwork())
        self.assertEqual(rc, an.REFUSED, out)
        for n in needles:
            self.assertIn(n, out)
        self.assertNotIn(FAR, out)
        self.assertNotIn(FAR[-10:], out)
        self.assertIn("REFUSED", out)
        return out

    def test_exit_codes_are_run_soaks(self):
        self.assertEqual(an.EXIT, {"PASS": 0, "FAIL": 1, "INVALID": 3, "ABORTED": 4, "NEEDS-HUMAN": 5})
        self.assertEqual(an.REFUSED, 2)

    def test_a_missing_or_expired_checkout_is_refused(self):
        self.refused(cli(checkout=None), base_env(), "no CHECK-OUT")
        self.refused(cli(checkout="https://github.com/GlomarGadaffi/pocket-dial/issues/428#issuecomment-1"),
                     base_env(), "not a discussion #428 comment link")
        self.refused(cli(exp=expiry(60)), base_env(), "before this run would end")

    def test_the_approval_must_be_a_recorded_one(self):
        self.refused(cli(approval=None), base_env(), "no --approval-url")
        for url in ("https://github.com/GlomarGadaffi/pocket-dial/issues/384#issuecomment-1",
                    an.APPROVALS[0] + "x",
                    "https://github.com/GlomarGadaffi/pocket-dial/discussions/451#discussioncomment-18621137"):
            self.refused(cli(approval=url), base_env(), "not a recorded approval")
        for url in an.APPROVALS:
            rc, out = run_main(cli("--dry-run", approval=url), base_env(), http=NoNetwork())
            self.assertEqual(rc, 0, out)

    def test_the_far_end_never_comes_from_argv(self):
        for extra in (["--far-end", FAR], ["--far-end=" + FAR], ["--target", FAR], [FAR], ["+" + FAR]):
            out = self.refused(cli(*extra), base_env(), "never goes on an argv")
            self.assertNotIn(FAR, out)
        # a value argparse would have echoed in "unrecognized arguments"
        self.refused(cli("--bogus", FAR), base_env(), "never goes on an argv")

    def test_the_far_end_must_be_set_exactly_once(self):
        self.refused(cli(), base_env(PD_ANCHOR_FAR_END=None), "no far end")
        self.refused(cli(), base_env(PD_ANCHOR_FAR_END_FILE="x"), "set exactly one")

    def test_emergency_and_never_dial_far_ends_are_refused(self):
        for num in ("911", "933", "112", "113", "999", "9911", "9933", "15559110000", "+19335551234"):
            rc, out = run_main(cli(), base_env(PD_ANCHOR_FAR_END=num), http=NoNetwork())
            self.assertEqual(rc, an.REFUSED, num)
            self.assertIn("emergency or never-dial", out, num)

    def test_owner_extensions_and_pbx_numbers_are_refused_as_the_far_end(self):
        for num in ("1001", "1002", "1003"):
            self.refused(cli(), base_env(PD_ANCHOR_FAR_END=num), "owner extension")
        self.refused(cli(), base_env(PD_ANCHOR_FAR_END="4242", PD_OWNER_EXTS="4242"), "owner extension")
        self.assertEqual(an.owner_set("4243,4244", None), {"1001", "1002", "1003", "113", "4243", "4244"})
        rc, out = run_main(cli("--owner-ext", "4243", "--dry-run"), base_env(), http=NoNetwork())
        self.assertEqual(rc, 0, out)
        # the far end itself on an argv, even as an "owner" value, is refused as a secret
        self.refused(cli("--owner-ext", "4243,%s" % FAR), base_env(), "holds a secret")
        for num in ("6101", "6104", "555", "777", "888", "985", "705"):
            self.refused(cli(), base_env(PD_ANCHOR_FAR_END=num), "this PBX owns")
        for num in ("sip:x@y", "15550104242@evil", "12", "abc"):
            self.refused(cli(), base_env(PD_ANCHOR_FAR_END=num), "not 3-15 digits")

    def test_the_far_end_file_must_be_0600_on_posix(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "far")
            with open(path, "w", encoding="utf-8") as f:
                f.write("# the designated far end\n%s\n" % FAR)
            env = {"PD_ANCHOR_FAR_END_FILE": path}
            uid = getattr(os, "getuid", lambda: 1000)()

            def st(mode, owner=uid):
                return lambda p: os.stat_result((mode, 0, 0, 1, owner, 0, 0, 0, 0, 0))
            self.assertEqual(an.load_far_end(env, stat_fn=st(0o100600), posix=True), (FAR, "file"))
            for mode in (0o100644, 0o100640, 0o100604):
                with self.assertRaises(an.Refused) as cm:
                    an.load_far_end(env, stat_fn=st(mode), posix=True)
                self.assertIn("0600", str(cm.exception))
                self.assertNotIn(FAR, str(cm.exception))
            if hasattr(os, "getuid"):
                with self.assertRaises(an.Refused):
                    an.load_far_end(env, stat_fn=st(0o100600, owner=uid + 1), posix=True)
            if os.name == "posix":
                os.chmod(path, 0o644)
                with self.assertRaises(an.Refused):
                    an.load_far_end(env)
                os.chmod(path, 0o600)
                self.assertEqual(an.load_far_end(env), (FAR, "file"))

    def test_the_admin_pin_comes_from_the_environment(self):
        self.refused(cli(), base_env(PD_BOARD_ADMIN_PIN=None), "PD_BOARD_ADMIN_PIN")
        out = self.refused(cli("--pin", PIN), base_env(), "holds a secret")
        self.assertNotIn(PIN, out)

    def test_only_an_approved_rig_or_loopback(self):
        self.refused(cli(host="192.168.12.110"), base_env(), "not an approved rig")
        for host in an.RIG_HOSTS:
            rc, out = run_main(cli("--dry-run", host=host), base_env(), http=NoNetwork())
            self.assertEqual(rc, 0, out)

    def test_test_uas_are_only_6101_to_6104_and_6104_detects(self):
        sc = dict(an.SCENARIOS["x4_cancel_ringing"])
        for uas, needle in (({"caller": "1001", "detector": "6104"}, "not a test UA"),
                            ({"caller": "6105", "detector": "6104"}, "not a test UA"),
                            ({"caller": "6101", "detector": "6103"}, "must be 6104"),
                            ({"caller": "6104", "detector": "6104"}, "two roles")):
            self.assertTrue(any(needle in p for p in an.scenario_problems(dict(sc, uas=uas))), uas)
            rc, out = run_main(cli(), base_env(), http=NoNetwork(), overrides={"uas": uas})
            self.assertEqual(rc, an.REFUSED)
            self.assertIn(needle, out)

    def test_calls_are_capped_at_thirty(self):
        rc, out = run_main(cli(), base_env(), http=NoNetwork(), overrides={"calls": 31})
        self.assertEqual(rc, an.REFUSED)
        self.assertIn("calls must be 1-30", out)

    def test_a_scenario_without_a_path_counter_cannot_register(self):
        with self.assertRaises(ValueError):
            an.scenario(name="x_none", uas={"caller": "6101", "detector": "6104"}, calls=1,
                        call_cap_s=10, judge=lambda *a: ([], [], {}))(lambda run, sc: None)
        self.assertNotIn("x_none", an.SCENARIOS)
        self.assertEqual(sorted(an.SCENARIOS), ["x4_cancel_ringing"])

    def test_dry_run_prints_the_plan_and_the_ring_required_banner(self):
        rc, out = run_main(cli("--dry-run"), base_env(), http=NoNetwork())
        self.assertEqual(rc, 0, out)
        self.assertIn("RING-REQUIRED", out)
        self.assertIn("rx554_window", out)
        self.assertNotIn(FAR, out)

    def test_sip_stress_delegates_the_scenario(self):
        with mock.patch.dict(os.environ, base_env(), clear=False):
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = sip_stress.main(cli("--dry-run"))
        self.assertEqual(rc, 0, buf.getvalue())
        self.assertIn("x4_cancel_ringing", buf.getvalue())


class CounterTest(unittest.TestCase):
    LINES = [
        "I (1) TelephonyAnchor: Successfully initiated call to <x> (own leg 19)",
        "I (2) TelephonyAnchor: Rx stream task started for participant 19",
        "W (3) TelephonyAnchor: startRxIfNeeded: rx task for 19 still exiting -- not restarting yet (#554)",
        "W (4) TelephonyAnchor: startRxIfNeeded: rx task for 19 had exited -- restarting (#554)",
        "I (5) TelephonyAnchor: Rx stream task started for participant 19",
        "W (6) TelephonyAnchor: startRxIfNeeded: 19 was dropped -- not re-priming (#554)",
        "I (7) TelephonyAnchor: Successfully dropped participant 19",
        "E (8) TelephonyAnchor: makeCall request failed (status=403)",
    ]

    def test_counts(self):
        c = an.count_lines(self.LINES)
        self.assertEqual((c["rx554_window"], c["rx554_restart"], c["rx554_dropped_leg"]), (2, 1, 1))
        self.assertEqual((c["initiated"], c["dropped"], c["rx_started"], c["makecall_status"]), (1, 1, 2, 1))
        self.assertEqual(an.drop_problems(self.LINES), [])
        self.assertEqual(an.rx_task_problems(self.LINES), [], "a #554 restart explains the 2nd task")

    def test_two_rx_tasks_and_drop_faults(self):
        two = self.LINES[:2] + [self.LINES[1]]
        self.assertTrue(an.rx_task_problems(two))
        self.assertIn("never dropped", " ".join(an.drop_problems(self.LINES[:1])))
        twice = self.LINES + ["Successfully dropped participant 19"]
        self.assertIn("dropped 2 times", " ".join(an.drop_problems(twice)))
        self.assertIn("failed", " ".join(an.drop_problems(["dropCall request failed for participant 7 (status=0)"])))

    def test_classify(self):
        base = {"final": 487, "cancel_status": 200, "cancel_sent_ms": 900, "cancel_answered_ms": 905,
                "final_ms": 910, "provisional": [[100, 5], [180, 300]], "bye": None}
        self.assertEqual(an.x4_classify(base), ("cancelled", None))
        self.assertEqual(an.x4_classify(dict(base, final=200, cancel_sent_ms=None, bye=200)),
                         ("answered_before_cancel", None))
        self.assertEqual(an.x4_classify(dict(base, final=200, final_ms=901, bye=200)), ("crossed_cancel", None))
        self.assertEqual(an.x4_classify(dict(base, final=200, final_ms=990, bye=200))[0], "answered_after_cancel")
        self.assertIn("a 180 before it", an.x4_classify(dict(base, final=503))[1])
        self.assertIn("no 180 before it", an.x4_classify(dict(base, final=503, provisional=[[100, 5]]))[1])
        self.assertIn("#548", an.x4_classify(dict(base, final=None))[1])


# ---------------------------------------------------------------- the fake board
class FakeBoard(FakePbx):
    """fake_pbx.py's registrar, plus the anchor route for FAR, the admin-gated HTTP
    API and a syslog sender. Knobs change one behaviour each."""

    def __init__(self):
        super().__init__()
        self.route_dn = ROUTE_DN
        self.mappings = [{"did": self.route_dn, "extension": "6104"}]
        self.syslog_cfg = {"supported": True, "enabled": False, "host": "", "port": 514}
        self.sessions = {}
        self.uptime_base = 5000
        self.coredump = {"present": False, "size": 0, "supported": True}
        self.window_calls = {1}           # call indexes that log the #554 window line
        self.refuse_calls = set()         # -> 180 then 503
        self.phantom_calls = set()        # -> an inbound INVITE to 6104 from the route DN
        self.undropped_calls = set()      # -> no drop line
        self.beep = False
        self.lapse_after = None           # authenticated roster reads before 6104 vanishes
        self.reboot_after_call = None
        self.leak_status = False
        self.roster_reads = 0
        self.calls = {}
        self.n_calls = 0
        self.leg = 40
        self.cancels = []
        self.log_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def stop(self):
        super().stop()
        self.log_sock.close()

    # -- syslog
    def log(self, text):
        c = self.syslog_cfg
        if c["enabled"] and c["host"]:
            self.log_sock.sendto(("<14>1 2026-10-03T00:00:00Z - pbx-log - - - " + text).encode(),
                                 (c["host"], int(c["port"])))

    # -- SIP
    def _on_register(self, req, addr):
        user = user_of(uri_of(req.get("to")))
        new = user not in self.bindings
        super()._on_register(req, addr)
        if self.beep and new and req.get("expires") != "0":
            self._request("INVITE", uri_of(req.get("contact")), '"PocketDial" <sip:pbx@%s:%d>;tag=bp' % (
                self.host, self.port), "<sip:%s@%s>" % (user, self.host), "beep-" + rand_hex(6), 1, addr,
                on_response=lambda r: None)

    def _on_invite(self, req, addr):
        if user_of(req.ruri) != FAR or tag_of(req.get("to")):
            return super()._on_invite(req, addr)
        self.invite_users.append(FAR)
        i, self.n_calls = self.n_calls, self.n_calls + 1
        self.leg += 1
        leg, tag = str(self.leg), rand_hex(6)
        self.calls[req.call_id()] = {"req": req, "addr": addr, "leg": leg, "tag": tag, "i": i}
        self._reply(req, addr, 100, "Trying")
        self.log("anchor(6101): 6101 ringing (async makeCall dispatched)")
        if i in self.refuse_calls:
            self._reply(req, addr, 180, "Ringing", to_tag=tag)
            self.log("[Telephony] Failed to initiate outbound call to %s" % FAR)
            self.calls[req.call_id()]["done"] = True
            self._reply(req, addr, 503, "Service Unavailable", to_tag=tag)
            return
        self.log("TelephonyAnchor: Successfully initiated call to %s (own leg %s)" % (FAR, leg))
        self.log("TelephonyAnchor: POST (device->Telephony) audio stream OPEN: https://%s/callcontrol/%s/"
                 "participants/%s/stream" % (TENANT, self.route_dn, leg))
        self.log("TelephonyAnchor: Rx stream task started for participant %s" % leg)
        self.log("debug: a careless line with the admin password=%s and PIN %s" % (PIN, PIN))
        if i in self.window_calls:
            self.log("TelephonyAnchor: startRxIfNeeded: rx task for %s still exiting -- not restarting "
                     "yet (#554)" % leg)
        self._reply(req, addr, 180, "Ringing", to_tag=tag)
        if i in self.phantom_calls and "6104" in self.bindings:
            b = self.bindings["6104"]
            self._request("INVITE", "sip:%s@%s:%d" % (self.route_dn, b["addr"][0], b["addr"][1]),
                          '"%s" <sip:%s@%s:%d>;tag=ph' % (FAR, self.route_dn, self.host, self.port),
                          "<sip:%s@%s>" % (self.route_dn, self.host), "ph-" + rand_hex(6), 1, b["addr"],
                          on_response=lambda r: None)

    def _on_cancel(self, req, addr):
        self._reply(req, addr, 200, "OK")
        c = self.calls.get(req.call_id())
        self.cancels.append(time.monotonic())
        if c is None or c.get("done"):
            return
        c["done"] = True
        self._send(self._resp(c["req"], 487, "Request Terminated", to_tag=c["tag"]), c["addr"])
        if c["i"] not in self.undropped_calls:
            self.log("TelephonyAnchor: Successfully dropped participant %s" % c["leg"])
        if self.reboot_after_call == c["i"]:
            self.uptime_base = -10**6

    # -- HTTP
    def public_status(self):
        st = {"version": "v1.5.0-fake", "uptime": int(time.monotonic() - self.started) + self.uptime_base,
              "resetReason": "POWERON", "coredump": dict(self.coredump), "clientCount": len(self.bindings),
              "rosterVisible": False, "clients": [], "sessionCount": 0}
        if self.leak_status:
            st["note"] = "far end %s" % FAR
        return st

    def authed_status(self):
        self.roster_reads += 1
        st = self.public_status()
        clients = [{"number": u, "address": "%s:%d" % b["addr"]} for u, b in sorted(self.bindings.items())]
        if self.lapse_after is not None and self.roster_reads > self.lapse_after:
            clients = [c for c in clients if c["number"] != "6104"]
        st.update(rosterVisible=True, clients=clients)
        return st

    def pcap(self):
        sip = ("INVITE sip:%s@10.0.0.1 SIP/2.0\r\nAuthorization: Digest username=\"1001\", response=\"abc\"\r\n"
               "To: <sip:%s@10.0.0.1>\r\n\r\n" % (FAR, FAR)).encode()
        return b"\xd4\xc3\xb2\xa1" + b"\x00" * 20 + sip

    def serve_http(self, port=0):
        board = self

        class Handler(BaseHTTPRequestHandler):
            def _session(self, need_csrf):
                m = re.search(r"pd_session=([0-9a-f]+)", self.headers.get("Cookie", ""))
                cookie = m.group(1) if m else None
                if cookie not in board.sessions:
                    return False
                return not need_csrf or self.headers.get("X-CSRF") == board.sessions[cookie]

            def _send(self, code, body, ctype="application/json", extra=()):
                data = body if isinstance(body, bytes) else json.dumps(body).encode()
                self.send_response(code)
                self.send_header("Content-Type", ctype)
                for k, v in extra:
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                path = self.path.split("?")[0]
                with board.lock:
                    if path == "/api/status":
                        return self._send(200, board.authed_status() if self._session(False)
                                          else board.public_status())
                    if not self._session(False):
                        return self._send(401, {"error": "authentication required"})
                    if path == "/api/did-mapping":
                        return self._send(200, {"mappings": board.mappings})
                    if path == "/api/telephony-config":
                        return self._send(200, {"slots": [{"index": 0, "type": "3cx", "enabled": True,
                                                           "implemented": True, "active": True,
                                                           "baseUrl": "https://%s" % TENANT,
                                                           "clientId": CLIENT_ID, "routeDn": board.route_dn,
                                                           "secretSet": True}]})
                    if path == "/api/syslog":
                        return self._send(200, board.syslog_cfg)
                    if path == "/api/pcap":
                        return self._send(200, board.pcap(), "application/vnd.tcpdump.pcap")
                return self._send(404, {"error": "not found"})

            def do_POST(self):
                path = self.path.split("?")[0]
                n = int(self.headers.get("Content-Length") or 0)
                form = dict(urllib.parse.parse_qsl(self.rfile.read(n).decode()))
                with board.lock:
                    if path == "/api/admin/login":
                        if form.get("username") != "admin" or form.get("password") != PIN:
                            return self._send(401, {"error": "bad credential"})
                        cookie, csrf = secrets.token_hex(16), secrets.token_hex(16)
                        board.sessions[cookie] = csrf
                        return self._send(200, {"csrf": csrf}, extra=[
                            ("Set-Cookie", "pd_session=%s; Path=/; HttpOnly; SameSite=Strict" % cookie)])
                    if not self._session(True):
                        return self._send(401 if not self._session(False) else 403, {"error": "denied"})
                    if path == "/api/admin/logout":
                        return self._send(200, {"status": "ok"})
                    if path == "/api/syslog":
                        host = form.get("host", "")
                        board.syslog_cfg.update(enabled=bool(host), host=host, port=int(form.get("port", 514)))
                        return self._send(200, {"status": "ok"})
                return self._send(404, {"error": "not found"})

            def log_message(self, *a):
                pass

        self._http = ThreadingHTTPServer((self.host, port), Handler)
        threading.Thread(target=self._http.serve_forever, daemon=True).start()
        return self._http.server_address[1]


class FakeLogger:
    """status_logger.sh's JSONL, written from the fake board's public status."""

    def __init__(self, board, argv, out_path):
        self.board, self.path = board, argv[2]
        self.argv = argv
        self._stop = threading.Event()
        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self):
        while not self._stop.wait(0.05):
            with self.board.lock:
                s = self.board.public_status()
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(json.dumps({"t": int(time.time()), "s": s}) + "\n")

    def poll(self):
        return 0 if self._stop.is_set() else None

    def terminate(self):
        self._stop.set()


class RunTest(unittest.TestCase):
    def setUp(self):
        self.board = FakeBoard().start()
        self.http_port = self.board.serve_http()
        self.addCleanup(self.board.stop)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.loggers = []

    def go(self, *extra, overrides=None, env=None):
        def start_logger(argv, out_path):
            lg = FakeLogger(self.board, argv, out_path)
            self.loggers.append(lg)
            return lg
        argv = cli("--port", str(self.board.port), "--http-port", str(self.http_port), "--local-ip", "127.0.0.1",
                   "--syslog-port", "0", "--set-syslog", "--pin-check-s", "0.05", "--out", self.tmp.name, *extra)
        rc, out = run_main(argv, env or base_env(), start_logger=start_logger,
                           overrides=dict(FAST, **(overrides or {})), run_defaults=FAST_RUN)
        dirs = [d for d in os.listdir(self.tmp.name) if os.path.isdir(os.path.join(self.tmp.name, d))]
        self.assertEqual(len(dirs), 1, out)
        self.res = os.path.join(self.tmp.name, dirs[0])
        with open(os.path.join(self.res, "manifest.json"), encoding="utf-8") as f:
            self.manifest = json.load(f)
        return rc, out

    def calls(self):
        with open(os.path.join(self.res, "calls.json"), encoding="utf-8") as f:
            return json.load(f)

    def assert_no_secret_anywhere(self, out):
        planted = (FAR, FAR[-10:], PIN, TENANT, CLIENT_ID) + tuple(self.board.sessions) + \
            tuple(self.board.sessions.values())
        for s in planted:
            self.assertNotIn(s, out)
        for d, _, files in os.walk(self.tmp.name):
            for n in files:
                if n.endswith(".tar.gz"):
                    continue
                with open(os.path.join(d, n), "rb") as f:
                    data = f.read()
                for s in planted:
                    self.assertNotIn(s.encode(), data, "%s holds a planted secret" % n)

    def test_pass(self):
        rc, out = self.go()
        self.assertEqual(rc, 0, out)
        self.assertEqual(self.manifest["verdict"], "PASS")
        self.assertEqual([c["final"] for c in self.calls()], [487, 487, 487])
        self.assertEqual([c["bucket"] for c in self.calls()], ["cancelled"] * 3)
        self.assertEqual(self.manifest["log_counters"]["rx554_window"], 1)
        self.assertEqual(self.manifest["log_counters"]["dropped"], 3)
        self.assertEqual(self.manifest["route_dn"], ROUTE_DN)
        sent = [c["cancel_sent_ms"] for c in self.calls()]
        for got, want in zip(sent, (100, 200, 300)):
            self.assertAlmostEqual(got, want, delta=120)
        pcaps = sorted(os.listdir(os.path.join(self.res, "pcap")))
        self.assertEqual(pcaps, ["call-01.pcap", "call-02.pcap", "call-03.pcap", "end.pcap"])
        with open(os.path.join(self.res, "pcap", "call-01.pcap"), "rb") as f:
            masked = f.read()
        self.assertEqual(len(masked), len(self.board.pcap()), "masked at the same length")
        self.assertTrue(masked.startswith(b"\xd4\xc3\xb2\xa1"))
        self.assertEqual(self.board.syslog_cfg, {"supported": True, "enabled": False, "host": "", "port": 514},
                         "the syslog setting is restored")
        self.assertEqual(self.board.bindings, {}, "both test UAs de-registered")
        self.assertIn("RING-REQUIRED", out)
        with open(os.path.join(self.res, "syslog.log"), encoding="utf-8") as f:
            self.assertIn("(#554)", f.read())
        self.assertTrue(os.path.isfile(self.res + ".tar.gz"))
        self.assert_no_secret_anywhere(out)

    def test_the_register_beep_is_not_a_phantom(self):
        self.board.beep = True
        rc, out = self.go()
        self.assertEqual(rc, 0, out)

    def test_invalid_when_the_path_counter_is_zero(self):
        self.board.window_calls = set()
        rc, out = self.go()
        self.assertEqual(rc, 3, out)
        self.assertEqual(self.manifest["verdict"], "INVALID")
        self.assertIn("rx554_window is 0", out)
        self.assert_no_secret_anywhere(out)

    def test_fail_on_a_503_instead_of_487(self):
        self.board.refuse_calls = {1}
        rc, out = self.go()
        self.assertEqual(rc, 1, out)
        self.assertIn("call 2: final 503 instead of 487 (a 180 before it", out)
        self.assertEqual([c["final"] for c in self.calls()], [487, 503, 487])

    def test_fail_on_a_phantom_inbound_at_6104(self):
        self.board.phantom_calls = {0}
        rc, out = self.go()
        self.assertEqual(rc, 1, out)
        self.assertIn("a phantom inbound (S1)", out)
        self.assertEqual(len(self.calls()), 1, "no call after the first phantom")
        self.assert_no_secret_anywhere(out)

    def test_a_did_shaped_route_dn_is_never_written(self):
        did = "+15550109999"
        self.board.route_dn = did
        self.board.mappings = [{"did": did, "extension": "6104"}]
        rc, out = self.go()
        self.assertEqual(rc, 0, out)
        for s in (did, did[1:], did[-10:]):
            self.assertNotIn(s, out)
        for d, _, files in os.walk(self.res):
            for n in files:
                with open(os.path.join(d, n), "rb") as f:
                    self.assertNotIn(did[-10:].encode(), f.read(), n)

    def test_fail_when_a_leg_is_never_dropped(self):
        self.board.undropped_calls = {2}
        rc, out = self.go()
        self.assertEqual(rc, 1, out)
        self.assertIn("never dropped", out)

    def test_fail_on_a_reboot(self):
        self.board.reboot_after_call = 0
        rc, out = self.go()
        self.assertEqual(rc, 1, out)
        self.assertIn("uptime went", out)

    def test_fail_on_a_new_coredump(self):
        orig = self.board._on_cancel

        def cancel_then_dump(req, addr):
            orig(req, addr)
            self.board.coredump = {"present": True, "size": 47264, "supported": True}
        self.board._on_cancel = cancel_then_dump
        rc, out = self.go()
        self.assertEqual(rc, 1, out)
        self.assertIn("the coredump changed", out)

    def test_invalid_when_6104_lapses_mid_run(self):
        self.board.lapse_after = 4
        rc, out = self.go()
        self.assertEqual(rc, 3, out)
        self.assertIn("the S1 pin lapsed", out)
        self.assertLess(len(self.calls()), 3)

    def test_invalid_and_no_call_without_the_did_pin(self):
        self.board.mappings = [{"did": ROUTE_DN, "extension": "1001"}]
        rc, out = self.go()
        self.assertEqual(rc, 3, out)
        self.assertIn("no DID row maps the route DN to 6104", out)
        self.assertEqual(self.board.invite_users, [], "no call before the pin holds")
        self.assertEqual(self.board.bindings, {})

    def test_invalid_without_syslog_and_without_set_syslog(self):
        def start_logger(argv, out_path):
            return FakeLogger(self.board, argv, out_path)
        argv = cli("--port", str(self.board.port), "--http-port", str(self.http_port), "--local-ip", "127.0.0.1",
                   "--syslog-port", "0", "--out", self.tmp.name)
        rc, out = run_main(argv, base_env(), start_logger=start_logger, overrides=FAST, run_defaults=FAST_RUN)
        self.assertEqual(rc, 3, out)
        self.assertIn("does not send syslog", out)
        self.assertEqual(self.board.invite_users, [])

    def test_a_wrong_pin_is_invalid_and_never_printed(self):
        rc, out = self.go(env=base_env(PD_BOARD_ADMIN_PIN="wrong-pin-9"))
        self.assertEqual(rc, 3, out)
        self.assertIn("admin login answered 401", out)
        self.assertNotIn("wrong-pin-9", out)
        self.assertEqual(self.board.invite_users, [])

    def test_a_secret_the_redactor_could_not_see_is_withheld(self):
        self.board.leak_status = True        # status.jsonl is written by the logger, not redacted
        rc, out = self.go()
        self.assertEqual(rc, 3, out)
        self.assertIn("status.jsonl", self.manifest["withheld"])
        self.assert_no_secret_anywhere(out)


if __name__ == "__main__":
    unittest.main()
