#!/usr/bin/env python3
"""Self-test for tests/conformance/emitted_conformance.py (Part of #199).

    python3 -m unittest discover -s tests/tools -p 'test_emitted_conformance.py'

Each rule is shown firing on a bad message AND staying quiet on the good one
next to it, so neither a dead rule nor a trigger-happy one passes. The pjsip
stage gets its own negative control when a pjproject tree is present.
"""

import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "conformance"))
import emitted_conformance as ec  # noqa: E402

PHONE = "10.0.0.2:5060"
PBX_REQ_HEAD = "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bKpbx1\r\n"


def msg(lines, body=""):
    head = "\r\n".join(lines) + "\r\n"
    if "Content-Length" not in head:
        head += "Content-Length: %d\r\n" % len(body)
    return head + "\r\n" + body


def invite_from_phone(branch="z9hG4bKph1", body=""):
    return msg(["INVITE sip:200@10.0.0.1 SIP/2.0",
                "Via: SIP/2.0/UDP 10.0.0.2:5060;branch=" + branch,
                "From: <sip:100@10.0.0.1>;tag=pa-tag1", "To: <sip:200@10.0.0.1>",
                "Call-ID: c1", "CSeq: 1 INVITE", "Max-Forwards: 70",
                "Contact: <sip:100@10.0.0.2:5060>"] +
               (["Content-Type: application/sdp"] if body else []), body)


def response_to_phone(status="486 Busy Here", to_tag=";tag=x1", cseq="1 INVITE", extra=(), body=""):
    return msg(["SIP/2.0 " + status,
                "Via: SIP/2.0/UDP 10.0.0.2:5060;branch=z9hG4bKph1",
                "From: <sip:100@10.0.0.1>;tag=pa-tag1", "To: <sip:200@10.0.0.1>" + to_tag,
                "Call-ID: c1", "CSeq: " + cseq] + list(extra) +
               (["Content-Type: application/sdp"] if body else []), body)


def sdp(user, direction):
    return ("v=0\r\no=%s 1 1 IN IP4 10.0.0.2\r\ns=-\r\nc=IN IP4 10.0.0.2\r\nt=0 0\r\n"
            "m=audio 4000 RTP/AVP 0\r\na=%s\r\n" % (user, direction))


def rules(recs):
    s = ec.Scenario("t")
    s.parties = {PHONE: "pa"}
    s.recs = [(k, PHONE, ec.Msg(raw)) for k, raw in recs]
    return sorted({r[0] for r in ec.check_scenario(s)})


class Rules(unittest.TestCase):
    def test_a_well_formed_exchange_is_clean(self):
        self.assertEqual(rules([("in", invite_from_phone()), ("out", response_to_phone())]), [])

    def test_content_length(self):
        bad = response_to_phone().replace("Content-Length: 0", "Content-Length: 12")
        self.assertIn("content-length", rules([("in", invite_from_phone()), ("out", bad)]))

    def test_bare_lf(self):
        bad = response_to_phone().replace("Call-ID: c1\r\n", "Call-ID: c1\n")
        self.assertIn("crlf", rules([("in", invite_from_phone()), ("out", bad)]))

    def test_to_tag(self):
        self.assertIn("to-tag", rules([("in", invite_from_phone()), ("out", response_to_phone(to_tag=""))]))
        self.assertNotIn("to-tag", rules([("in", invite_from_phone()),
                                          ("out", response_to_phone("100 Trying", to_tag=""))]))

    def test_second_to_tag(self):
        self.assertIn("tag-dup", rules([("in", invite_from_phone()),
                                        ("out", response_to_phone(to_tag=";tag=x1;tag=x2"))]))

    def test_echo(self):
        self.assertIn("echo", rules([("in", invite_from_phone()), ("out", response_to_phone(cseq="2 INVITE"))]))

    def test_cancel_response(self):
        cancel = invite_from_phone().replace("INVITE sip", "CANCEL sip").replace("1 INVITE", "1 CANCEL")
        self.assertIn("cancel-response", rules([("in", cancel),
                                                ("out", response_to_phone("404 Not Found", cseq="1 CANCEL"))]))
        self.assertNotIn("cancel-response", rules([("in", cancel),
                                                   ("out", response_to_phone("200 OK", cseq="1 CANCEL"))]))

    def test_dialog_orientation_catches_a_from_to_swap(self):
        # #700's shape: a BYE to the phone carrying the phone's own tag in From.
        swapped = msg(["BYE sip:100@10.0.0.2:5060 SIP/2.0", PBX_REQ_HEAD.strip(),
                       "From: <sip:100@10.0.0.1>;tag=pa-tag1", "To: <sip:200@10.0.0.1>;tag=x1",
                       "Call-ID: c1", "CSeq: 2 BYE", "Max-Forwards: 70"])
        right = swapped.replace("tag=pa-tag1", "tag=TMP").replace("tag=x1", "tag=pa-tag1").replace("tag=TMP", "tag=x1")
        self.assertIn("dialog-orientation", rules([("out", swapped)]))
        self.assertNotIn("dialog-orientation", rules([("out", right)]))

    def test_via_branch_cookie(self):
        req = msg(["OPTIONS sip:100@10.0.0.2:5060 SIP/2.0",
                   "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=abc123",
                   "From: <sip:server@10.0.0.1>;tag=s1", "To: <sip:100@10.0.0.2>",
                   "Call-ID: o1", "CSeq: 1 OPTIONS", "Max-Forwards: 70"])
        self.assertIn("via-branch", rules([("out", req)]))
        self.assertNotIn("via-branch", rules([("out", req.replace("branch=abc123", "branch=z9hG4bKabc123"))]))

    def test_ack_missing_and_cancel_match(self):
        inv = msg(["INVITE sip:100@10.0.0.2:5060 SIP/2.0", PBX_REQ_HEAD.strip(),
                   "From: <sip:pbx@10.0.0.1>;tag=s1", "To: <sip:100@10.0.0.1>", "Call-ID: b1",
                   "CSeq: 1 INVITE", "Max-Forwards: 70", "Contact: <sip:pbx@10.0.0.1>"])
        busy = msg(["SIP/2.0 486 Busy Here", PBX_REQ_HEAD.strip(), "From: <sip:pbx@10.0.0.1>;tag=s1",
                    "To: <sip:100@10.0.0.1>;tag=pa-tag9", "Call-ID: b1", "CSeq: 1 INVITE"])
        ack = msg(["ACK sip:100@10.0.0.2:5060 SIP/2.0", PBX_REQ_HEAD.strip(), "From: <sip:pbx@10.0.0.1>;tag=s1",
                   "To: <sip:100@10.0.0.1>;tag=pa-tag9", "Call-ID: b1", "CSeq: 1 ACK", "Max-Forwards: 70"])
        self.assertIn("ack-missing", rules([("out", inv), ("in", busy)]))
        self.assertEqual(rules([("out", inv), ("in", busy), ("out", ack)]), [])
        bad_cancel = msg(["CANCEL sip:100@10.0.0.9:5060 SIP/2.0", PBX_REQ_HEAD.strip(),
                          "From: <sip:pbx@10.0.0.1>;tag=s1", "To: <sip:100@10.0.0.1>", "Call-ID: b1",
                          "CSeq: 1 CANCEL", "Max-Forwards: 70"])
        self.assertIn("cancel", rules([("out", inv), ("out", bad_cancel)]))
        self.assertNotIn("cancel", rules([("out", inv), ("out", bad_cancel.replace("10.0.0.9", "10.0.0.2"))]))

    def test_double_final(self):
        self.assertIn("double-final", rules([("in", invite_from_phone()),
                                             ("out", response_to_phone("200 OK", extra=["Contact: <sip:200@10.0.0.1>"])),
                                             ("out", response_to_phone("487 Request Terminated"))]))

    def test_sdp_direction_and_answer_as_offer(self):
        offer = invite_from_phone(body=sdp("pa-offer", "sendonly"))
        ok = ["Contact: <sip:200@10.0.0.1>"]
        self.assertIn("sdp-direction", rules([("in", offer),
                                              ("out", response_to_phone("200 OK", extra=ok, body=sdp("x", "sendrecv")))]))
        self.assertNotIn("sdp-direction", rules([("in", offer),
                                                 ("out", response_to_phone("200 OK", extra=ok, body=sdp("x", "recvonly")))]))
        reoffer = msg(["INVITE sip:100@10.0.0.2:5060 SIP/2.0", PBX_REQ_HEAD.strip(),
                       "From: <sip:200@10.0.0.1>;tag=x1", "To: <sip:100@10.0.0.1>;tag=pa-tag1", "Call-ID: c1",
                       "CSeq: 5 INVITE", "Max-Forwards: 70", "Contact: <sip:200@10.0.0.1>",
                       "Content-Type: application/sdp"], sdp("pb-answer", "recvonly"))
        self.assertIn("sdp-answer-as-offer", rules([("out", reoffer)]))
        self.assertNotIn("sdp-answer-as-offer", rules([("out", reoffer.replace("recvonly", "sendrecv"))]))

    def test_register_binding(self):
        reg = msg(["REGISTER sip:10.0.0.1 SIP/2.0", "Via: SIP/2.0/UDP 10.0.0.2:5060;branch=z9hG4bKr1",
                   "From: <sip:100@10.0.0.1>;tag=pa-tag1", "To: <sip:100@10.0.0.1>", "Call-ID: r1",
                   "CSeq: 1 REGISTER", "Max-Forwards: 70", "Contact: <sip:100@10.0.0.2:5060>", "Expires: 60"])

        def ok(contact):
            return msg(["SIP/2.0 200 OK", "Via: SIP/2.0/UDP 10.0.0.2:5060;branch=z9hG4bKr1",
                        "From: <sip:100@10.0.0.1>;tag=pa-tag1", "To: <sip:100@10.0.0.1>;tag=s9",
                        "Call-ID: r1", "CSeq: 1 REGISTER", "Contact: " + contact])
        self.assertIn("register-binding", rules([("in", reg), ("out", ok("<sip:100@10.0.0.1:5060>;expires=60"))]))
        self.assertEqual(rules([("in", reg), ("out", ok("<sip:100@10.0.0.2:5060>;expires=60"))]), [])


class Allowlist(unittest.TestCase):
    """The gate logic: unlisted fails, listed passes, stale fails, the ceiling holds."""

    def run_main(self, allow_lines, max_allow=None):
        bad = response_to_phone(to_tag="")          # one to-tag violation, label 486/INVITE->pa
        with tempfile.TemporaryDirectory() as d:
            t = os.path.join(d, "t.jsonl")
            with open(t, "w") as f:
                f.write(json.dumps({"s": "sc", "k": "meta", "parties": [{"name": "pa", "ext": "100", "peer": PHONE}]}) + "\n")
                for k, raw in (("in", invite_from_phone()), ("out", bad)):
                    f.write(json.dumps({"s": "sc", "k": k, "peer": PHONE, "raw": raw}) + "\n")
            a = os.path.join(d, "allow.txt")
            with open(a, "w") as f:
                f.write("# comment\n" + "".join(line + "\n" for line in allow_lines))
            out = io.StringIO()
            saved = ec.MAX_ALLOWLIST
            if max_allow is not None:
                ec.MAX_ALLOWLIST = max_allow
            try:
                with redirect_stdout(out):
                    rc = ec.main([t, "--allowlist", a, "--no-pjsip"])
            finally:
                ec.MAX_ALLOWLIST = saved
            return rc, out.getvalue()

    def test_unlisted_violation_fails(self):
        rc, out = self.run_main([])
        self.assertEqual(rc, 1)
        self.assertIn("VIOLATION to-tag sc 486/INVITE->pa", out)

    def test_listed_violation_passes_the_gate_part(self):
        _rc, out = self.run_main(["to-tag sc 486/INVITE->pa #702"])
        self.assertNotIn("VIOLATION", out)
        self.assertNotIn("STALE", out)

    def test_stale_line_and_stale_pattern_fail(self):
        rc, out = self.run_main(["to-tag sc 486/INVITE->pa #702", "ack * BYE->pa #1"])
        self.assertEqual(rc, 1)
        self.assertIn("STALE allowlist line", out)
        rc, out = self.run_main(["to-tag sc 486/INVITE->pa,404/INVITE->pa #702"])
        self.assertEqual(rc, 1)
        self.assertIn("pattern '404/INVITE->pa' matches nothing", out)

    def test_entry_needs_an_issue_and_the_ceiling_holds(self):
        rc, out = self.run_main(["to-tag sc 486/INVITE->pa no-issue"])
        self.assertEqual(rc, 1)
        self.assertIn("needs 'rule scenario label #issue'", out)
        rc, out = self.run_main(["to-tag sc 486/INVITE->pa #702"], max_allow=0)
        self.assertEqual(rc, 1)
        self.assertIn("it only shrinks", out)


@unittest.skipUnless(os.path.isfile(os.path.join(os.environ.get("PJDIR") or os.path.expanduser("~/pjproject"), "build.mak")),
                     "no pjproject tree: the pjsip oracle's own red run needs one")
class PjsipOracle(unittest.TestCase):
    def test_pjsip_rejects_what_it_should_and_accepts_the_rest(self):
        good = response_to_phone()
        bad = good.replace("CSeq: 1 INVITE", "CSeq: one INVITE")
        s = ec.Scenario("pj")
        s.parties = {PHONE: "pa"}
        s.recs = [("out", PHONE, ec.Msg(good)), ("out", PHONE, ec.Msg(bad))]
        with tempfile.TemporaryDirectory() as d:
            fails = ec.run_pjsip([s], d, os.path.join(HERE, "..", "conformance"))
        self.assertNotIn(("pj", 0), fails)
        self.assertIn(("pj", 1), fails)
        self.assertIn("CSeq", fails[("pj", 1)])


if __name__ == "__main__":
    unittest.main()
