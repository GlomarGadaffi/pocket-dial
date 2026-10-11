#!/usr/bin/env python3
"""Judge every SIP message the PBX emitted (Part of #199).

Input is the transcript EmittedConformance_test.cpp writes when
PD_EMITTED_TRANSCRIPT is set: one JSON object per line, per scenario a "meta"
record naming the simulated parties, then every stimulus ("in") and every
emitted datagram ("out") in order.

Each outbound message is judged twice:
  * by pjsip (pjsip_check.c, linked against a built pjproject): parse errors,
    missing mandatory headers, bad status codes and unparseable SDP are all
    things a pjsip phone drops or rejects;
  * by the RFC 3261 checklist below, which needs the conversation around the
    message (the request a response answers, whose tag is whose, the INVITE
    an ACK or CANCEL belongs to, the offer an answer answers).

Every violation must match a line of the allowlist, and every allowlist line
must still match a violation, so the list can only shrink: fix a bug and its
line has to go; introduce one and the gate goes red. Lines carry the issue
that tracks them.

    emitted_conformance.py TRANSCRIPT --allowlist FILE [--pjsip-build DIR]

Exit 0 when clean against the allowlist, 1 on any unlisted violation, stale
allowlist line or coverage hole, 2 on a harness error.
"""

import argparse
import fnmatch
import json
import os
import re
import subprocess
import sys
from collections import Counter, defaultdict

# Ceiling on allowlist lines. Lowering it is how a fix PR proves it shrank the
# list; raising it needs a reviewer to accept a new known violation.
MAX_ALLOWLIST = 2

# What this PBX implements, independent of what it claims: the request
# dispatch table (RequestsHandler.cpp, `_handlers.emplace`) plus INFO, which
# handle() takes before the table. Allow on an AUTHORED message must not claim
# more (a narrower Allow, like the trunk leg's, is an honest under-claim).
IMPLEMENTED_METHODS = {"INVITE", "ACK", "CANCEL", "BYE", "OPTIONS", "REGISTER",
                       "INFO", "MESSAGE", "REFER", "SUBSCRIBE", "UPDATE"}
# Option tags with an implementation behind them (RFC 3891 Replaces, RFC 4028
# Session Timers #198). Not "100rel": it is honoured only in Require on the 777
# echo INVITE (#172), so Supported never claims it.
IMPLEMENTED_OPTION_TAGS = {"replaces", "timer"}

# Every message type the brief requires the scenarios to make the PBX emit.
# A type that stops being emitted fails the run, so coverage can't rot.
REQUIRED_REQUESTS = {"REGISTER", "INVITE", "re-INVITE", "ACK", "BYE", "CANCEL",
                     "OPTIONS", "NOTIFY", "UPDATE"}
REQUIRED_STATUSES = {100, 180, 183, 200, 202, 400, 401, 403, 404, 422, 480, 481,
                     415, 420, 486, 487, 488, 489, 491, 503, 603}
# Codes the PBX never ORIGINATES (grep of src/SIP at d210d21 finds no emit site)
# and that no scenario can make it relay. Listed so the report says so; if one
# starts being emitted the run fails until it moves to REQUIRED_STATUSES.
NOT_EMITTED = {
    408: "no emit site; a Timer B/F expiry only logs (#726)",
    500: "emit sites need an RTP start or voicemail buffer failure the host cannot provoke",
}

COMPACT = {"v": "via", "f": "from", "t": "to", "i": "call-id", "m": "contact",
           "l": "content-length", "c": "content-type", "k": "supported",
           "o": "event", "r": "refer-to", "b": "referred-by", "u": "allow-events",
           "e": "content-encoding", "s": "subject", "x": "session-expires"}
LIST_HEADERS = {"via", "route", "record-route", "allow", "supported", "contact"}


def split_list(value):
    """Split a comma-separated header value, ignoring commas in <> or quotes."""
    out, cur, depth, quote = [], "", 0, False
    for ch in value:
        if ch == '"':
            quote = not quote
        elif not quote and ch == "<":
            depth += 1
        elif not quote and ch == ">":
            depth -= 1
        if ch == "," and depth == 0 and not quote:
            out.append(cur.strip())
            cur = ""
        else:
            cur += ch
    if cur.strip():
        out.append(cur.strip())
    return out


class Msg:
    def __init__(self, raw):
        self.raw = raw
        head, sep, self.body = raw.partition("\r\n\r\n")
        self.terminated = bool(sep)
        lines = head.split("\r\n")
        self.start = lines[0]
        self.hdrs = []
        for ln in lines[1:]:
            if ln[:1] in (" ", "\t") and self.hdrs:
                n, v = self.hdrs[-1]
                self.hdrs[-1] = (n, v + " " + ln.strip())
                continue
            name, _, val = ln.partition(":")
            n = name.strip().lower()
            n = COMPACT.get(n, n)
            val = val.strip()
            if n in LIST_HEADERS:
                self.hdrs.extend((n, v) for v in split_list(val))
            else:
                self.hdrs.append((n, val))
        parts = self.start.split(" ")
        self.is_resp = self.start.startswith("SIP/2.0 ")
        self.status = int(parts[1]) if self.is_resp and len(parts) > 1 and parts[1].isdigit() else 0
        self.method = "" if self.is_resp else parts[0]
        self.ruri = "" if self.is_resp or len(parts) < 2 else parts[1]

    def all(self, name):
        return [v for n, v in self.hdrs if n == name]

    def get(self, name):
        v = self.all(name)
        return v[0] if v else None

    @property
    def call_id(self):
        return self.get("call-id") or ""

    @property
    def cseq(self):
        v = (self.get("cseq") or "").split()
        num = int(v[0]) if v and v[0].isdigit() else -1
        return num, (v[1] if len(v) > 1 else "")

    @property
    def branch(self):
        via = self.get("via") or ""
        m = re.search(r";\s*branch=([^;,\s]+)", via)
        return m.group(1) if m else ""

    def tags(self, name):
        return header_tags(self.get(name) or "")

    def tag(self, name):
        t = self.tags(name)
        return t[0] if t else ""

    def kind(self):
        """REGISTER / INVITE / re-INVITE / ... for requests, the code for responses."""
        if self.is_resp:
            return self.status
        if self.method == "INVITE" and self.tag("to"):
            return "re-INVITE"
        return self.method


def header_tags(value):
    """All tag= params of a From/To value (outside the <> URI)."""
    params = value[value.index(">") + 1:] if "<" in value and ">" in value else value
    return re.findall(r";\s*tag=([^;>,\s]+)", params)


def uri_of(value):
    if "<" in value:
        return value[value.index("<") + 1:value.index(">")]
    return value.split(";")[0].strip()


def uri_key(uri):
    """host:port of a SIP URI (where the request actually lands), port defaulted."""
    m = re.match(r"sips?:(?:[^@;>]*@)?([^:;>?]+)(?::(\d+))?", uri.strip())
    if not m:
        return uri.strip()
    return "%s:%s" % (m.group(1).lower(), m.group(2) or "5060")


def sdp_direction(sdp):
    """Direction of the first audio stream (media level beats session level)."""
    session, media, in_media = None, None, False
    for ln in sdp.split("\r\n"):
        if ln.startswith("m="):
            if in_media:
                break
            in_media = True
        m = re.match(r"a=(sendrecv|sendonly|recvonly|inactive)$", ln)
        if m:
            if in_media:
                media = m.group(1)
            else:
                session = m.group(1)
    return media or session or "sendrecv"


def sdp_origin_user(sdp):
    m = re.search(r"^o=(\S+)", sdp, re.M)
    return m.group(1) if m else ""


COMPATIBLE_ANSWER = {
    "sendrecv": {"sendrecv", "sendonly", "recvonly", "inactive"},
    "sendonly": {"recvonly", "inactive"},
    "recvonly": {"sendonly", "inactive"},
    "inactive": {"inactive"},
}


class Scenario:
    def __init__(self, name):
        self.name = name
        self.parties = {}          # peer -> party name
        self.recs = []             # (kind, peer, Msg)

    def party(self, peer):
        return self.parties.get(peer, "?")

    def owns(self, peer, tag):
        name = self.parties.get(peer)
        return bool(name) and tag.startswith(name + "-tag")


def label(scn, peer, m):
    who = scn.party(peer)
    if m.is_resp:
        return "%d/%s->%s" % (m.status, m.cseq[1], who)
    return "%s->%s" % ("re-INVITE" if m.kind() == "re-INVITE" else m.method, who)


def check_scenario(scn):
    """RFC 3261 checklist over one scenario. Returns [(rule, label, index, detail)]."""
    v = []
    inbound_req = {}                    # (peer, branch, method) -> Msg
    out_invite = {}                     # (peer, call-id, cseq) -> Msg
    finals = {}                         # (peer, call-id, cseq) -> status of the peer's final
    acked = set()                       # (peer, call-id, cseq) the PBX ACKed
    contact = {}                        # (peer, call-id) -> last Contact URI the peer sent
    rroute = {}                         # (peer, call-id) -> Record-Route the peer sent
    offers = {}                         # (peer, call-id, cseq) -> the peer's SDP offer
    out_final = {}                      # (peer, branch, method) -> first final status sent
    inbound_allow, inbound_supported = set(), set()

    for idx, (kind, peer, m) in enumerate(scn.recs):
        cid = m.call_id
        if kind == "in":
            if m.get("contact") and (not m.is_resp or m.status < 300):
                contact[(peer, cid)] = uri_of(m.get("contact"))
            if m.all("record-route") and (not m.is_resp or m.status < 300):
                rroute[(peer, cid)] = m.all("record-route")
            if m.get("allow"):
                inbound_allow.add(frozenset(t.strip().upper() for t in m.all("allow")))
            if m.get("supported") is not None:
                inbound_supported.add(frozenset(t.strip().lower() for t in m.all("supported")))
            if not m.is_resp:
                inbound_req[(peer, m.branch, m.method)] = m
                if m.body and m.method in ("INVITE", "UPDATE"):
                    offers[(peer, cid, m.cseq[0])] = m.body
            elif m.cseq[1] == "INVITE" and m.status >= 200:
                finals.setdefault((peer, cid, m.cseq[0]), m.status)
            continue

        lab = label(scn, peer, m)

        def bad(rule, detail):
            v.append((rule, lab, idx, detail))

        # ── framing ──────────────────────────────────────────────────────────
        head = m.raw.partition("\r\n\r\n")[0]
        if not m.terminated:
            bad("crlf", "no CRLF CRLF between headers and body")
        if re.search(r"(?<!\r)\n|\r(?!\n)", head):
            bad("crlf", "bare CR or LF in the header section")
        body_bytes = len(m.body.encode("latin-1"))
        clen = m.get("content-length")
        if clen is None:
            bad("content-length", "no Content-Length (mandatory over UDP when a body may follow)")
        elif not clen.isdigit() or int(clen) != body_bytes:
            bad("content-length", "Content-Length %s but the body is %d bytes" % (clen, body_bytes))
        if body_bytes and not m.get("content-type"):
            bad("content-type", "a %d-byte body with no Content-Type" % body_bytes)

        # ── mandatory headers ────────────────────────────────────────────────
        for h in ("via", "from", "to", "call-id", "cseq"):
            if not m.get(h):
                bad("mandatory", "no %s" % h)
        if not m.is_resp:
            if m.get("max-forwards") is None:
                bad("mandatory", "request without Max-Forwards (§8.1.1.6)")
            if m.method in ("INVITE", "UPDATE", "SUBSCRIBE", "NOTIFY", "REFER") and not m.get("contact"):
                bad("mandatory", "%s without Contact (§8.1.1.8)" % m.method)
            if m.cseq[1] and m.cseq[1] != m.method:
                bad("cseq-method", "CSeq method %s on a %s" % (m.cseq[1], m.method))
            if not m.branch.startswith("z9hG4bK"):
                bad("via-branch", "top Via branch '%s' lacks the z9hG4bK magic cookie (§8.1.1.7)" % m.branch)
        else:
            if m.cseq[1] in ("INVITE", "UPDATE", "SUBSCRIBE") and 200 <= m.status < 300 and not m.get("contact"):
                bad("mandatory", "2xx to %s without Contact (§12.1.1)" % m.cseq[1])
            if m.cseq[1] == "INVITE" and 100 < m.status < 200 and m.tag("to") and not m.get("contact"):
                bad("mandatory", "dialog-creating %d without Contact (§12.1.1)" % m.status)

        # ── tags ─────────────────────────────────────────────────────────────
        for h in ("from", "to"):
            if len(m.tags(h)) > 1:
                bad("tag-dup", "%s carries %d tag parameters" % (h.capitalize(), len(m.tags(h))))
        if m.is_resp and m.status != 100 and not m.tag("to"):
            bad("to-tag", "%d without a To tag (§8.2.6.2)" % m.status)

        # ── responses echo their request ─────────────────────────────────────
        if m.is_resp:
            req = inbound_req.get((peer, m.branch, m.cseq[1]))
            if req is None:
                bad("echo", "answers no request this peer sent (top Via branch %s, CSeq %s)" % (m.branch, m.get("cseq")))
            else:
                if m.call_id != req.call_id:
                    bad("echo", "Call-ID %s, request had %s" % (m.call_id, req.call_id))
                if m.cseq != req.cseq:
                    bad("echo", "CSeq %s, request had %s" % (m.get("cseq"), req.get("cseq")))
                if uri_of(m.get("from") or "") != uri_of(req.get("from") or "") or m.tag("from") != req.tag("from"):
                    bad("echo", "From '%s', request had '%s'" % (m.get("from"), req.get("from")))
                if uri_of(m.get("to") or "") != uri_of(req.get("to") or ""):
                    bad("echo", "To URI '%s', request had '%s'" % (m.get("to"), req.get("to")))
                if req.tag("to") and m.tag("to") != req.tag("to"):
                    bad("echo", "To tag '%s' replaces the request's '%s'" % (m.tag("to"), req.tag("to")))
            if m.status >= 200:
                key = (peer, m.branch, m.cseq[1])
                first = out_final.setdefault(key, m.status)
                if first != m.status:
                    bad("double-final", "a %d after a %d on the same %s transaction (§17.2.1)"
                        % (m.status, first, m.cseq[1]))
            # A 2xx to a target-refresh request (or a 3xx) whose Contact is the
            # requester's own points the requester's dialog at itself.
            if req is not None and m.get("contact") and req.get("contact") and \
                    ((200 <= m.status < 300 and m.cseq[1] in ("INVITE", "UPDATE", "SUBSCRIBE"))
                     or 300 <= m.status < 400) and \
                    uri_key(uri_of(m.get("contact"))) == uri_key(uri_of(req.get("contact"))):
                bad("contact-echo", "Contact %s is the requester's own: its remote target now points at itself (§12.2.1.2)"
                    % uri_of(m.get("contact")))
            # A registrar's 2xx lists the current bindings (§10.3 step 8): the
            # phone that just registered must find its own Contact in it.
            if req is not None and m.cseq[1] == "REGISTER" and 200 <= m.status < 300 and \
                    req.get("contact") and req.get("contact") != "*":
                exp = req.get("expires")
                if not (exp is not None and exp.strip() == "0"):
                    want = uri_key(uri_of(req.get("contact")))
                    if want not in [uri_key(uri_of(c)) for c in m.all("contact")]:
                        bad("register-binding", "the 2xx lists Contact %s, not the binding just registered (%s) (§10.3)"
                            % (", ".join(uri_of(c) for c in m.all("contact")) or "none", uri_of(req.get("contact"))))
            # SDP in a response answers the peer's offer, if it made one.
            if m.body and req is not None and req.body and m.cseq[1] in ("INVITE", "UPDATE"):
                check_answer(bad, req.body, m.body)
            elif (m.body and m.cseq[1] == "INVITE" and sdp_origin_user(m.body).endswith("-answer")
                    and sdp_direction(m.body) != "sendrecv"):
                bad("sdp-answer-as-offer", "a %s answer (o=%s) sent as the offer in a %d"
                    % (sdp_direction(m.body), sdp_origin_user(m.body), m.status))
            if m.cseq[1] == "CANCEL" and m.status not in (200, 481):
                bad("cancel-response", "a CANCEL answered %d; only 200 or 481 exist for it (§9.2)" % m.status)
        else:
            # ── requests ────────────────────────────────────────────────────
            if m.method == "INVITE":
                out_invite[(peer, cid, m.cseq[0])] = m
            if (m.body and m.method in ("INVITE", "UPDATE") and sdp_origin_user(m.body).endswith("-answer")
                    and sdp_direction(m.body) != "sendrecv"):
                bad("sdp-answer-as-offer", "o=%s is a %s answer, re-sent as a new offer (RFC 3264 §8)"
                    % (sdp_origin_user(m.body), sdp_direction(m.body)))
            if m.method == "ACK" and m.body:
                offer = offers.get((peer, cid, m.cseq[0]))
                if offer:
                    check_answer(bad, offer, m.body)

            to_tag, from_tag = m.tag("to"), m.tag("from")
            if to_tag and peer in scn.parties:
                if not scn.owns(peer, to_tag):
                    bad("dialog-orientation", "To tag '%s' is not the recipient's own tag (§12.2.1.1)" % to_tag)
                if scn.owns(peer, from_tag):
                    bad("dialog-orientation", "From tag '%s' is the recipient's own tag: From/To swapped" % from_tag)

            inv = out_invite.get((peer, cid, m.cseq[0]))
            if m.method == "CANCEL":
                if inv is None or inv.branch != m.branch:
                    bad("cancel", "CANCEL matches no INVITE sent to this peer (Call-ID/CSeq/branch)")
                else:
                    if m.ruri != inv.ruri:
                        bad("cancel", "Request-URI %s, the INVITE's was %s (§9.1)" % (m.ruri, inv.ruri))
                    if m.get("to") != inv.get("to") or m.get("from") != inv.get("from"):
                        bad("cancel", "From/To differ from the INVITE's (§9.1)")
                    if m.body:
                        bad("cancel", "CANCEL carries a body")
            elif m.method == "ACK" and inv is not None:
                acked.add((peer, cid, m.cseq[0]))
                final = finals.get((peer, cid, m.cseq[0]))
                if final is not None and final >= 300:
                    if m.branch != inv.branch or m.ruri != inv.ruri:
                        bad("ack", "ACK for a %d must reuse the INVITE's branch and Request-URI (§17.1.1.3)" % final)
                elif final is not None and m.branch == inv.branch:
                    bad("ack", "ACK for a 2xx reuses the INVITE's branch; it is a new transaction (§13.2.2.4)")

            if to_tag and m.method != "CANCEL":
                target = contact.get((peer, cid))
                final = finals.get((peer, cid, m.cseq[0]))
                non2xx_ack = m.method == "ACK" and final is not None and final >= 300
                if target and not non2xx_ack and uri_key(m.ruri) != uri_key(target):
                    bad("route", "Request-URI %s is not the peer's Contact %s (§12.2.1.1)" % (m.ruri, target))
                rr = rroute.get((peer, cid))
                if rr and not non2xx_ack:
                    routes = [uri_of(r) for r in m.all("route")]
                    missing = [uri_of(r) for r in rr if uri_of(r) not in routes]
                    if missing:
                        bad("route", "the peer's Record-Route %s is missing from Route (§12.2.1.1)" % ", ".join(missing))

        # ── capabilities (authored messages only; a relay keeps the peer's) ──
        allow = m.all("allow")
        if allow:
            tokens = frozenset(t.strip().upper() for t in allow)
            if not tokens <= IMPLEMENTED_METHODS and tokens not in inbound_allow:
                bad("allow", "Allow claims %s, which nothing implements" % sorted(tokens - IMPLEMENTED_METHODS))
        sup = m.all("supported")
        if sup:
            tokens = frozenset(t.strip().lower() for t in sup)
            if tokens not in inbound_supported and not tokens <= IMPLEMENTED_OPTION_TAGS:
                bad("supported", "Supported %s claims an option tag with no implementation" % sorted(tokens))

    # ── after the fact: every non-2xx final to our INVITE is ACKed ───────────
    for (peer, cid, cseq), status in finals.items():
        if status >= 300 and (peer, cid, cseq) in out_invite and (peer, cid, cseq) not in acked:
            v.append(("ack-missing", "%d/INVITE->%s" % (status, scn.party(peer)), len(scn.recs),
                      "the %d to the INVITE sent to %s (Call-ID %s) was never ACKed (§17.1.1.3)" % (status, scn.party(peer), cid)))
    return v


def check_answer(bad, offer, answer):
    od, ad = sdp_direction(offer), sdp_direction(answer)
    if ad not in COMPATIBLE_ANSWER.get(od, {ad}):
        bad("sdp-direction", "answer is %s to a %s offer (RFC 3264 §6.1)" % (ad, od))
    if offer.count("\r\nm=") + offer.startswith("m=") != answer.count("\r\nm=") + answer.startswith("m="):
        bad("sdp-direction", "answer's m= line count differs from the offer's (RFC 3264 §6)")


# ─────────────────────────────────────────────────────────────────────────────

def load(path):
    scns, order = {}, []
    with open(path, encoding="utf-8") as f:
        for n, line in enumerate(f, 1):
            if not line.strip():
                continue
            r = json.loads(line)
            s = scns.get(r["s"])
            if s is None:
                s = scns[r["s"]] = Scenario(r["s"])
                order.append(s)
            if r["k"] == "meta":
                s.parties = {p["peer"]: p["name"] for p in r["parties"]}
            else:
                s.recs.append((r["k"], r["peer"], Msg(r["raw"])))
    return order


def load_allowlist(path):
    entries, errors = [], []
    with open(path, encoding="utf-8") as f:
        for n, line in enumerate(f, 1):
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            parts = line.split()
            if len(parts) < 4 or not re.fullmatch(r"#\d+", parts[3]):
                errors.append("allowlist line %d needs 'rule scenario label #issue': %s" % (n, line.strip()))
                continue
            pats = {("scenario", p): 0 for p in parts[1].split(",")}
            pats.update({("label", p): 0 for p in parts[2].split(",")})
            entries.append({"line": n, "rule": parts[0], "issue": parts[3], "text": line.strip(),
                            "hits": 0, "pattern_hits": pats})
    return entries, errors


def run_pjsip(scenarios, build_dir, here):
    """Feed every outbound message to pjsip. Returns {(scenario, idx): reason} or None if skipped."""
    pjdir = os.environ.get("PJDIR") or os.path.expanduser("~/pjproject")
    if not os.path.isfile(os.path.join(pjdir, "build.mak")):
        if os.environ.get("PD_CONFORMANCE_ALLOW_NO_PJSIP") == "1":
            print("WARNING: no pjproject at %s; pjsip stage SKIPPED (PD_CONFORMANCE_ALLOW_NO_PJSIP=1)" % pjdir)
            return None
        raise SystemExit("ERROR: no built pjproject at %s (set PJDIR). The gate never skips the "
                         "pjsip stage; set PD_CONFORMANCE_ALLOW_NO_PJSIP=1 only on a dev box." % pjdir)
    os.makedirs(build_dir, exist_ok=True)
    exe = os.path.join(build_dir, "pjsip_check")
    r = subprocess.run(["make", "-s", "-C", here, "PJDIR=" + pjdir, "OUT=" + exe],
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)
    if r.returncode != 0:
        raise SystemExit("ERROR: building pjsip_check failed:\n" + r.stdout)
    corpus = os.path.join(build_dir, "emitted_corpus.bin")
    index = []
    with open(corpus, "wb") as f:
        for s in scenarios:
            for i, (kind, _peer, m) in enumerate(s.recs):
                if kind != "out":
                    continue
                b = m.raw.encode("latin-1")
                f.write(b"%d\n" % len(b) + b)
                index.append((s.name, i))
    r = subprocess.run([exe, corpus], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    if r.returncode != 0:
        raise SystemExit("ERROR: pjsip_check failed: " + r.stderr)
    fails, seen = {}, 0
    for line in r.stdout.splitlines():
        idx, _, rest = line.partition(" ")
        seen += 1
        if rest.startswith("FAIL "):
            fails[index[int(idx)]] = rest[5:]
    if seen != len(index):
        raise SystemExit("ERROR: pjsip_check judged %d of %d messages" % (seen, len(index)))
    return fails


def main(argv=None):
    here = os.path.dirname(os.path.abspath(__file__))
    ap = argparse.ArgumentParser()
    ap.add_argument("transcript")
    ap.add_argument("--allowlist", default=os.path.join(here, "emitted_allowlist.txt"))
    ap.add_argument("--pjsip-build", default=os.path.join(os.getcwd(), "pjsip_check_build"))
    ap.add_argument("--no-pjsip", action="store_true", help="checklist only (self-tests)")
    a = ap.parse_args(argv)

    scenarios = load(a.transcript)
    if not scenarios:
        print("ERROR: empty transcript %s -- the scenarios did not run" % a.transcript)
        return 2
    entries, errors = load_allowlist(a.allowlist)

    violations = []   # (rule, scenario, label, detail, first line)
    for s in scenarios:
        for rule, lab, idx, detail in check_scenario(s):
            first = s.recs[idx][2].start if idx < len(s.recs) else ""
            violations.append((rule, s.name, lab, detail, first))
    pj = None if a.no_pjsip else run_pjsip(scenarios, a.pjsip_build, here)
    for (sname, idx), reason in (pj or {}).items():
        s = next(x for x in scenarios if x.name == sname)
        _k, peer, m = s.recs[idx]
        violations.append(("pjsip", sname, label(s, peer, m), reason, m.start))

    # De-duplicate identical findings (a retransmission is the same finding).
    violations = sorted(set(violations))
    unlisted = []
    for vi in violations:
        rule, sname, lab = vi[0], vi[1], vi[2]
        hit = []
        for e in entries:
            if e["rule"] != rule:
                continue
            spats = [k for k in e["pattern_hits"] if k[0] == "scenario" and fnmatch.fnmatchcase(sname, k[1])]
            lpats = [k for k in e["pattern_hits"] if k[0] == "label" and fnmatch.fnmatchcase(lab, k[1])]
            if spats and lpats:
                hit.append(e)
                e["hits"] += 1
                for k in spats + lpats:
                    e["pattern_hits"][k] += 1
        if not hit:
            unlisted.append(vi)

    # Coverage.
    out_kinds = Counter()
    for s in scenarios:
        for kind, _p, m in s.recs:
            if kind == "out":
                out_kinds[m.kind()] += 1
    missing = sorted(str(k) for k in (REQUIRED_REQUESTS | REQUIRED_STATUSES) if out_kinds[k] == 0)
    now_emitted = sorted(k for k in NOT_EMITTED if out_kinds[k])

    total_out = sum(out_kinds.values())
    print("emitted-conformance: %d scenarios, %d outbound messages, %d violations (%d allowlisted), pjsip stage %s"
          % (len(scenarios), total_out, len(violations), len(violations) - len(unlisted),
             "SKIPPED" if pj is None and not a.no_pjsip else ("off" if a.no_pjsip else "ran")))
    print("coverage: " + ", ".join("%s x%d" % (k, n) for k, n in sorted(out_kinds.items(), key=lambda kv: str(kv[0]))))
    for code, why in sorted(NOT_EMITTED.items()):
        print("not emitted: %d (%s)" % (code, why))

    failed = False
    for rule, sname, lab, detail, first in unlisted:
        print("VIOLATION %s %s %s: %s  [%s]" % (rule, sname, lab, detail, first))
        failed = True
    for e in entries:
        if e["hits"] == 0:
            print("STALE allowlist line %d (%s): matches nothing now -- the bug is fixed or moved; remove the line"
                  % (e["line"], e["text"]))
            failed = True
        else:
            for (field, p), n in e["pattern_hits"].items():
                if n == 0:
                    print("STALE allowlist line %d: %s pattern '%s' matches nothing now; remove it from the line"
                          % (e["line"], field, p))
                    failed = True
    for err in errors:
        print("ERROR " + err)
        failed = True
    if len(entries) > MAX_ALLOWLIST:
        print("ERROR allowlist has %d lines, ceiling is %d: it only shrinks" % (len(entries), MAX_ALLOWLIST))
        failed = True
    for k in missing:
        print("COVERAGE no scenario made the PBX emit %s" % k)
        failed = True
    for k in now_emitted:
        print("COVERAGE %d is emitted now; move it from NOT_EMITTED to REQUIRED_STATUSES" % k)
        failed = True
    for e in entries:
        if e["hits"]:
            print("known (%s) x%d: %s" % (e["issue"], e["hits"], e["text"]))
    print("RESULT: %s" % ("FAIL" if failed else "PASS"))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
