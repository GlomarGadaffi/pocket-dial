#!/usr/bin/env python3
"""A dialog-capable raw-UDP SIP user agent for the #401 load profiles.

sip_stress.py's UA can only originate: it sends, then reads its own socket. The
rc1 mix also needs the answering side, because an extension-to-extension call
must be answered and a park retrieve re-INVITEs the parked party. This agent
runs one receive thread per socket. The thread hands each response to the
transaction waiting for it and answers each request itself (the UAS side).

Wire choices, each deliberate (see the PR):
  * Every request goes to the PBX's address, as to an outbound proxy (RFC 3261
    s8.1.2). An in-dialog request carries the remote target from the 2xx
    Contact as its Request-URI (s12.2.1.1).
  * A response goes to the SOURCE address of the request, not to the top Via's
    sent-by (s18.2.2). The PBX does not push its own Via on every relayed
    request, so a strict s18.2.2 reply would bypass the PBX and the harness
    would manufacture its own stuck legs. This agent therefore does not
    reproduce an RFC-strict phone on that path.
  * No digest authentication. A 401 or 407 is recorded as a failure.

Opt-in additions for the anchor scenarios (anchor_scenarios.py); every default
keeps the behaviour above:
  * invite(..., cancel_after_ms=N) CANCELs N ms after the INVITE was sent, never
    before a provisional response (s9.1), and records when it went;
  * invite(..., cancel_when=fn, cancel_when_timeout_s=T) CANCELs when the caller's own
    signal says so: fn(invite_sent_at) returns the monotonic time the CANCEL is due, or
    None while that is unknown. The wait is always bounded: at T s, or if fn raises, the
    CANCEL goes at once and the dialog says so (cancel_when_expired), so a phone is never
    left ringing. Used to time a CANCEL from a syslog line instead of from the INVITE;
  * invite(..., invite_timeout=T) bounds this call's INVITE transaction at T s instead of the agent's
    invite_timeout (16 s), for a call that must ring longer before its CANCEL;
  * Dialog.hold() / resume(): a re-INVITE offering sendonly / sendrecv (s14.1);
  * contact_params: URI parameters on the Contact (e.g. ";line=pd6101");
  * strict_dialogs: a BYE must match Call-ID AND both tags (s12.2.2), else 481;
  * Dialog.bye_log: each BYE that reached the dialog, with its Request-URI (rule 1);
  * reject_invites=<code>: every new incoming INVITE is refused and recorded.

Dial guard (target_allowed): invite() raises DialRefused, before anything is built or sent, for a target that
could leave the board through the anchor. Allowed: an extension a UA of this process registered; the PBX's own
service numbers (SERVICE_LITERALS, park 700-709, page 980-989 if the zone is configured, *8, **<ext>); extensions
named by allow_targets() or SIP_AGENT_ALLOW_TARGETS. 911, 933, 112, 113 and 555 (the anchor bridge) are refused
whatever is listed. A leading '+' or 7 or more digits is an outside number: refused unless that exact string was
opted in with allow_outside() or SIP_AGENT_ALLOW_OUTSIDE (the approved anchor runs do it for their far end).
A re-INVITE inside a dialog is no new call.

stdlib only.
"""
import os
import random
import re
import socket
import struct
import threading
import time

T1 = 0.5
T2 = 4.0

COMPACT = {"i": "call-id", "f": "from", "t": "to", "v": "via", "m": "contact",
           "l": "content-length", "c": "content-type", "k": "supported",
           "s": "subject", "e": "content-encoding", "o": "event", "x": "session-expires"}


# ---- dial guard ---------------------------------------------------------------------------------
# In SBC mode the board sends a dialed string that is neither registered nor claimed by its dial plan out
# the anchor (src/SIP/CallForker.cpp:416-436, reached only after every reserved extension, ring group and
# dial rule), so a number this harness does not know to be local can cost a real carrier call. On
# 2026-10-19 about ten calls went out as INVITE sip:+6102@... because a script dialed 6102 with no UA
# registered for it. Agent.invite() is the one place this harness starts a call, so the check lives there.

class DialRefused(Exception):
    """Agent.invite() was asked for a number the dial guard does not allow. Nothing was sent.

    Not a ValueError on purpose: callers that catch ValueError for a bad argument must not swallow it."""


ALLOW_TARGETS_ENV = "SIP_AGENT_ALLOW_TARGETS"    # comma separated extensions: registered elsewhere, or a real phone
ALLOW_OUTSIDE_ENV = "SIP_AGENT_ALLOW_OUTSIDE"    # comma separated EXACT outside numbers a run is approved to dial

# (b) Numbers the board answers itself, copied from the firmware. tests/tools/test_sip_agent_dial_guard.py
# fails if pbx::isReservedExtension() (src/SIP/PbxConfig.hpp:299-304) gains or loses a literal, or the park
# or page range moves, so a change there is a decision here. All of them are claimed in onInvite ahead of
# the dial plan and its SBC fallback (src/SIP/RequestsHandler.cpp:2641-2759), so none of them can leave
# through the anchor. docs/PHONE_COMPATIBILITY.md:88-100 is the operator-facing list.
SERVICE_LITERALS = frozenset((
    "777",   # echo test: src/SIP/RequestsHandler.cpp:2486; docs/PHONE_COMPATIBILITY.md:92
    "999",   # all-page broadcast to every registered phone: RequestsHandler.cpp:2641; PHONE_COMPATIBILITY.md:93
    "440",   # server tone stream: RequestsHandler.cpp:2682; PHONE_COMPATIBILITY.md:94
    "888",   # meet-me conference, ConferenceRoom::EXT: RequestsHandler.cpp:2689; PHONE_COMPATIBILITY.md:96
    "997",   # multicast paging, off by default (refused locally when off): RequestsHandler.cpp:127,2697; :97
    "796",   # voicemail retrieval dial-in (#246): RequestsHandler.cpp:124,2713; PbxConfig.hpp:282
))
# Firmware-reserved literals the guard does NOT allow. 555 is the anchored-media bridge: dialing it makes the
# board's AnchorClient place a call (RequestsHandler.cpp:118,2705; PbxConfig.hpp:290-296). 911/933 are the
# emergency number and its test number (src/SIP/EmergencyCall.hpp:67-68).
FIRMWARE_RESERVED_REFUSED = frozenset(("555", "911", "933"))
# 700-709: park orbits, POCKETDIAL_PARK_SLOTS = 10 (src/SIP/PoolConfig.hpp:125-126; DialPlan.hpp:198-207;
# RequestsHandler.cpp:2724-2733). A board built with fewer slots does not claim the top ones.
PARK_ORBITS = frozenset("70%d" % i for i in range(10))
# 980-989: paging zones (PbxConfig.hpp:226-232; RequestsHandler.cpp:2670-2680). UNSURE: a zone is claimed only
# when it is configured on the board; an unconfigured 98x falls through to normal routing, which in SBC mode is
# the anchor. The guard cannot see the board's zones: list only zones that are configured.
PAGE_ZONES = frozenset("98%d" % i for i in range(10))
# *8 group pickup and **<ext> directed pickup: always answered locally (PbxConfig.hpp:363-378;
# RequestsHandler.cpp:2735-2759; PHONE_COMPATIBILITY.md:100).
PICKUP_GROUP = "*8"
_DIRECTED_PICKUP = re.compile(r"\*\*[0-9]+")

# Refused whatever is registered or listed: 911, 933 (EmergencyCall.hpp:67-68), the harness's own never-dial pair
# 112, 113 (113 is the owner's phone; anchor_scenarios.NEVER_EXACT), and 555, the anchored-media bridge (dialing
# it makes the board place an anchor call: RequestsHandler.cpp:2705; load_profile.ANCHORED). Bare or behind one
# trunk-access digit '9' (kTrunkAccessDigit, EmergencyCall.hpp:71), a superset of what the board classifies.
_NEVER_DIAL = frozenset(("911", "933", "112", "113", "555"))
_DIAL_STRING = re.compile(r"\+?[0-9*#]+")

_REGISTERED = set()                  # (a) extensions a UA of THIS process holds a confirmed binding for
_REGISTERED_LOCK = threading.Lock()


def _note_registered(ext, registered):
    with _REGISTERED_LOCK:
        (_REGISTERED.add if registered else _REGISTERED.discard)(ext)


def registered_extensions():
    """A snapshot of the extensions a UA of this process has registered and not yet released."""
    with _REGISTERED_LOCK:
        return frozenset(_REGISTERED)


def _csv(name):
    return frozenset(p.strip() for p in os.environ.get(name, "").split(",") if p.strip())


def _never_dial(s):
    d = s.lstrip("+")
    return d in _NEVER_DIAL or (len(d) == 4 and d[0] == "9" and d[1:] in _NEVER_DIAL)


def _outside_looking(s):
    return s.startswith("+") or sum(c in "0123456789" for c in s) >= 7


def _is_service(s):
    return (s in SERVICE_LITERALS or s in PARK_ORBITS or s in PAGE_ZONES or s == PICKUP_GROUP
            or _DIRECTED_PICKUP.fullmatch(s) is not None)


def target_allowed(target, registered, extra=(), outside=()):
    """May the harness INVITE `target`? Returns (ok, reason). Pure: no socket, no clock, no environment.

    registered: extensions a UA of this process registered. extra: extensions the caller listed.
    outside: outside numbers the caller opted in, matched as EXACT strings. In this order:
      refused  empty, or not made only of digits, '*' and '#' (and one leading '+');
      refused  911, 933, 112, 113, 555, bare or behind one '9', whatever is registered or listed;
      allowed  a string in `outside` (an exact opt-in; the approved anchor runs use it for their far end);
      refused  a leading '+' or 7 or more digits (looks like an outside number) that is not in `outside`;
      allowed  registered, a PBX service number, or in `extra`;
      refused  everything else: the board would send it out the anchor in SBC mode."""
    s = "" if target is None else str(target)
    if not s:
        return False, "empty target"
    if not _DIAL_STRING.fullmatch(s):
        return False, "not a dial string: only digits, '*' and '#' (and one leading '+') are dialed"
    if _never_dial(s):
        return False, ("emergency or never-dial number (911, 933, 112, 113; 555 is the anchored-media bridge and "
                       "makes the board place an anchor call): refused whatever is listed")
    if s in frozenset(map(str, outside)):
        return True, "outside number opted in with allow_outside() or %s" % ALLOW_OUTSIDE_ENV
    if _outside_looking(s):
        return False, ("looks like an outside number (a leading '+', or 7 or more digits): refused unless that "
                       "exact number is opted in with allow_outside() or %s" % ALLOW_OUTSIDE_ENV)
    if s in frozenset(map(str, registered)):
        return True, "registered by a UA of this process"
    if _is_service(s):
        return True, "PBX service number"
    if s in frozenset(map(str, extra)):
        return True, "listed with allow_targets() or %s" % ALLOW_TARGETS_ENV
    return False, ("not registered by a UA of this process, not a PBX service number and not listed: in SBC mode "
                   "the board sends an unclaimed number out the anchor (list it with allow_targets() or %s "
                   "if another process or a real phone registered it)" % ALLOW_TARGETS_ENV)


def _shown(target):
    """The target as it may appear in a message: emergency numbers and short extensions as they are, anything
    that could be a real person's number (a leading '+', or 7 or more digits) as its shape only."""
    s = "" if target is None else str(target)
    if s and _DIAL_STRING.fullmatch(s) and _never_dial(s):
        return repr(s)
    if s.startswith("+") or sum(c in "0123456789" for c in s) >= 7:
        return "a number of %d digits%s (value withheld)" % (
            sum(c in "0123456789" for c in s), " with a leading '+'" if s.startswith("+") else "")
    return repr(s[:32] + ("..." if len(s) > 32 else ""))


def rand_hex(n):
    return "".join(random.choice("0123456789abcdef") for _ in range(n))


def local_ip_for(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((host, port))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


class SipMsg:
    """A parsed SIP message. Header names are lower-case long forms."""

    def __init__(self, first, headers, body):
        self.first = first
        self.headers = headers
        self.body = body
        parts = first.split(" ", 2)
        self.is_response = first.startswith("SIP/2.0 ")
        self.status = None
        self.method = None
        self.ruri = None
        if self.is_response:
            try:
                self.status = int(parts[1])
            except (IndexError, ValueError):
                self.status = 0
            self.method = self.cseq()[1]
        else:
            self.method = parts[0] if parts else ""
            self.ruri = parts[1] if len(parts) > 1 else ""

    @classmethod
    def parse(cls, data):
        text = data.decode("utf-8", "replace") if isinstance(data, bytes) else data
        head, sep, body = text.partition("\r\n\r\n")
        if not sep:
            head, sep, body = text.partition("\n\n")
        lines = head.replace("\r\n", "\n").split("\n")
        headers = []
        for line in lines[1:]:
            if not line:
                continue
            if line[0] in " \t" and headers:
                name, value = headers[-1]
                headers[-1] = (name, value + " " + line.strip())
                continue
            name, _, value = line.partition(":")
            name = name.strip().lower()
            headers.append((COMPACT.get(name, name), value.strip()))
        msg = cls(lines[0].strip(), headers, body)
        clen = msg.get("content-length")
        if clen.isdigit():
            msg.body = body[:int(clen)]
        return msg

    def get(self, name):
        for n, v in self.headers:
            if n == name:
                return v
        return ""

    def all(self, name):
        return [v for n, v in self.headers if n == name]

    def cseq(self):
        parts = self.get("cseq").split()
        try:
            return int(parts[0]), (parts[1] if len(parts) > 1 else "")
        except (IndexError, ValueError):
            return 0, ""

    def call_id(self):
        return self.get("call-id")

    def branch(self):
        m = re.search(r";\s*branch=([^;,\s]+)", self.get("via"))
        return m.group(1) if m else ""


def tag_of(value):
    m = re.search(r";\s*tag=([^;,\s>]+)", value or "")
    return m.group(1) if m else ""


def uri_of(value):
    value = value or ""
    if "<" in value:
        return value[value.index("<") + 1:value.index(">")] if ">" in value else value[value.index("<") + 1:]
    return value.split(";")[0].strip()


def user_of(uri):
    m = re.match(r"sips?:([^@;>]+)@", uri or "")
    return m.group(1) if m else ""


def parse_sdp(body):
    """-> (ip, port, direction) of the first audio section, or (None, 0, None)."""
    ip, port, direction = None, 0, "sendrecv"
    in_audio = False
    seen_audio = False
    for line in (body or "").replace("\r\n", "\n").split("\n"):
        line = line.strip()
        if line.startswith("m="):
            if seen_audio:
                break
            in_audio = line.startswith("m=audio")
            seen_audio = in_audio
            if in_audio:
                try:
                    port = int(line.split()[1])
                except (IndexError, ValueError):
                    port = 0
        elif line.startswith("c=IN IP4 ") and (in_audio or ip is None):
            ip = line[len("c=IN IP4 "):].split("/")[0].strip()
        elif in_audio and line in ("a=sendrecv", "a=sendonly", "a=recvonly", "a=inactive"):
            direction = line[2:]
    return (ip, port, direction) if seen_audio else (None, 0, None)


class RtpPump:
    """One thread sends 20 ms of PCMU silence on every active stream that may
    send, and counts what arrives on every stream (echo, conference mix, MoH)."""

    def __init__(self, interval=0.02):
        self.interval = interval
        self._lock = threading.Lock()
        self._streams = {}
        self._next = 1
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._loop, name="rtp-pump", daemon=True)
        self._thread.start()

    def add(self, sock, remote, send):
        sock.setblocking(False)
        with self._lock:
            sid = self._next
            self._next += 1
            self._streams[sid] = {"sock": sock, "remote": remote, "send": send,
                                  "seq": random.randint(0, 65535), "ts": random.randint(0, 1 << 30),
                                  "ssrc": random.getrandbits(32), "tx": 0, "rx": 0}
        return sid

    def update(self, sid, remote, send):
        with self._lock:
            st = self._streams.get(sid)
            if st:
                st["remote"], st["send"] = remote, send

    def remove(self, sid):
        with self._lock:
            st = self._streams.pop(sid, None)
        return (st["tx"], st["rx"]) if st else (0, 0)

    def counts(self, sid):
        with self._lock:
            st = self._streams.get(sid)
            return (st["tx"], st["rx"]) if st else (0, 0)

    def stop(self):
        self._stop.set()

    def _loop(self):
        payload = b"\xff" * 160
        while not self._stop.wait(self.interval):
            with self._lock:
                for st in self._streams.values():
                    if st["send"] and st["remote"] and st["remote"][1] > 0:
                        hdr = struct.pack("!BBHII", 0x80, 0, st["seq"] & 0xFFFF,
                                          st["ts"] & 0xFFFFFFFF, st["ssrc"])
                        try:
                            st["sock"].sendto(hdr + payload, st["remote"])
                            st["tx"] += 1
                        except OSError:
                            pass
                        st["seq"] += 1
                        st["ts"] += 160
                    while True:
                        try:
                            st["sock"].recvfrom(2048)
                            st["rx"] += 1
                        except (BlockingIOError, InterruptedError):
                            break
                        except OSError:
                            break


class _Txn:
    def __init__(self):
        self.provisional = threading.Event()
        self.final = threading.Event()
        self.final_msg = None
        self.responses = []          # (monotonic time, status), 1xx included

    def add(self, msg):
        self.responses.append((time.monotonic(), msg.status))
        if msg.status >= 200:
            if not self.final.is_set():
                self.final_msg = msg
                self.final.set()
        else:
            self.provisional.set()


class Dialog:
    """One call leg of this agent, either side (role "uac" or "uas")."""

    def __init__(self, agent, role, call_id, local_tag):
        self.agent = agent
        self.role = role
        self.call_id = call_id
        self.local_tag = local_tag
        self.remote_tag = ""
        self.local_uri = "sip:%s@%s" % (agent.ext, agent.host)
        self.remote_uri = ""
        self.remote_target = ""
        self.route = []
        self.local_cseq = 1
        self.invite_cseq = 0
        self.final_status = None
        self.remote_media = (None, 0, None)
        self.confirmed = threading.Event()   # uas: the ACK for our 2xx arrived
        self.ended = threading.Event()       # the far side sent BYE
        self.reinvited = threading.Event()   # an in-dialog INVITE arrived
        self.reinvites = 0
        self.byes = 0                # BYE transactions that matched this dialog
        self.bye_mismatches = 0      # strict_dialogs: same Call-ID, wrong tags -> 481
        self.bye_log = []            # every BYE with this Call-ID: {"t", "ruri", "status"}
        self.responses = []          # uac: (monotonic time, status) of every INVITE response
        self.invite_sent_at = None
        self.cancel_sent_at = None   # cancel_after_ms: when the CANCEL actually went
        self.cancel_status = None
        self.cancel_answered_at = None
        self.cancel_when_expired = False   # cancel_when: no answer by its timeout, or it raised
        self.cancel_when_error = None      # ... and what it raised
        self.rtp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.rtp_sock.bind((agent.lip, 0))
        self.rtp_port = self.rtp_sock.getsockname()[1]
        self.rtp_id = None
        self.rtp_tx = 0
        self.rtp_rx = 0
        self._closed = False

    @property
    def ok(self):
        return self.final_status is not None and 200 <= self.final_status < 300

    def start_media(self):
        pump = self.agent.rtp_pump
        ip, port, direction = self.remote_media
        send = direction in ("sendrecv", "recvonly") and bool(ip) and port > 0
        remote = (ip, port) if ip and port else None
        if pump is None:
            return
        if self.rtp_id is None:
            self.rtp_id = pump.add(self.rtp_sock, remote, send)
        else:
            pump.update(self.rtp_id, remote, send)

    def media_counts(self):
        pump = self.agent.rtp_pump
        if pump is None or self.rtp_id is None:
            return (self.rtp_tx, self.rtp_rx)
        return pump.counts(self.rtp_id)

    def bye(self):
        """Send BYE in this dialog. Returns the final status, or None."""
        self.local_cseq += 1
        cseq = self.local_cseq
        msg = self.agent._request("BYE", self.remote_target or self.remote_uri, self,
                                  cseq, branch="z9hG4bK" + rand_hex(12))
        final = self.agent._transaction(msg, (self.call_id, cseq, "BYE"), invite=False)
        return final.status if final else None

    def reinvite(self, direction):
        """Re-INVITE this dialog offering a=<direction> (s14.1). Returns the final status, or None."""
        agent = self.agent
        self.local_cseq += 1
        cseq = self.local_cseq
        target = self.remote_target or self.remote_uri
        branch = "z9hG4bK" + rand_hex(12)
        text = agent._request("INVITE", target, self, cseq, branch, body=agent.sdp(self, direction))
        final = agent._transaction(text, (self.call_id, cseq, "INVITE"), invite=True)
        if final is None:
            return None
        if not 200 <= final.status < 300:
            agent._send(agent._request("ACK", target, self, cseq, branch, cseq_method="ACK"))
            return final.status
        if final.body:
            self.remote_media = parse_sdp(final.body)
        ack = agent._request("ACK", target, self, cseq, "z9hG4bK" + rand_hex(12), cseq_method="ACK")
        with agent._lock:
            agent._acks.pop((self.call_id, self.invite_cseq), None)
            agent._acks[(self.call_id, cseq)] = ack
        self.invite_cseq = cseq
        agent._send(ack)
        self.start_media()
        return final.status

    def hold(self):
        return self.reinvite("sendonly")

    def resume(self):
        return self.reinvite("sendrecv")

    def close(self):
        if self._closed:
            return
        self._closed = True
        if self.agent.rtp_pump is not None and self.rtp_id is not None:
            self.rtp_tx, self.rtp_rx = self.agent.rtp_pump.remove(self.rtp_id)
        try:
            self.rtp_sock.close()
        except OSError:
            pass
        self.agent._forget(self)


class Agent:
    """One virtual phone: a REGISTER binding, outgoing calls, and an auto-answer UAS."""

    _allow_extra = frozenset()      # allow_targets(): extensions this agent may dial besides the guard's own
    _allow_outside = frozenset()    # allow_outside(): exact outside numbers this agent may dial

    def __init__(self, ext, host, port, local_ip=None, rtp_pump=None,
                 timeout=8.0, invite_timeout=16.0, ack_wait=8.0,
                 contact_params="", strict_dialogs=False, reject_invites=None):
        self.ext = str(ext)
        self.host = host
        self.port = int(port)
        self.pbx = (host, int(port))
        self.lip = local_ip or local_ip_for(host, port)
        self.rtp_pump = rtp_pump
        self.timeout = timeout
        self.invite_timeout = invite_timeout
        self.ack_wait = ack_wait
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((self.lip, 0))
        self.sock.settimeout(0.2)
        self.lport = self.sock.getsockname()[1]
        self.contact = "<sip:%s@%s:%d%s>" % (self.ext, self.lip, self.lport, contact_params)
        self.strict_dialogs = strict_dialogs
        self.reject_invites = reject_invites
        self.rejected = []          # reject_invites: {"t", "call_id", "from_user"} per refused INVITE
        self.bye_481 = []           # strict_dialogs: every BYE answered 481, and why
        self.reg_call_id = "%s@%s" % (rand_hex(16), self.lip)
        self.reg_tag = rand_hex(8)
        self.reg_cseq = 0
        self.registered = False
        self._lock = threading.Lock()
        self._waiters = {}
        self._acks = {}
        self._dialogs = {}
        self._last_resp = {}
        self.incoming = []          # every new incoming dialog, in arrival order
        self._incoming_cv = threading.Condition(self._lock)
        self.requests_seen = {}
        self._closed = threading.Event()
        self._thread = threading.Thread(target=self._rx_loop, name="ua-%s" % self.ext, daemon=True)
        self._thread.start()

    # ---- wire ----------------------------------------------------------
    def _send(self, text, addr=None):
        try:
            self.sock.sendto(text.encode("utf-8"), addr or self.pbx)
        except OSError:
            pass

    def _via(self, branch):
        return "SIP/2.0/UDP %s:%d;branch=%s;rport" % (self.lip, self.lport, branch)

    def _request(self, method, ruri, dlg, cseq, branch, body="", cseq_method=None):
        lines = ["%s %s SIP/2.0" % (method, ruri),
                 "Via: " + self._via(branch),
                 "Max-Forwards: 70"]
        for r in dlg.route:
            lines.append("Route: " + r)
        frm = "<%s>;tag=%s" % (dlg.local_uri, dlg.local_tag)
        to = "<%s>" % dlg.remote_uri
        if dlg.remote_tag:
            to += ";tag=" + dlg.remote_tag
        lines += ["From: " + frm, "To: " + to, "Call-ID: " + dlg.call_id,
                  "CSeq: %d %s" % (cseq, cseq_method or method)]
        if method == "INVITE":
            lines.append("Contact: " + self.contact)
        lines.append("User-Agent: pd-load")
        if body:
            lines.append("Content-Type: application/sdp")
        lines.append("Content-Length: %d" % len(body.encode("utf-8")))
        return "\r\n".join(lines) + "\r\n\r\n" + body

    def _response(self, req, code, reason, to_tag="", body="", contact=False):
        lines = ["SIP/2.0 %d %s" % (code, reason)]
        for v in req.all("via"):
            lines.append("Via: " + v)
        to = req.get("to")
        if to_tag and not tag_of(to):
            to += ";tag=" + to_tag
        lines += ["From: " + req.get("from"), "To: " + to,
                  "Call-ID: " + req.call_id(), "CSeq: " + req.get("cseq")]
        if contact:
            lines.append("Contact: " + self.contact)
        if body:
            lines.append("Content-Type: application/sdp")
        lines.append("Content-Length: %d" % len(body.encode("utf-8")))
        return "\r\n".join(lines) + "\r\n\r\n" + body

    def sdp(self, dlg, direction="sendrecv"):
        sess = random.randint(1000, 999999)
        return ("v=0\r\no=%s %d %d IN IP4 %s\r\ns=pd-load\r\nc=IN IP4 %s\r\nt=0 0\r\n"
                "m=audio %d RTP/AVP 0 101\r\na=rtpmap:0 PCMU/8000\r\n"
                "a=rtpmap:101 telephone-event/8000\r\na=fmtp:101 0-15\r\na=ptime:20\r\na=%s\r\n"
                % (self.ext, sess, sess, self.lip, self.lip, dlg.rtp_port, direction))

    def _transaction(self, text, key, invite, txn=None, timeout=None):
        """Send a request, retransmit per RFC 3261 s17.1, return the final response or None."""
        txn = txn or _Txn()
        with self._lock:
            self._waiters[key] = txn
        self._send(text)
        deadline = time.monotonic() + (timeout or (self.invite_timeout if invite else self.timeout))
        interval = T1
        try:
            while True:
                left = deadline - time.monotonic()
                if left <= 0:
                    return None
                if txn.final.wait(min(interval, left)):
                    return txn.final_msg
                if self._closed.is_set():
                    return None
                if not (invite and txn.provisional.is_set()):
                    self._send(text)
                interval = min(interval * 2, T2) if not invite else interval * 2
        finally:
            with self._lock:
                self._waiters.pop(key, None)

    # ---- UAC -----------------------------------------------------------
    def register(self, expires):
        """REGISTER this agent's binding. Returns the final status, or None.

        `registered` is True only after a 200 whose Contact echoes this
        agent's own binding (#686), so a caller can be sure a call to this
        extension rings this agent and nothing else."""
        with self._lock:
            self.reg_cseq += 1
            cseq = self.reg_cseq
        branch = "z9hG4bK" + rand_hex(12)
        text = ("REGISTER sip:%s SIP/2.0\r\nVia: %s\r\nMax-Forwards: 70\r\n"
                "From: <sip:%s@%s>;tag=%s\r\nTo: <sip:%s@%s>\r\nCall-ID: %s\r\n"
                "CSeq: %d REGISTER\r\nContact: %s\r\nExpires: %d\r\n"
                "User-Agent: pd-load\r\nContent-Length: 0\r\n\r\n"
                % (self.host, self._via(branch), self.ext, self.host, self.reg_tag,
                   self.ext, self.host, self.reg_call_id, cseq, self.contact, expires))
        final = self._transaction(text, (self.reg_call_id, cseq, "REGISTER"), invite=False)
        status = final.status if final else None
        if status == 200 and expires > 0:
            mine = "%s:%d" % (self.lip, self.lport)
            self.registered = any(mine in c for c in final.all("contact"))
        elif status == 200:
            self.registered = False
        elif expires > 0:
            self.registered = False
        _note_registered(self.ext, self.registered)      # the dial guard's (a): only a confirmed binding counts
        return status

    # ---- dial guard ----------------------------------------------------
    def allow_targets(self, *exts):
        """Let this agent INVITE these extensions although no UA of this process registered them (another
        process did, or a real phone). Never lifts the refusals: see target_allowed()."""
        self._allow_extra = self._allow_extra | frozenset(str(e).strip() for e in exts)

    def allow_outside(self, *numbers):
        """Let this agent INVITE exactly these outside numbers (a leading '+', or 7 or more digits): the exact
        strings only, never a pattern or a prefix. For a run approved to dial through the anchor."""
        self._allow_outside = self._allow_outside | frozenset(str(n).strip() for n in numbers)

    def _check_dial(self, target):
        """Raise DialRefused unless target_allowed(). The environment is read now, not at construction."""
        ok, why = target_allowed(target, registered_extensions(),
                                 self._allow_extra | _csv(ALLOW_TARGETS_ENV),
                                 self._allow_outside | _csv(ALLOW_OUTSIDE_ENV))
        if not ok:
            raise DialRefused("refusing to INVITE %s from %s: %s" % (_shown(target), self.ext, why))

    def invite(self, target_user, cancel_after_ms=None, cancel_when=None, cancel_when_timeout_s=None,
               invite_timeout=None):
        """INVITE sip:<target_user>@<pbx>. Returns the Dialog; dialog.ok says
        whether it was answered (2xx, then ACKed). A non-2xx final is ACKed by
        the transaction (s17.1.1.3); no final at all is CANCELled if it rang.

        cancel_after_ms: CANCEL that many ms after the INVITE went, or at the
        first provisional response if none had arrived by then (s9.1); not at
        all if a final response came first. dialog.cancel_sent_at says when.

        cancel_when: instead, CANCEL when fn(invite_sent_at) says (it returns the
        monotonic time the CANCEL is due, or None while unknown; polled every 10 ms),
        never before a provisional response and not at all if a final one came first.
        cancel_when_timeout_s (required with it) bounds the wait: at that many seconds
        after the INVITE, or at once if fn raises, the CANCEL goes and
        dialog.cancel_when_expired is set (cancel_when_error says what fn raised).
        The two ways of timing a CANCEL exclude each other.

        invite_timeout: this call's INVITE transaction bound in s (default: the agent's), so that a CANCEL
        due after the agent's own bound can still read its 487.

        Raises DialRefused, with nothing built or sent, if the dial guard does not allow target_user."""
        if cancel_when is not None:
            if cancel_after_ms is not None:
                raise ValueError("cancel_after_ms and cancel_when are two ways to time the CANCEL: use one")
            if not cancel_when_timeout_s or cancel_when_timeout_s <= 0:
                raise ValueError("cancel_when needs a positive cancel_when_timeout_s: the wait is always bounded")
        self._check_dial(target_user)
        dlg = Dialog(self, "uac", "%s@%s" % (rand_hex(16), self.lip), rand_hex(8))
        dlg.remote_uri = "sip:%s@%s" % (target_user, self.host)
        dlg.invite_cseq = dlg.local_cseq
        with self._lock:
            self._dialogs[dlg.call_id] = dlg
        branch = "z9hG4bK" + rand_hex(12)
        ruri = dlg.remote_uri
        offer = self.sdp(dlg)
        text = self._request("INVITE", ruri, dlg, dlg.local_cseq, branch, body=offer)
        txn = _Txn()
        dlg.responses = txn.responses
        dlg.invite_sent_at = time.monotonic()
        canceller = None
        if cancel_after_ms is not None:
            canceller = threading.Thread(target=self._cancel_at, daemon=True,
                                         args=(dlg, ruri, branch, txn,
                                               dlg.invite_sent_at + cancel_after_ms / 1000.0))
            canceller.start()
        elif cancel_when is not None:
            canceller = threading.Thread(target=self._cancel_at, daemon=True,
                                         args=(dlg, ruri, branch, txn, None, cancel_when,
                                               dlg.invite_sent_at + cancel_when_timeout_s))
            canceller.start()
        final = self._transaction(text, (dlg.call_id, dlg.local_cseq, "INVITE"), invite=True, txn=txn,
                                  timeout=invite_timeout)
        if canceller is not None:
            canceller.join(self.timeout + 1.0)
        if final is None:
            dlg.final_status = None
            if dlg.cancel_sent_at is None:
                cancel = self._request("CANCEL", ruri, dlg, dlg.local_cseq, branch)
                self._transaction(cancel, (dlg.call_id, dlg.local_cseq, "CANCEL"), invite=False)
            return dlg
        dlg.final_status = final.status
        dlg.remote_tag = tag_of(final.get("to"))
        if not dlg.ok:
            ack = self._request("ACK", ruri, dlg, dlg.local_cseq, branch, cseq_method="ACK")
            self._send(ack)
            return dlg
        dlg.remote_target = uri_of(final.get("contact")) or ruri
        dlg.route = list(reversed(final.all("record-route")))
        dlg.remote_media = parse_sdp(final.body)
        ack = self._request("ACK", dlg.remote_target, dlg, dlg.local_cseq,
                            "z9hG4bK" + rand_hex(12), cseq_method="ACK")
        with self._lock:
            self._acks[(dlg.call_id, dlg.local_cseq)] = ack
        self._send(ack)
        dlg.start_media()
        return dlg

    def _cancel_time(self, dlg, txn, when, deadline):
        """cancel_when: poll when(invite_sent_at) for the monotonic time the CANCEL is due. At
        `deadline`, or if `when` raises, it is due now and the dialog says so: a caller's bug
        must not leave a phone ringing. None: a final response came first, or the agent closed."""
        while True:
            if txn.final.is_set() or self._closed.is_set():
                return None
            try:
                at = when(dlg.invite_sent_at)
            except Exception as e:  # noqa: BLE001 -- cancel now, say why, never leave the handset ringing
                dlg.cancel_when_error = repr(e)
                dlg.cancel_when_expired = True
                return time.monotonic()
            if at is not None:
                return at
            if time.monotonic() >= deadline:
                dlg.cancel_when_expired = True
                return time.monotonic()
            txn.final.wait(0.01)

    def _cancel_at(self, dlg, ruri, branch, txn, at, when=None, deadline=None):
        """cancel_after_ms / cancel_when: CANCEL the pending INVITE at `at` (monotonic; or
        when `when` gives it), but never before a provisional response (s9.1) and never
        once a final one arrived."""
        if when is not None:
            at = self._cancel_time(dlg, txn, when, deadline)
            if at is None:
                return
        left = at - time.monotonic()
        if left > 0 and txn.final.wait(left):
            return
        while not txn.provisional.is_set():
            if txn.final.wait(0.01) or self._closed.is_set():
                return
        if txn.final.is_set():
            return
        cancel = self._request("CANCEL", ruri, dlg, dlg.local_cseq, branch)
        dlg.cancel_sent_at = time.monotonic()
        final = self._transaction(cancel, (dlg.call_id, dlg.local_cseq, "CANCEL"), invite=False)
        dlg.cancel_status = final.status if final else None
        dlg.cancel_answered_at = time.monotonic() if final else None

    def wait_incoming(self, since, timeout):
        """The first incoming dialog after `since` earlier ones, or None."""
        deadline = time.monotonic() + timeout
        with self._incoming_cv:
            while len(self.incoming) <= since:
                left = deadline - time.monotonic()
                if left <= 0:
                    return None
                self._incoming_cv.wait(left)
            return self.incoming[since]

    def incoming_count(self):
        with self._lock:
            return len(self.incoming)

    def live_dialogs(self):
        with self._lock:
            return list(self._dialogs.values())

    def _forget(self, dlg):
        with self._lock:
            if self._dialogs.get(dlg.call_id) is dlg:
                del self._dialogs[dlg.call_id]
            self._acks.pop((dlg.call_id, dlg.local_cseq), None)

    # ---- receive -------------------------------------------------------
    def _rx_loop(self):
        while not self._closed.is_set():
            try:
                data, addr = self.sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            if not data.strip():
                continue          # CRLF keep-alive
            try:
                msg = SipMsg.parse(data)
            except Exception:     # noqa: BLE001 -- a junk datagram must not kill the agent
                continue
            if msg.is_response:
                self._on_response(msg)
            else:
                self._on_request(msg, addr)

    def _on_response(self, msg):
        num, method = msg.cseq()
        key = (msg.call_id(), num, method)
        with self._lock:
            txn = self._waiters.get(key)
            ack = self._acks.get((msg.call_id(), num)) if method == "INVITE" else None
        if txn is not None:
            txn.add(msg)
        elif ack and 200 <= msg.status < 300:
            self._send(ack)       # a retransmitted 2xx: ACK it again (s13.2.2.4)

    def _reply(self, req, addr, code, reason, to_tag="", body="", contact=False):
        text = self._response(req, code, reason, to_tag=to_tag, body=body, contact=contact)
        with self._lock:
            if len(self._last_resp) > 512:
                self._last_resp.clear()       # bounded over a 5 h run
            self._last_resp[(req.call_id(), req.get("cseq"), req.branch())] = text
        self._send(text, addr)
        return text

    def _note_bye_481(self, req, why):
        with self._lock:
            self.bye_481.append({"t": time.monotonic(), "call_id": req.call_id(),
                                 "from_tag": tag_of(req.get("from")), "to_tag": tag_of(req.get("to")),
                                 "why": why})

    def _resend_until_ack(self, text, addr, event):
        interval = T1
        deadline = time.monotonic() + self.ack_wait
        while not event.wait(interval):
            if self._closed.is_set() or time.monotonic() >= deadline:
                return
            self._send(text, addr)
            interval = min(interval * 2, T2)

    def _on_request(self, req, addr):
        method = req.method
        with self._lock:
            self.requests_seen[method] = self.requests_seen.get(method, 0) + 1
            cached = self._last_resp.get((req.call_id(), req.get("cseq"), req.branch()))
            dlg = self._dialogs.get(req.call_id())
        if cached and method != "ACK":
            self._send(cached, addr)          # a retransmitted request
            return
        if method == "INVITE":
            self._on_invite(req, addr, dlg)
        elif method == "ACK":
            if dlg is not None:
                dlg.confirmed.set()
        elif method == "BYE":
            if dlg is None:
                self._reply(req, addr, 481, "Call/Transaction Does Not Exist")
                if self.strict_dialogs:
                    self._note_bye_481(req, "no dialog with this Call-ID")
                return
            if self.strict_dialogs:
                why = None
                if (tag_of(req.get("from")), tag_of(req.get("to"))) != (dlg.remote_tag, dlg.local_tag):
                    dlg.bye_mismatches += 1
                    why = "Call-ID matches but the tags do not (s12.2.2)"
                elif dlg.ended.is_set():
                    dlg.byes += 1
                    why = "a second BYE on an ended dialog"
                if why:
                    self._reply(req, addr, 481, "Call/Transaction Does Not Exist")
                    self._note_bye_481(req, why)
                    dlg.bye_log.append({"t": time.monotonic(), "ruri": req.ruri, "status": 481})
                    return
            dlg.byes += 1
            self._reply(req, addr, 200, "OK")
            dlg.bye_log.append({"t": time.monotonic(), "ruri": req.ruri, "status": 200})
            dlg.ended.set()
        elif method == "CANCEL":
            self._reply(req, addr, 200, "OK")
        elif method in ("OPTIONS", "NOTIFY", "INFO", "UPDATE", "MESSAGE"):
            self._reply(req, addr, 200, "OK")
        else:
            self._reply(req, addr, 501, "Not Implemented")

    def _on_invite(self, req, addr, dlg):
        to_tag = tag_of(req.get("to"))
        if dlg is not None and to_tag and to_tag == dlg.local_tag:
            # re-INVITE (e.g. a park retrieve re-pointing the parked party's media)
            dlg.remote_media = parse_sdp(req.body) if req.body else dlg.remote_media
            dlg.reinvites += 1
            dlg.confirmed.clear()
            text = self._reply(req, addr, 200, "OK", body=self.sdp(dlg), contact=True)
            dlg.start_media()
            dlg.reinvited.set()
            threading.Thread(target=self._resend_until_ack, args=(text, addr, dlg.confirmed),
                             daemon=True).start()
            return
        if to_tag:
            self._reply(req, addr, 481, "Call/Transaction Does Not Exist")
            return
        if self.reject_invites:
            with self._lock:
                self.rejected.append({"t": time.monotonic(), "call_id": req.call_id(),
                                      "from_user": user_of(uri_of(req.get("from")))})
            self._reply(req, addr, self.reject_invites, "Busy Here" if self.reject_invites == 486
                        else "Rejected", to_tag=rand_hex(8))
            return
        dlg = Dialog(self, "uas", req.call_id(), rand_hex(8))
        dlg.remote_tag = tag_of(req.get("from"))
        dlg.remote_uri = uri_of(req.get("from"))
        dlg.local_uri = uri_of(req.get("to"))
        dlg.remote_target = uri_of(req.get("contact")) or dlg.remote_uri
        dlg.route = req.all("record-route")
        dlg.invite_cseq = req.cseq()[0]
        dlg.final_status = 200
        dlg.remote_media = parse_sdp(req.body)
        with self._lock:
            self._dialogs[dlg.call_id] = dlg
        self._send(self._response(req, 180, "Ringing", to_tag=dlg.local_tag, contact=True), addr)
        text = self._reply(req, addr, 200, "OK", to_tag=dlg.local_tag, body=self.sdp(dlg), contact=True)
        dlg.start_media()
        with self._incoming_cv:
            self.incoming.append(dlg)
            self._incoming_cv.notify_all()
        threading.Thread(target=self._resend_until_ack, args=(text, addr, dlg.confirmed),
                         daemon=True).start()

    def close(self):
        for dlg in self.live_dialogs():
            dlg.close()
        _note_registered(self.ext, False)
        self._closed.set()
        try:
            self.sock.close()
        except OSError:
            pass
