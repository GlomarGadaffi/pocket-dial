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
  * Dialog.hold() / resume(): a re-INVITE offering sendonly / sendrecv (s14.1);
  * contact_params: URI parameters on the Contact (e.g. ";line=pd6101");
  * strict_dialogs: a BYE must match Call-ID AND both tags (s12.2.2), else 481;
  * Dialog.bye_log: each BYE that reached the dialog, with its Request-URI (rule 1);
  * reject_invites=<code>: every new incoming INVITE is refused and recorded.

stdlib only.
"""
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

    def _transaction(self, text, key, invite, txn=None):
        """Send a request, retransmit per RFC 3261 s17.1, return the final response or None."""
        txn = txn or _Txn()
        with self._lock:
            self._waiters[key] = txn
        self._send(text)
        deadline = time.monotonic() + (self.invite_timeout if invite else self.timeout)
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
        return status

    def invite(self, target_user, cancel_after_ms=None):
        """INVITE sip:<target_user>@<pbx>. Returns the Dialog; dialog.ok says
        whether it was answered (2xx, then ACKed). A non-2xx final is ACKed by
        the transaction (s17.1.1.3); no final at all is CANCELled if it rang.

        cancel_after_ms: CANCEL that many ms after the INVITE went, or at the
        first provisional response if none had arrived by then (s9.1); not at
        all if a final response came first. dialog.cancel_sent_at says when."""
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
        final = self._transaction(text, (dlg.call_id, dlg.local_cseq, "INVITE"), invite=True, txn=txn)
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

    def _cancel_at(self, dlg, ruri, branch, txn, at):
        """cancel_after_ms: CANCEL the pending INVITE at `at` (monotonic), but never
        before a provisional response (s9.1) and never once a final one arrived."""
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
        self._closed.set()
        try:
            self.sock.close()
        except OSError:
            pass
