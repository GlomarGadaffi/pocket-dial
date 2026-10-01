#!/usr/bin/env python3
"""A loopback fake of the pocket-dial PBX's SIP surface, for the #401 load-profile tests.

It is NOT the PBX: it is just enough of it to prove the load generator's call
flows, counts and refusals without a board. It does a registrar with binding
echo, answers 777 and 888 itself, parks a caller on a free orbit (sendonly MoH
SDP) and on retrieve re-INVITEs the parked party, and relays an extension call
the way the PBX does since #808 (its own Via on the far leg, its own BYE to the
far phone). It records the Request-URI user of every INVITE it receives, so a
test can prove nothing outside the allowlist was ever dialled. It sends no RTP.

    python3 tests/load/fake_pbx.py [--port 5099] [--http-port 8099]

serves sip:127.0.0.1:<port> and http://127.0.0.1:<http-port>/api/status until
Ctrl-C. stdlib only.
"""
import argparse
import json
import os
import signal
import socket
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)
from sip_agent import SipMsg, rand_hex, tag_of, uri_of, user_of  # noqa: E402


class FakePbx:
    def __init__(self, host="127.0.0.1", port=0, orbits=(700, 709)):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((host, port))
        self.sock.settimeout(0.2)
        self.host, self.port = self.sock.getsockname()
        self.orbits = {str(n) for n in range(orbits[0], orbits[1] + 1)}
        self.lock = threading.RLock()
        self.bindings = {}
        self.sessions = {}
        self.parked = {}
        self.pending = {}
        self.last = {}
        self.invite_users = []
        self.counts = {}
        self.packets = 0
        self.reject_ext = None          # e.g. 486: every extension call is refused with it
        self.register_status = {}       # ext -> a forced REGISTER status (e.g. 403)
        self.parked_count_override = None
        self.started = time.monotonic()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._loop, name="fake-pbx", daemon=True)
        self._http = None

    # ---- lifecycle ------------------------------------------------------
    def start(self):
        self._thread.start()
        return self

    def stop(self):
        self._stop.set()
        if self._http is not None:
            self._http.shutdown()
            self._http.server_close()
        try:
            self.sock.close()
        except OSError:
            pass

    def serve_http(self, port=0):
        pbx = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path.split("?")[0] != "/api/status":
                    self.send_error(404)
                    return
                body = json.dumps(pbx.status()).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass

        self._http = ThreadingHTTPServer((self.host, port), Handler)
        threading.Thread(target=self._http.serve_forever, daemon=True).start()
        return "http://%s:%d/api/status" % (self.host, self._http.server_address[1])

    def status(self):
        with self.lock:
            parked = len(self.parked) if self.parked_count_override is None else self.parked_count_override
            return {"version": "fake-pbx", "uptime": int(time.monotonic() - self.started),
                    "resetReason": "POWERON", "clientCount": len(self.bindings),
                    "sessionCount": len(self.sessions), "oldestSessionSec": 0, "sessions": [],
                    "parkedCount": parked, "parkedCalls": []}

    # ---- wire -----------------------------------------------------------
    def _send(self, text, addr):
        try:
            self.sock.sendto(text.encode("utf-8"), addr)
        except OSError:
            pass

    def _contact(self, user):
        return "<sip:%s@%s:%d>" % (user, self.host, self.port)

    def _sdp(self, direction):
        return ("v=0\r\no=pbx 1 1 IN IP4 %s\r\ns=fake\r\nc=IN IP4 %s\r\nt=0 0\r\n"
                "m=audio 40000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=%s\r\n"
                % (self.host, self.host, direction))

    def _resp(self, req, code, reason, to_tag="", body="", contact_user=None, extra=()):
        lines = ["SIP/2.0 %d %s" % (code, reason)]
        lines += ["Via: " + v for v in req.all("via")]
        to = req.get("to")
        if to_tag and not tag_of(to):
            to += ";tag=" + to_tag
        lines += ["From: " + req.get("from"), "To: " + to, "Call-ID: " + req.call_id(),
                  "CSeq: " + req.get("cseq")]
        if contact_user:
            lines.append("Contact: " + self._contact(contact_user))
        lines += list(extra)
        if body:
            lines.append("Content-Type: application/sdp")
        lines.append("Content-Length: %d" % len(body))
        return "\r\n".join(lines) + "\r\n\r\n" + body

    def _reply(self, req, addr, code, reason, **kw):
        text = self._resp(req, code, reason, **kw)
        with self.lock:
            self.last[(req.call_id(), req.get("cseq"), req.branch())] = text
        self._send(text, addr)

    def _request(self, method, ruri, frm, to, call_id, cseq, addr, body="", on_response=None):
        branch = "z9hG4bK" + rand_hex(12)
        lines = ["%s %s SIP/2.0" % (method, ruri),
                 "Via: SIP/2.0/UDP %s:%d;branch=%s" % (self.host, self.port, branch),
                 "Max-Forwards: 70", "From: " + frm, "To: " + to, "Call-ID: " + call_id,
                 "CSeq: %d %s" % (cseq, method), "Contact: " + self._contact("pbx")]
        if body:
            lines.append("Content-Type: application/sdp")
        lines.append("Content-Length: %d" % len(body))
        if on_response is not None:
            with self.lock:
                self.pending[branch] = on_response
        self._send("\r\n".join(lines) + "\r\n\r\n" + body, addr)

    # ---- receive --------------------------------------------------------
    def _loop(self):
        while not self._stop.is_set():
            try:
                data, addr = self.sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            with self.lock:
                self.packets += 1
            if not data.strip():
                continue
            msg = SipMsg.parse(data)
            with self.lock:
                if msg.is_response:
                    handler = self.pending.get(msg.branch())
                    if handler is not None:
                        handler(msg)
                else:
                    self.counts[msg.method] = self.counts.get(msg.method, 0) + 1
                    self._on_request(msg, addr)

    def _on_request(self, req, addr):
        cached = self.last.get((req.call_id(), req.get("cseq"), req.branch()))
        if cached is not None and req.method != "ACK":
            self._send(cached, addr)
            return
        handler = getattr(self, "_on_" + req.method.lower(), None)
        if handler is None:
            self._reply(req, addr, 501, "Not Implemented")
        else:
            handler(req, addr)

    def _on_options(self, req, addr):
        self._reply(req, addr, 200, "OK")

    def _on_cancel(self, req, addr):
        self._reply(req, addr, 200, "OK")

    def _on_register(self, req, addr):
        user = user_of(uri_of(req.get("to")))
        forced = self.register_status.get(user)
        if forced:
            self._reply(req, addr, forced, "Forced")
            return
        exp = req.get("expires")
        expires = int(exp) if exp.isdigit() else 3600
        contact = uri_of(req.get("contact"))
        if expires == 0:
            self.bindings.pop(user, None)
            self._reply(req, addr, 200, "OK")
            return
        self.bindings[user] = {"uri": contact, "addr": addr}
        self._reply(req, addr, 200, "OK", extra=["Contact: <%s>;expires=%d" % (contact, expires)])

    def _on_invite(self, req, addr):
        if tag_of(req.get("to")):
            self._reply(req, addr, 200, "OK", body=self._sdp("sendrecv"), contact_user="pbx")
            return
        user = user_of(req.ruri)
        self.invite_users.append(user)
        cid = req.call_id()
        tag = rand_hex(8)
        if user in ("777", "888"):
            self.sessions[cid] = {"kind": "media", "addr": addr}
            self._reply(req, addr, 200, "OK", to_tag=tag, body=self._sdp("sendrecv"), contact_user=user)
        elif user in self.orbits and user not in self.parked:
            to = req.get("to") + ";tag=" + tag
            self.parked[user] = {"call_id": cid, "from": req.get("from"), "to": to,
                                 "addr": addr, "contact": uri_of(req.get("contact")), "sdp": req.body}
            self.sessions[cid] = {"kind": "parked", "orbit": user, "addr": addr}
            self._reply(req, addr, 200, "OK", to_tag=tag, body=self._sdp("sendonly"), contact_user=user)
        elif user in self.orbits:
            p = self.parked.pop(user)
            self.sessions[cid] = {"kind": "retriever", "peer": p["call_id"], "addr": addr,
                                  "from": req.get("from"), "to": req.get("to") + ";tag=" + tag,
                                  "contact": uri_of(req.get("contact"))}
            self.sessions[p["call_id"]] = dict(p, kind="retrieved", peer=cid)
            self._reply(req, addr, 200, "OK", to_tag=tag, body=p["sdp"], contact_user=user)

            def on_reinvite_answer(resp, p=p):
                if 200 <= resp.status < 300:
                    self._request("ACK", p["contact"], p["to"], p["from"], p["call_id"], 100, p["addr"])
            self._request("INVITE", p["contact"], p["to"], p["from"], p["call_id"], 100, p["addr"],
                          body=req.body, on_response=on_reinvite_answer)
        elif user in self.bindings:
            if self.reject_ext:
                self._reply(req, addr, self.reject_ext, "Rejected", to_tag=tag)
                return
            b = self.bindings[user]
            s = {"kind": "relay", "a_addr": addr, "a_req": req, "b_addr": b["addr"],
                 "b_uri": b["uri"], "b_tag": "", "user": user}
            self.sessions[cid] = s
            self._reply(req, addr, 100, "Trying")

            def on_b_answer(resp, s=s):
                if resp.method != "INVITE":
                    return
                if 200 <= resp.status < 300:
                    s["b_tag"] = tag_of(resp.get("to"))
                lines = [resp.first] + ["Via: " + v for v in s["a_req"].all("via")]
                lines += ["From: " + resp.get("from"), "To: " + resp.get("to"),
                          "Call-ID: " + resp.call_id(), "CSeq: " + resp.get("cseq"),
                          "Contact: " + self._contact(s["user"])]
                if resp.body:
                    lines.append("Content-Type: application/sdp")
                lines.append("Content-Length: %d" % len(resp.body))
                self._send("\r\n".join(lines) + "\r\n\r\n" + resp.body, s["a_addr"])
            self._request("INVITE", b["uri"], req.get("from"), req.get("to"), cid, req.cseq()[0],
                          b["addr"], body=req.body, on_response=on_b_answer)
        else:
            self._reply(req, addr, 404, "Not Found", to_tag=tag)

    def _on_ack(self, req, addr):
        s = self.sessions.get(req.call_id())
        if s and s["kind"] == "relay" and s["b_tag"]:
            a = s["a_req"]
            self._request("ACK", s["b_uri"], a.get("from"), a.get("to") + ";tag=" + s["b_tag"],
                          a.call_id(), req.cseq()[0], s["b_addr"])

    def _on_bye(self, req, addr):
        cid = req.call_id()
        s = self.sessions.pop(cid, None)
        if s is None:
            self._reply(req, addr, 481, "Call/Transaction Does Not Exist")
            return
        self._reply(req, addr, 200, "OK")
        ignore = (lambda resp: None)
        if s["kind"] == "parked":
            self.parked.pop(s["orbit"], None)
        elif s["kind"] == "relay":
            a = s["a_req"]
            if addr == s["a_addr"]:
                self._request("BYE", s["b_uri"], a.get("from"), a.get("to") + ";tag=" + s["b_tag"],
                              cid, req.cseq()[0], s["b_addr"], on_response=ignore)
            else:
                self._request("BYE", uri_of(a.get("contact")), a.get("to") + ";tag=" + s["b_tag"],
                              a.get("from"), cid, 100, s["a_addr"], on_response=ignore)
        elif s["kind"] == "retriever":
            p = self.sessions.pop(s["peer"], None)
            if p is not None:
                self._request("BYE", p["contact"], p["to"], p["from"], p["call_id"], 101, p["addr"],
                              on_response=ignore)
        elif s["kind"] == "retrieved":
            r = self.sessions.pop(s["peer"], None)
            if r is not None:
                self._request("BYE", r["contact"], r["to"], r["from"], s["peer"], 100, r["addr"],
                              on_response=ignore)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=5099)
    ap.add_argument("--http-port", type=int, default=8099)
    args = ap.parse_args(argv)
    if not args.host.startswith("127."):
        print("fake_pbx.py serves loopback only")
        return 2
    pbx = FakePbx(args.host, args.port).start()
    url = pbx.serve_http(args.http_port)
    print("fake PBX: sip:%s:%d  status %s" % (pbx.host, pbx.port, url), flush=True)
    done = threading.Event()
    signal.signal(signal.SIGINT, lambda *a: done.set())
    signal.signal(signal.SIGTERM, lambda *a: done.set())
    done.wait()
    pbx.stop()
    print("fake PBX: %d packets, requests %s, INVITE users %s"
          % (pbx.packets, json.dumps(pbx.counts, sort_keys=True), sorted(set(pbx.invite_users))))
    return 0


if __name__ == "__main__":
    sys.exit(main())
