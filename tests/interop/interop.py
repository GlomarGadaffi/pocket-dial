#!/usr/bin/env python3
"""Real-SIP-stack interop harness for pocket-dial.

Where `tests/sipp/run_sipp.sh` replays hand-written message flows and
`.smoke/office_smoke.py` drives a hand-rolled UAC, this harness points two
*production* SIP stacks -- pjsip's `pjsua` and `baresip` -- at the PBX and
lets them negotiate for real: their own offer/answer, their own transaction
timers and retransmissions, their own RTP. That is what makes it useful for
state-machine edges: the UA does not politely follow our script, it follows
RFC 3261, and it complains (or wedges) when the PBX does not.

Run it under WSL/Linux (see docs: raw sockets + no Windows firewall prompts):

    tests/interop/run_interop.sh [path/to/SipServer]
    tests/interop/run_interop.sh --only hold_resume,blind_transfer

Every UA binds its own 127.0.0.x source address. That is not cosmetic: the
PBX rate-limits per source IP (~40 burst / 20 pkt/s, Issue #38), and a whole
office sharing 127.0.0.1 trips it -- the same reason `office_smoke.py` has
`phone_source_ip()`.

pjsua is driven over its telnet CLI (`--use-cli --cli-telnet-port`), not the
legacy stdin menu: the menu prompts for missing arguments and a bare group
name ("call" with no subcommand) drops the connection. Always send a complete
command. Assertions read pjsua's own log at level 5, which contains the full
SIP trace, plus `call dump_q` for RTP counters and the PBX's own /api/*.

Build pjsua with PJMEDIA_HAS_VIDEO=1 (see run_interop.sh) even though nothing
here sends video: its CLI compiles the dynamic call-id picker inside
"#if PJSUA_HAS_VIDEO", and without it `call transfer_replaces <id>` rejects every
id and the attended-transfer scenario can never issue its REFER.

baresip is optional: if it is not installed the mixed-stack scenarios report
SKIP rather than FAIL, and the exit code ignores them. A baresip installed
without root: put it on PATH and set BARESIP_MODULES to its modules directory.
"""
import argparse
import json
import os
import re
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
LOGDIR = os.path.join(HERE, ".logs")

PBX_IP = "127.0.0.1"
PBX_SIP_PORT = 5070          # deliberately not 5060: a stale run_sipp.sh server
PBX_WEB_PORT = 8085          # must not silently absorb this harness's traffic

RESULTS = []   # (name, status, detail)  status in {"OK", "FAIL", "SKIP"}

# "This leg went down", precisely.
#
# pjsua runs at log level 5 here, so its log holds the full SIP trace as raw
# text -- which makes a naive r"BYE" match two things that have nothing to do
# with a leg ending:
#
#   * the "Allow: ... BYE ..." header that EVERY SIP message carries, so any
#     traffic at all to a UA looks like a teardown; and
#   * "Received RTCP BYE", a media event pjsua logs when a stream is re-pointed
#     -- which is precisely what a SUCCESSFUL transfer does.
#
# Both fire on a perfectly healthy leg, and in blind_transfer they fired within
# one millisecond of the transfer succeeding. Match only an inbound BYE request
# or pjsua's own call-state line. Deliberately NOT "Request msg BYE" on its own:
# that also matches a UA *sending* its own BYE during scenario teardown.
TEARDOWN_RX = r"Processing incoming message: Request msg BYE|Call \d+ is DISCONNECTED"

# "This leg was re-INVITEd" -- the observable for a leg being moved to a new
# peer. Same pattern sc_attended_transfer already uses for its splice check.
REINVITE_RX = r"Received Request msg INVITE|RX .*INVITE"

# ...and that UA ACCEPTING it: its 200 on the wire. Arrival alone proves nothing
# -- #402's splice re-INVITEs arrived on every run and were 500'd.
ACCEPTED_REINVITE_RX = r"TX \d+ bytes Response msg 200/INVITE"

# A UA refusing something the PBX sent it: any 5xx it transmitted. #389/#402's
# requests were refused this way ("500 Invalid CSeq") while the checks passed.
REFUSAL_RX = r"TX \d+ bytes Response msg 5\d\d/"


def refusals(*marked):
    """Names of the UAs that sent a 5xx since their mark: [(ua, mark), ...]."""
    return [ua.name for ua, m in marked if re.search(REFUSAL_RX, ua.log_since(m))]


# --------------------------------------------------------------------------
# small helpers
# --------------------------------------------------------------------------
def report(name, status, detail=""):
    RESULTS.append((name, status, detail))
    print("  [%s] %-22s %s" % (status.ljust(4), name, detail))
    return status == "OK"


def http_json(path, timeout=5):
    url = "http://%s:%d%s" % (PBX_IP, PBX_WEB_PORT, path)
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8", "replace"))
    except Exception:
        return None


def pbx_http(method, path, form=None, headers=None, timeout=10):
    """(status, headers, body) of a request to the PBX's web port, `form` sent as a
    urlencoded body. Status 0 when nothing answered. Loopback only (PBX_IP)."""
    data = urllib.parse.urlencode(form).encode() if form is not None else None
    req = urllib.request.Request("http://%s:%d%s" % (PBX_IP, PBX_WEB_PORT, path),
                                 data=data, headers=headers or {}, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.headers, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.headers, e.read().decode("utf-8", "replace")
    except Exception:
        return 0, None, ""


def pbx_admin_login():
    """Request headers for an admin POST, or None when the PBX would not let us in.

    The host PBX starts unprovisioned: it takes the shipped default login, then
    refuses every admin action until that login is replaced (requireAdmin(),
    tests/http/test_api.sh TC-AUTH-04..07). So this logs in, completes that setup with
    a password drawn at random for this run (held in memory only, never written
    anywhere), and returns the session cookie and CSRF token. The PBX is a fresh
    process per run (credentials are not persisted on host), and the web port is
    loopback."""
    code, hdrs, body = pbx_http("POST", "/api/admin/login",
                                {"username": "admin", "password": "admin"})
    if code != 200 or hdrs is None:
        return None
    cookie = re.search(r"pd_session=([0-9a-fA-F]+)", " ".join(hdrs.get_all("Set-Cookie") or []))
    try:
        info = json.loads(body)
    except ValueError:
        return None
    if not cookie or not info.get("csrf"):
        return None
    auth = {"Cookie": "pd_session=" + cookie.group(1), "X-CSRF": info["csrf"]}
    if info.get("needsSetup"):
        code, _, _ = pbx_http("POST", "/api/admin/set-credential",
                              {"username": "admin", "password": secrets.token_hex(16)}, auth)
        if code != 200:
            return None
    return auth


def pbx_set_group(auth, ext, members):
    """POST /api/group: ring group `ext` = `members` (comma list); "" deletes it.
    True when the PBX answered 200. Pickup eligibility is ring-group co-membership
    (PbxConfig.hpp, 'Directed / group call pickup'), and there is no other way to
    set a group on the host binary."""
    code, _, _ = pbx_http("POST", "/api/group",
                          {"extension": ext, "members": members, "mode": "ringall"}, auth)
    return code == 200


def wait_for(predicate, timeout, interval=0.2):
    """Poll predicate until truthy or timeout. Returns the truthy value or None."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        v = predicate()
        if v:
            return v
        time.sleep(interval)
    return None


# --------------------------------------------------------------------------
# pjsua
# --------------------------------------------------------------------------
class PjsuaCli:
    """Telnet client for pjsua's CLI. Line protocol, prompt is '<something>> '."""

    def __init__(self, port, timeout=10):
        deadline = time.time() + timeout
        last = None
        while time.time() < deadline:
            try:
                self.sock = socket.create_connection((PBX_IP, port), 2)
                break
            except OSError as e:
                last = e
                time.sleep(0.25)
        else:
            raise RuntimeError("pjsua CLI never opened on port %d (%s)" % (port, last))
        self.sock.settimeout(0.6)
        self.drain()

    def drain(self):
        """Read whatever is pending; strips telnet IAC noise crudely but adequately."""
        chunks = b""
        try:
            while True:
                d = self.sock.recv(65536)
                if not d:
                    break
                chunks += d
        except OSError:
            pass
        return "".join(chr(c) for c in chunks if c == 10 or 9 <= c < 127)

    def send(self, cmd, settle=0.8):
        self.sock.sendall(cmd.encode() + b"\r\n")
        time.sleep(settle)
        return self.drain()

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


class PjsuaUA:
    """One pjsua process registered to the PBX as `ext`."""

    def __init__(self, name, ext, host_octet, sip_port, rtp_port, cli_port,
                 auto_answer=200, extra=()):
        self.name = name
        self.ext = ext
        self.ip = "127.0.0.%d" % host_octet
        self.sip_port = sip_port
        self.rtp_port = rtp_port
        self.cli_port = cli_port
        self.auto_answer = auto_answer
        self.extra = list(extra)
        self.logfile = os.path.join(LOGDIR, "pjsua-%s.log" % name)
        self.proc = None
        self.cli = None

    def argv(self, binary):
        return [
            binary,
            "--null-audio", "--no-vad", "--no-tcp",
            "--ip-addr=%s" % self.ip, "--bound-addr=%s" % self.ip,
            "--local-port=%d" % self.sip_port,
            "--rtp-port=%d" % self.rtp_port,
            "--id=sip:%s@%s" % (self.ext, PBX_IP),
            "--registrar=sip:%s:%d" % (PBX_IP, PBX_SIP_PORT),
            "--realm=*", "--username=%s" % self.ext, "--password=%s" % self.ext,
            "--reg-timeout=300",
            "--auto-answer=%d" % self.auto_answer,
            "--max-calls=4",
            "--log-level=5", "--app-log-level=3",
            "--log-file=%s" % self.logfile,
            "--use-cli", "--no-cli-console",
            "--cli-telnet-port=%d" % self.cli_port,
        ] + self.extra

    def start(self, binary):
        self.proc = subprocess.Popen(
            self.argv(binary), stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
        self.cli = PjsuaCli(self.cli_port)
        return self

    def mark(self):
        """Byte offset into the log, so later waits ignore earlier scenarios."""
        try:
            return os.path.getsize(self.logfile)
        except OSError:
            return 0

    def log_since(self, mark):
        # Seek in BYTES, the unit mark() records. Slicing text-mode read() output
        # by a byte offset starts late by one char per \r\n before the mark (text
        # mode folds each to \n), and the log carries full SIP messages, so by
        # mid-suite that is ~2000 chars of skipped fresh log -- issue #378.
        try:
            with open(self.logfile, "rb") as f:
                f.seek(mark)
                return f.read().decode("utf-8", "replace")
        except OSError:
            return ""

    def wait_log(self, pattern, timeout=8.0, mark=0, flags=0):
        rx = re.compile(pattern, flags)
        return wait_for(lambda: rx.search(self.log_since(mark)), timeout)

    def registered(self, timeout=12.0):
        return self.wait_log(r"registration success|status=200.*\bOK\b", timeout) is not None

    def cmd(self, c, settle=0.8):
        return self.cli.send(c, settle)

    # --- call verbs -------------------------------------------------------
    def call(self, target, settle=1.0):
        return self.cmd("call new sip:%s@%s:%d" % (target, PBX_IP, PBX_SIP_PORT), settle)

    def hangup_all(self):
        return self.cmd("call hangup_all", 0.8)

    def current_call_id(self):
        """pjsua's id for the call it currently has selected, or None.

        Ids are slot numbers, reused as calls end, so they cannot be hardcoded --
        `call transfer_replaces` takes one and rejects anything else with
        "%Error : Invalid Arguments" and no REFER on the wire.
        """
        m = re.search(r"Current call id=(\d+)", self.cmd("call list", 1.2))
        return int(m.group(1)) if m else None

    def rtp_counters(self):
        """(rx_pkt, tx_pkt) for the current call, from `call dump_q`.

        The dump goes to the log as well as the CLI socket, and the log is the
        reliable copy -- a slow dump can outrun the socket's settle window.
        Format is 'RX pt=0, last update:...' then '   total 182pkt 29.1KB'.
        """
        mark = self.mark()
        self.cmd("call dump_q", 1.5)
        text = self.log_since(mark)
        rx = tx = 0
        m = re.search(r"RX pt=.*?total (\d+)pkt", text, re.S)
        if m:
            rx = int(m.group(1))
        m = re.search(r"TX pt=.*?total (\d+)pkt", text, re.S)
        if m:
            tx = int(m.group(1))
        return rx, tx

    def stop(self):
        if self.cli:
            self.cli.close()
        if self.proc and self.proc.poll() is None:
            self.proc.send_signal(signal.SIGTERM)
            try:
                self.proc.wait(timeout=4)
            except subprocess.TimeoutExpired:
                self.proc.kill()


# --------------------------------------------------------------------------
# baresip (optional)
# --------------------------------------------------------------------------
class BaresipUA:
    """baresip driven over its ctrl_tcp module (netstring-framed JSON)."""

    def __init__(self, name, ext, host_octet, sip_port, ctrl_port):
        self.name = name
        self.ext = ext
        self.ip = "127.0.0.%d" % host_octet
        self.sip_port = sip_port
        self.ctrl_port = ctrl_port
        self.cfgdir = os.path.join(LOGDIR, "baresip-%s" % name)
        self.logfile = os.path.join(LOGDIR, "baresip-%s.log" % name)
        self.proc = None
        self.sock = None
        self.rxbuf = b""

    @staticmethod
    def module_dir():
        """Where this baresip's modules live, or None to use its built-in default.

        The config must name it: without `module_path` Debian's baresip looks in
        ./, loads nothing, never opens ctrl_tcp, and mixed_stack SKIPs exactly as
        if baresip were absent. BARESIP_MODULES=<dir> is searched first, for a
        user-side install (e.g. ~/baresip-root/usr/lib/baresip/modules).
        """
        import glob
        for d in [os.environ.get("BARESIP_MODULES", ""), "/usr/lib/baresip/modules",
                  "/usr/local/lib/baresip/modules"] + \
                 glob.glob("/usr/lib/*/baresip/modules"):
            if os.path.isfile(os.path.join(d, "ctrl_tcp.so")):
                return d
        return None

    def write_config(self):
        os.makedirs(self.cfgdir, exist_ok=True)
        mdir = self.module_dir()
        cfg = "\n".join(([("module_path\t\t%s" % mdir)] if mdir else []) + [
            "sip_listen\t\t%s:%d" % (self.ip, self.sip_port),
            "audio_player\t\taufile,%s" % os.path.join(self.cfgdir, "out.wav"),
            "audio_source\t\tausine,440",
            # ausine only generates 48 kHz, and baresip 1.0.0's (ubuntu-24.04) only
            # stereo -- 1.1.0 accepts stereo too. Without these the source fails to
            # start against the 8 kHz mono PCMU codec and the call carries no RTP at
            # all. Declaring both makes baresip resample 48k/2ch -> 8k/1ch.
            "ausrc_srate\t\t48000",
            "ausrc_channels\t\t2",
            "audio_alert\t\taufile,%s" % os.path.join(self.cfgdir, "alert.wav"),
            "ctrl_tcp_listen\t\t%s:%d" % (PBX_IP, self.ctrl_port),
            "module\t\t\tstdio.so",
            "module\t\t\tausine.so",
            "module\t\t\taufile.so",
            "module\t\t\tg711.so",
            "module\t\t\tctrl_tcp.so",
            "module\t\t\tmenu.so",
            "module\t\t\taccount.so",
            "",
        ])
        with open(os.path.join(self.cfgdir, "config"), "w") as f:
            f.write(cfg)
        # answermode=manual: BS only ever dials. Auto-answering the PBX's
        # register-beep call put the PBX's BYE right on "Call established",
        # and baresip 1.1.0's aufile teardown race then died ("auframe: init:
        # unsupported sample format"), breaking mixed_stack's ctrl pipe.
        acct = "<sip:%s@%s>;auth_pass=%s;outbound=\"sip:%s:%d\";regint=300;answermode=manual;audio_codecs=PCMU,PCMA\n" % (
            self.ext, PBX_IP, self.ext, PBX_IP, PBX_SIP_PORT)
        with open(os.path.join(self.cfgdir, "accounts"), "w") as f:
            f.write(acct)

    def start(self, binary):
        self.write_config()
        log = open(self.logfile, "w")
        self.proc = subprocess.Popen([binary, "-f", self.cfgdir, "-v"],
                                     stdin=subprocess.DEVNULL, stdout=log,
                                     stderr=subprocess.STDOUT)
        deadline = time.time() + 12
        while time.time() < deadline:
            try:
                self.sock = socket.create_connection((PBX_IP, self.ctrl_port), 2)
                self.sock.settimeout(0.6)
                return self
            except OSError:
                time.sleep(0.3)
        raise RuntimeError("baresip ctrl_tcp never opened on %d (see %s)"
                           % (self.ctrl_port, self.logfile))

    def cmd(self, command, params=""):
        """ctrl_tcp speaks netstrings: '<len>:<payload>,'."""
        payload = json.dumps({"command": command, "params": params,
                              "token": "%d" % int(time.time() * 1000)}).encode()
        self.sock.sendall(b"%d:%s," % (len(payload), payload))
        time.sleep(0.8)
        try:
            while True:
                d = self.sock.recv(65536)
                if not d:
                    break
                self.rxbuf += d
        except OSError:
            pass
        return self.rxbuf.decode("utf-8", "replace")

    def log(self):
        try:
            with open(self.logfile, "r", errors="replace") as f:
                return f.read()
        except OSError:
            return ""

    def registered(self, timeout=12.0):
        return wait_for(lambda: re.search(r"\{%s\}.*(OK|200)" % re.escape(self.ext),
                                          self.log()) or "registered successfully"
                        in self.log(), timeout) is not None

    def stop(self):
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass
        if self.proc and self.proc.poll() is None:
            self.proc.send_signal(signal.SIGTERM)
            try:
                self.proc.wait(timeout=4)
            except subprocess.TimeoutExpired:
                self.proc.kill()


# --------------------------------------------------------------------------
# PBX under test
# --------------------------------------------------------------------------
class Pbx:
    def __init__(self, binary):
        self.binary = binary
        self.logfile = os.path.join(LOGDIR, "pbx.log")
        self.proc = None

    def start(self):
        log = open(self.logfile, "w")
        self.proc = subprocess.Popen(
            [self.binary, "--ip", PBX_IP, "--port", str(PBX_SIP_PORT),
             "--web", str(PBX_WEB_PORT)],
            stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT)
        if not wait_for(lambda: http_json("/api/status") is not None, 15):
            raise RuntimeError("PBX web API never came up (see %s)" % self.logfile)
        return self

    def stop(self):
        if self.proc and self.proc.poll() is None:
            self.proc.send_signal(signal.SIGTERM)
            try:
                self.proc.wait(timeout=4)
            except subprocess.TimeoutExpired:
                self.proc.kill()


# --------------------------------------------------------------------------
# scenarios
# --------------------------------------------------------------------------
def sc_register(env):
    a, b = env["A"], env["B"]
    ok = a.registered() and b.registered()
    return report("register", "OK" if ok else "FAIL",
                  "two pjsua UAs REGISTER" if ok else "no 200 to REGISTER in pjsua log")


def sc_echo777_rtp(env):
    a = env["A"]
    m = a.mark()
    a.call("777")
    if not a.wait_log(r"state changed to CONFIRMED", 10, m):
        a.hangup_all()
        return report("echo777_rtp", "FAIL", "777 never reached CONFIRMED")
    time.sleep(2.0)
    rx, tx = a.rtp_counters()
    a.hangup_all()
    ok = rx > 0 and tx > 0
    return report("echo777_rtp", "OK" if ok else "FAIL",
                  "RTP rx=%d tx=%d (echo loops the caller's own SDP back)" % (rx, tx))


def sc_p2p_call(env):
    """A -> B through the PBX: real O/A, real RTP both ways, callee-side BYE."""
    a, b = env["A"], env["B"]
    ma, mb = a.mark(), b.mark()
    a.call(b.ext)
    if not a.wait_log(r"state changed to CONFIRMED", 10, ma):
        a.hangup_all()
        return report("p2p_call", "FAIL", "caller never CONFIRMED")
    if not b.wait_log(r"state changed to CONFIRMED", 5, mb):
        a.hangup_all()
        return report("p2p_call", "FAIL", "callee never CONFIRMED")
    time.sleep(2.0)
    arx, atx = a.rtp_counters()
    brx, btx = b.rtp_counters()
    b.hangup_all()
    a_saw_bye = a.wait_log(r"(is|to) DISCONNECTED", 6, ma) is not None
    a.hangup_all()
    ok = arx > 0 and atx > 0 and brx > 0 and btx > 0 and a_saw_bye
    return report("p2p_call", "OK" if ok else "FAIL",
                  "A rx/tx=%d/%d B rx/tx=%d/%d, callee BYE reached caller=%s"
                  % (arx, atx, brx, btx, a_saw_bye))


def sc_hold_resume(env):
    """re-INVITE hold then resume. The PBX relays the hold offer untouched."""
    a, b = env["A"], env["B"]
    ma = a.mark()
    a.call(b.ext)
    if not a.wait_log(r"state changed to CONFIRMED", 10, ma):
        a.hangup_all()
        return report("hold_resume", "FAIL", "setup call never CONFIRMED")
    # Mark AFTER the call is up: the previous scenario's teardown line can still
    # be flushing into the log when this one starts, and reading it back as this
    # call's disconnect made `still_up` flap.
    m_live = a.mark()
    time.sleep(1.0)

    mb_hold = b.mark()
    a.cmd("call hold", 2.0)
    # pjsip renders hold as sendonly (inactive if both sides hold). The callee
    # must see the re-INVITE carrying it -- the PBX relays the body untouched.
    hold_sdp = a.wait_log(r"a=(sendonly|inactive)", 6, mb_hold) is not None or \
        re.search(r"a=(sendonly|inactive)", b.log_since(mb_hold)) is not None

    mb_res = b.mark()
    a.cmd("call reinvite", 2.0)
    resumed = re.search(r"a=(sendrecv|recvonly)", b.log_since(mb_res)) is not None or \
        b.wait_log(r"a=(sendrecv|recvonly)", 6, mb_res) is not None

    # A disconnect during hold/resume is exactly what this scenario is here to catch.
    still_up = re.search(r"(is|to) DISCONNECTED", a.log_since(m_live)) is None
    a.hangup_all()
    ok = hold_sdp and resumed and still_up
    return report("hold_resume", "OK" if ok else "FAIL",
                  "callee saw hold SDP=%s, resume SDP=%s, call survived=%s"
                  % (hold_sdp, resumed, still_up))


def sc_cancel_ringing(env):
    """Caller CANCELs while the callee is still ringing -> 487 and no stuck session."""
    a, r = env["A"], env["R"]
    ma, mr = a.mark(), r.mark()
    a.call(r.ext)
    if not r.wait_log(r"Received Request msg INVITE|RX .*INVITE", 8, mr):
        a.hangup_all()
        return report("cancel_ringing", "FAIL", "ringing UA never got the INVITE")
    time.sleep(0.8)
    a.cmd("call hangup", 1.5)            # pre-answer hangup == CANCEL
    cancelled = r.wait_log(r"CANCEL", 6, mr) is not None
    terminated = a.wait_log(r"487|Request Terminated|(is|to) DISCONNECTED",
                            8, ma) is not None
    a.hangup_all()
    r.hangup_all()
    time.sleep(1.5)
    st = http_json("/api/status") or {}
    active = st.get("activeCalls", st.get("active_calls", 0))
    ok = cancelled and terminated and not active
    return report("cancel_ringing", "OK" if ok else "FAIL",
                  "callee got CANCEL=%s, caller terminated=%s, PBX activeCalls=%s"
                  % (cancelled, terminated, active))


def sc_blind_transfer(env):
    """A<->B established, then A REFERs B to C with no Replaces.

    RFC 3515 s2 / RFC 5359 s2.4: B ends up talking to C and A drops out. This
    scenario used to assert the reverse ("transferee torn down"), matching a PBX
    that BYEd B and dialled A through to C -- issue #197, fixed by #211.

    When those corrected assertions were first actually executed (2026-09-21)
    they reported a failure the PBX was not committing: `b_torn` used a bare
    r"BYE", which matches both the Allow: header on the transfer's own
    re-INVITE and the "Received RTCP BYE" pjsua logs when that re-INVITE
    re-points the media. A correct blind transfer produces both, so the
    assertion could never pass. See TEARDOWN_RX.

    B's survival is now checked as "re-INVITEd AND not torn down": the second
    half alone would also pass a PBX that dropped A, INVITEd C, and left B
    sitting on a dead leg.
    """
    a, b, c = env["A"], env["B"], env["C"]
    ma = a.mark()
    a.call(b.ext)
    if not a.wait_log(r"state changed to CONFIRMED", 10, ma):
        a.hangup_all()
        return report("blind_transfer", "FAIL", "setup call never CONFIRMED")
    time.sleep(1.0)
    ma2, mb2, mc2 = a.mark(), b.mark(), c.mark()
    a.cmd("call transfer sip:%s@%s:%d" % (c.ext, PBX_IP, PBX_SIP_PORT), 3.0)
    accepted = a.wait_log(r"202 Accepted|202/REFER", 6, ma2) is not None
    # The TRANSFEROR is the one that leaves.
    a_torn = a.wait_log(TEARDOWN_RX, 8, ma2) is not None
    c_invited = c.wait_log(r"INVITE", 8, mc2) is not None
    # B must be MOVED, not merely left alive. "No teardown seen" alone would
    # also pass a PBX that 202s the REFER, drops A, INVITEs C and then simply
    # forgets B -- B would sit CONFIRMED on a dead leg, untorn and unmoved.
    # B ACCEPTING the swap re-INVITE is the positive evidence it was re-pointed.
    b_reinvited = b.wait_log(ACCEPTED_REINVITE_RX, 8, mb2) is not None
    # Checked last, and only as "no teardown seen": a pass costs the full
    # timeout, which is why it is not first.
    b_torn = b.wait_log(TEARDOWN_RX, 6, mb2) is not None
    for ua in (a, b, c):
        ua.hangup_all()
    # #402: A's own BYE (after the NOTIFY) ends A's leg whatever the PBX sends,
    # so "dropped" can't see a refused server BYE -- this does. Checked after
    # cleanup so the PBX's teardown BYEs are covered too.
    time.sleep(1.0)
    refused = refusals((a, ma2), (b, mb2), (c, mc2))
    ok = accepted and a_torn and c_invited and b_reinvited and not b_torn and not refused
    return report("blind_transfer", "OK" if ok else "FAIL",
                  "202 to REFER=%s, transferor dropped=%s, target INVITEd=%s, "
                  "transferee accepted re-INVITE=%s, transferee survived=%s, 5xx from=%s"
                  % (accepted, a_torn, c_invited, b_reinvited, not b_torn, refused or "none"))


def sc_attended_transfer(env):
    """A holds B, calls C, then REFERs with Replaces so B and C are spliced."""
    a, b, c = env["A"], env["B"], env["C"]
    ma = a.mark()
    a.call(b.ext)
    if not a.wait_log(r"state changed to CONFIRMED", 10, ma):
        a.hangup_all()
        return report("attended_transfer", "FAIL", "A->B never CONFIRMED")
    ab_id = a.current_call_id()
    a.cmd("call hold", 1.5)
    m2 = a.mark()
    a.call(c.ext)
    if not a.wait_log(r"state changed to CONFIRMED", 10, m2):
        a.hangup_all()
        return report("attended_transfer", "FAIL", "A->C never CONFIRMED")
    if ab_id is None:
        a.hangup_all()
        return report("attended_transfer", "FAIL", "could not read pjsua's call id for A-B")
    time.sleep(1.0)
    ma3, mb2, mc2 = a.mark(), b.mark(), c.mark()
    # Issued while the A-C call is current: REFER C to replace A's leg on the
    # A-B dialog, so B and C end up talking to each other.
    reply = a.cmd("call transfer_replaces %d" % ab_id, 3.5)
    # pjsua's call-id picker refuses some ids (observed: the highest slot, 3,
    # under --max-calls=4) by echoing a bare "^" and sending NO REFER. Left
    # unreported that reads as "the PBX never answered the REFER" -- a harness
    # failure dressed as a PBX one. Name it for what it is.
    if re.search(r"^\s*\^\s*$|Invalid Arg|%Error", reply or "", re.M):
        for ua in (a, b, c):
            ua.hangup_all()
        return report("attended_transfer", "FAIL",
                      "HARNESS: pjsua CLI rejected 'call transfer_replaces %d' (no REFER sent) "
                      "-- pjsua call-slot issue, not a PBX result" % ab_id)
    accepted = a.wait_log(r"202 Accepted|202/REFER", 8, ma3) is not None
    # #402: each side must ACCEPT its splice re-INVITE. Arrival passed for every
    # run while B 500'd its re-INVITE and was never connected to C.
    b_spliced = b.wait_log(ACCEPTED_REINVITE_RX, 8, mb2) is not None
    c_spliced = c.wait_log(ACCEPTED_REINVITE_RX, 8, mc2) is not None
    for ua in (a, b, c):
        ua.hangup_all()
    # After cleanup: the bridge's teardown BYE to the surviving side only goes
    # out when the other side hangs up here, and it was 500'd too.
    time.sleep(1.0)
    refused = refusals((a, ma3), (b, mb2), (c, mc2))
    ok = accepted and b_spliced and c_spliced and not refused
    return report("attended_transfer", "OK" if ok else "FAIL",
                  "202 to REFER=%s, B accepted splice=%s, C accepted splice=%s, 5xx from=%s"
                  % (accepted, b_spliced, c_spliced, refused or "none"))


def sc_park_retrieve(env):
    """A parks a live 777 call on orbit 700; C retrieves it from another phone."""
    a, c = env["A"], env["C"]
    ma = a.mark()
    a.call("777")
    if not a.wait_log(r"state changed to CONFIRMED", 10, ma):
        a.hangup_all()
        return report("park_retrieve", "FAIL", "777 setup never CONFIRMED")
    m_park = a.mark()
    a.call("700")                        # a park invite is a brand-new dialog by design
    parked = a.wait_log(r"state changed to CONFIRMED", 8, m_park) is not None
    hold_sdp = re.search(r"a=inactive", a.log_since(m_park)) is not None

    mc = c.mark()
    c.call("700")                        # retrieve from a different extension
    retrieved = c.wait_log(r"state changed to CONFIRMED", 10, mc) is not None

    m_bye = a.mark()
    c.hangup_all()
    # The parker's leg must actually END, not merely receive a BYE: #389's BYE
    # arrived on every run but reused the re-INVITE's CSeq, pjsua answered
    # "500 Invalid CSeq", and the leg stayed CONFIRMED -- which TEARDOWN_RX's
    # "Request msg BYE" half matched as success. A's 777 call stays up until
    # hangup_all below, so the only DISCONNECTED in this window is the 700 leg.
    parker_ended = a.wait_log(r"Call \d+ is DISCONNECTED", 8, m_bye) is not None
    bye_rejected = re.search(r"Response msg 500/BYE", a.log_since(m_bye)) is not None
    a.hangup_all()
    ok = parked and hold_sdp and retrieved and parker_ended and not bye_rejected
    return report("park_retrieve", "OK" if ok else "FAIL",
                  "park 200 w/ a=inactive=%s, retrieve CONFIRMED=%s, parker's leg ended=%s, "
                  "parker 500'd the BYE=%s"
                  % (parked and hold_sdp, retrieved, parker_ended, bye_rejected))


def dnd_flag(ext):
    """True when the PBX's own status view lists `ext` as do-not-disturb.

    /api/status renders DND as an array of extension strings ("dnd":["601"]),
    not a per-extension boolean.
    """
    st = http_json("/api/status")
    if not isinstance(st, dict):
        return False
    return str(ext) in [str(x) for x in (st.get("dnd") or [])]


def sc_dtmf_info_dnd(env):
    """*60 sent as SIP INFO by a real stack must toggle DND, and *80 clear it.

    Deliberately SIP INFO, not RFC 2833: pocket-dial's call path is peer-to-peer
    media by design (docs/FEATURE_ROADMAP Non-Goals), so on an ordinary call the
    server never sees the RTP at all -- and the 777 echo answers with the
    CALLER'S OWN SDP, so even there the digits loop back to the caller and never
    reach the PBX. In-band DTMF feature codes are architecturally unavailable
    here; DtmfFeatureCodes parses "Signal=" out of an INFO body. What this
    scenario adds over office_smoke.py is that the INFO comes from pjsip's own
    dialog state rather than a hand-built request.
    """
    a = env["A"]
    ma = a.mark()
    a.call("777")
    if not a.wait_log(r"state changed to CONFIRMED", 10, ma):
        a.hangup_all()
        return report("dtmf_info_dnd", "FAIL", "777 never CONFIRMED")
    time.sleep(1.0)
    a.cmd("call d_info *60", 3.0)
    set_ok = wait_for(lambda: dnd_flag(a.ext), 6) is not None

    cleared = None
    if set_ok:                           # leave the extension the way we found it
        a.cmd("call d_info *80", 3.0)
        cleared = wait_for(lambda: not dnd_flag(a.ext), 6)
    a.hangup_all()
    ok = set_ok and cleared is not None
    return report("dtmf_info_dnd", "OK" if ok else "FAIL",
                  "*60 set DND=%s, *80 cleared it=%s" % (set_ok, cleared is not None))


def sc_mixed_stack(env):
    """baresip -> pjsua through the PBX: two different stacks must agree on O/A."""
    bs = env.get("BS")
    if bs is None:
        return report("mixed_stack", "SKIP", "baresip not installed")
    b = env["B"]
    mb = b.mark()
    bs.cmd("dial", "%s@%s:%d" % (b.ext, PBX_IP, PBX_SIP_PORT))
    up = b.wait_log(r"state changed to CONFIRMED", 12, mb) is not None
    time.sleep(2.0)
    rx, tx = b.rtp_counters() if up else (0, 0)
    bs.cmd("hangup")
    b.hangup_all()
    ok = up and rx > 0 and tx > 0
    return report("mixed_stack", "OK" if ok else "FAIL",
                  "baresip->pjsua CONFIRMED=%s, pjsua RTP rx/tx=%d/%d" % (up, rx, tx))


# --------------------------------------------------------------------------
# heap/stack telemetry (#235 item 3)
# --------------------------------------------------------------------------
# HttpServer::sendApiStatus() (src/Helpers/HttpServer.cpp) emits an additive
# JSON block for Issue #185: 8 heap counters, resetReason, and 9 per-task
# stackHwm_* fields. Everything in it is #if defined(ESP_PLATFORM); the #else
# arm emits the same key set with every reading replaced by 0 (the 8 numeric
# fields) or JSON null (the 9 stackHwm_* fields) -- see that file's own
# comment and docs/API.md, which documents "0 on the host build" / "null on
# the host build" for each field. #225/#321 (Issue #185, #235) wired real,
# non-zero readings for these keys on-device; nothing exercised that wiring
# against a live server's actual HTTP response until now.
#
# #235 item 3 asks to "record" these fields in "the host-test heap_debug
# interop config". No such config exists in this file or anywhere under
# tests/interop/ (grepped) -- the only `heap_debug` in the repo is
# .github/workflows/ci.yml's firmware sdkconfig fragment, an unrelated
# on-device build variant this harness cannot drive (it spawns a plain host
# subprocess; see find_server() below). Treated as descriptive rather than
# literal: what's actually missing is a scenario here, so that's what this
# adds.
#
# This harness always drives a HOST build -- find_server() only ever locates
# a locally-built `SipServer` binary and Pbx.start() runs it as a plain
# subprocess -- so there is no path here that could ever produce a real
# on-device reading. Recording these fields honestly therefore means pinning
# the HOST branch's exact contract (key presence, right JSON type, right
# "empty" value), not inventing a plausible non-zero host stub the firmware
# never actually emits: a stub would assert something that isn't true of the
# code, and a later real reading that happens to land on 0 (unusual but legal
# right after boot) would then look like a regression that never happened.
#
# telemetry_check() is a pure function (no I/O) precisely so it can be
# mutation-tested without pjsua/baresip installed at all -- feed it captured
# or hand-built /api/status dicts and check its verdict, same as any other
# unit test, then separately confirm sc_heap_telemetry() wires it to a real
# running server. The recording itself is TELEMETRY_SNAPSHOT_PATH: a JSON
# file (re)written every run, pass or fail, alongside the per-UA logs in
# tests/interop/.logs/ -- something to diff against later, and, if this
# harness is ever pointed at a real device's already-running /api/status
# instead of spawning the binary itself, the same file would start holding
# actual device numbers without any code change here.
TELEMETRY_SNAPSHOT_PATH = os.path.join(LOGDIR, "telemetry.json")

# The 8 counters that are always an int on both platforms (0 on host, never
# null there -- these are readings that always exist, just at "nothing to
# report yet" on a build with no FreeRTOS/heap_caps).
TELEMETRY_NUMERIC_FIELDS = (
    "freeHeap", "minFreeHeap", "minFreeHeapSpiram", "minFreeHeapInternal",
    "freeHeapInternal", "largestFreeBlockInternal",
    "freeHeapDma", "largestFreeBlockDma",
)
# The 9 per-task fields: int on-device (when that task exists / has run),
# JSON null (-> Python None) otherwise -- always PRESENT as a key, on both
# platforms, per docs/API.md.
TELEMETRY_HWM_FIELDS = (
    "stackHwm_sip_server_task", "stackHwm_udp_receiver_task",
    "stackHwm_rtp_media_tx", "stackHwm_rtp_media_rx", "stackHwm_conf_mix_tick",
    "stackHwm_tel_ctl0", "stackHwm_tel_ctl1", "stackHwm_tel_drop", "stackHwm_tel_sos",
)


def telemetry_check(status):
    """Verify one /api/status JSON value's #185 telemetry block.

    Pure and side-effect-free: takes whatever http_json() would have
    returned (a dict, or None on a transport/JSON error) and returns
    (ok, detail, snapshot). `snapshot` is always a plain dict -- of every
    field actually present plus a "platform" tag -- meant to be persisted
    (to TELEMETRY_SNAPSHOT_PATH) regardless of `ok`, so a FAIL leaves
    something to look at rather than nothing.
    """
    if not isinstance(status, dict):
        return False, "/api/status did not return a JSON object", {"platform": "unknown"}

    all_fields = TELEMETRY_NUMERIC_FIELDS + TELEMETRY_HWM_FIELDS + ("resetReason",)
    snapshot = {k: status.get(k) for k in all_fields if k in status}
    missing = [k for k in all_fields if k not in status]
    if missing:
        snapshot["platform"] = "unknown"
        return False, "missing key(s): %s" % ", ".join(missing), snapshot

    # pdResetReasonString() (HttpServer.cpp) never returns "n/a" -- only the
    # host #else arm hardcodes that literal -- so this is an exact, not a
    # heuristic, host/device discriminator.
    is_host = status.get("resetReason") == "n/a"
    snapshot["platform"] = "host" if is_host else "device"

    if is_host:
        bad_numeric = [k for k in TELEMETRY_NUMERIC_FIELDS if status.get(k) != 0]
        bad_hwm = [k for k in TELEMETRY_HWM_FIELDS if status.get(k) is not None]
        if bad_numeric or bad_hwm:
            return False, ("host build must report 0/null (docs/API.md), got "
                           "numeric=%s hwm=%s" % (bad_numeric, bad_hwm)), snapshot
        return True, ("host build: shape verified (8 numeric fields=0, "
                      "9 stackHwm_*=null, by construction)"), snapshot

    # Not reachable from this harness today (see the module comment above),
    # kept honest anyway: a real device reading must be an actual int, not
    # null-forever and not a copy-pasted host zero. isinstance(x, bool) is
    # excluded explicitly since bool is a subclass of int in Python and JSON
    # has no separate bool/int confusion here, but it costs nothing to be
    # precise about what "an int" means.
    def is_real_int(v):
        return isinstance(v, int) and not isinstance(v, bool)

    bad_numeric = [k for k in TELEMETRY_NUMERIC_FIELDS if not is_real_int(status.get(k))]
    # docs/API.md: stackHwm_sip_server_task/udp_receiver_task can also read
    # null pre-provisioning, and the three call/conference tasks read null
    # whenever nothing is using them -- null is an ordinary device reading
    # for this group, not a wiring gap.
    bad_hwm = [k for k in TELEMETRY_HWM_FIELDS
               if status.get(k) is not None and not is_real_int(status.get(k))]
    if bad_numeric or bad_hwm:
        return False, ("device build has wrong type(s), numeric=%s hwm=%s"
                       % (bad_numeric, bad_hwm)), snapshot
    return True, "device build: fields recorded", snapshot


def sc_heap_telemetry(env):
    """Pin #185/#235's heap/stack telemetry block's presence, type and
    host-build values against a real, running server, and record it.

    Deliberately independent of `env` / any UA: sendApiStatus() emits this
    block unconditionally, so asserting it only while other scenarios happen
    to have calls up would make a real wiring gap look like flakiness.
    Placed last in SCENARIOS so that if this harness is ever extended to run
    against a live device instead of spawning the host binary, the snapshot
    it records reflects post-call state (rtp_media_tx/rx, conf_mix_tick),
    not just a cold boot.
    """
    status = http_json("/api/status")
    ok, detail, snapshot = telemetry_check(status)
    try:
        with open(TELEMETRY_SNAPSHOT_PATH, "w") as f:
            json.dump(snapshot, f, indent=2, sort_keys=True)
    except OSError as e:
        return report("heap_telemetry", "FAIL",
                      "%s (also could not write %s: %r)"
                      % (detail, TELEMETRY_SNAPSHOT_PATH, e))
    return report("heap_telemetry", "OK" if ok else "FAIL",
                  "%s (recorded -> %s)" % (detail, TELEMETRY_SNAPSHOT_PATH))


def _bye_endpoints(log, direction):
    """(cseq, ip, port) for every BYE request a UA sent ("TX ... to") or received
    ("RX ... from") in `log`. Parsed rather than string-compared: pjsua writes
    the address with a trailing colon ("to UDP 127.0.0.1:5070:"), which is
    exactly how a naive equality check reports the PBX as "not the PBX"."""
    verb, prep = ("TX", "to") if direction == "tx" else ("RX", "from")
    return re.findall(r"%s \d+ bytes Request msg BYE/cseq=(\d+) \([^)]*\) %s UDP ([0-9.]+):(\d+)"
                      % (verb, prep), log)


def _live_session_between(ext_a, ext_b):
    """True if the PBX still lists a session between these two extensions. None
    if /api/status is unreachable -- never read as False."""
    st = http_json("/api/status")
    if st is None or "sessions" not in st:
        return None
    if st["sessions"]:
        return any({s.get("caller"), s.get("callee")} == {ext_a, ext_b} for s in st["sessions"])
    # #539: an unauthenticated read gets an empty array plus sessionCount. The
    # scenarios run one at a time (hangup_all() between them), so any live
    # session here is this call's. A board without sessionCount predates #539,
    # where an empty array really meant none.
    count = st.get("sessionCount")
    return bool(count) if isinstance(count, int) else False


def _bye_went_through_pbx(caller, callee, m_caller, m_callee):
    """After `caller` hangs up, prove the teardown crossed the PBX.

    The gate is two facts that a bypassed BYE cannot fake:
      - the callee received exactly one BYE transaction (by CSeq, so a
        retransmit does not count twice), and it came FROM THE PBX -- a BYE
        that went phone-to-phone arrives from the caller's own address;
      - the PBX no longer lists a session for the call -- a bypassed BYE leaves
        it holding a ghost.

    The caller's own "TX ... BYE ... to" line is corroboration only, and is
    checked strictly when present. It cannot be the gate: pjsua buffers its log
    file, and a caller that goes idle after hanging up is stopped by the harness
    before the buffer flushes -- measured, the log ended mid-timestamp one line
    after the BYE resolved to the PBX. Requiring it made a correct teardown fail
    on log I/O, not on the PBX. Returns (ok, detail)."""
    pbx = (PBX_IP, str(PBX_SIP_PORT))
    caller.wait_log(r"TX \d+ bytes Request msg BYE", 3, m_caller)
    tx = _bye_endpoints(caller.log_since(m_caller), "tx")
    rx = _bye_endpoints(callee.log_since(m_callee), "rx")
    rx_ok = len({c for c, _, _ in rx}) == 1 and all((ip, pt) == pbx for _, ip, pt in rx)
    tx_contradicts = any((ip, pt) != pbx for _, ip, pt in tx)
    gone = wait_for(lambda: _live_session_between(caller.ext, callee.ext) is False, 5) is not None
    tx_note = ("%s" % ["%s:%s" % (i, p) for _, i, p in tx]) if tx else "unflushed"
    detail = ("callee BYE<-PBX=%s (%s), PBX session cleared=%s, caller log BYE->%s"
              % (rx_ok, ["%s:%s" % (i, p) for _, i, p in rx], gone, tx_note))
    return rx_ok and gone and not tx_contradicts, detail


def sc_hold_bye_via_pbx(env):
    """#425: after a hold/resume the PBX must still be IN the dialog.

    re-INVITE is a target refresh: the Contact in the relayed request and in its
    relayed 200 becomes each phone's remote target. Forwarded untouched they
    carried the other phone's real address, so after one hold the BYE went
    phone-to-phone and the PBX kept a ghost session after both had hung up.

    Placed on C (not A) deliberately: pjsua hands out call slots round-robin,
    and `call transfer_replaces` rejects the highest slot with a bare caret and
    no REFER (see sc_attended_transfer). One extra A-originated call here
    rotated A's slots so attended_transfer's A-B call landed on that slot."""
    c, b = env["C"], env["B"]
    mc = c.mark()
    c.call(b.ext)
    if not c.wait_log(r"state changed to CONFIRMED", 10, mc):
        c.hangup_all()
        return report("hold_bye_via_pbx", "FAIL", "setup call never CONFIRMED")
    time.sleep(1.0)
    c.cmd("call hold", 2.0)
    c.cmd("call reinvite", 2.0)
    time.sleep(1.0)
    m_c, m_b = c.mark(), b.mark()
    c.hangup_all()
    b.wait_log(r"RX \d+ bytes Request msg BYE", 6, m_b)
    time.sleep(0.5)
    ok, detail = _bye_went_through_pbx(c, b, m_c, m_b)
    b.hangup_all()
    return report("hold_bye_via_pbx", "OK" if ok else "FAIL", detail)


def sc_session_refresh(env):
    """#198: a session-timer refresh on an ordinary call must reach the far phone.

    T offers Session-Expires: 90 (the RFC 4028 floor), so it refreshes at 45 s
    and B's own timer would end the call at ~60 s without one. The PBX used to
    answer every bodiless refresh UPDATE itself: B never saw it and hung up a
    healthy call ("408 No session refresh received") -- the ~30-minute drop at
    the common 1800 s. Held 70 s: past the refresh and past B's deadline."""
    t, b = env["T"], env["B"]
    mt = t.mark()
    t.call(b.ext)
    if not t.wait_log(r"state changed to CONFIRMED", 10, mt):
        t.hangup_all()
        return report("session_refresh", "FAIL", "setup call never CONFIRMED")
    m_t, m_b = t.mark(), b.mark()
    time.sleep(70)
    tlog, blog = t.log_since(m_t), b.log_since(m_b)
    b_got = len(re.findall(r"RX \d+ bytes Request msg UPDATE", blog))
    pbx_contact = "<sip:%s@%s:%d;transport=UDP>" % (b.ext, PBX_IP, PBX_SIP_PORT)
    oks = re.findall(r"RX \d+ bytes Response msg 200/UPDATE/cseq=\d+[^\n]*\n(?:.*\n){0,25}?Contact: ([^\n]+)", tlog)
    contact_ok = bool(oks) and all(c.strip() == pbx_contact for c in oks)
    survived = re.search(r"(is|to) DISCONNECTED", tlog) is None and \
        re.search(r"(is|to) DISCONNECTED", blog) is None
    m_t2, m_b2 = t.mark(), b.mark()
    t.hangup_all()
    b.wait_log(r"RX \d+ bytes Request msg BYE", 6, m_b2)
    time.sleep(0.5)
    bye_ok, bye_detail = _bye_went_through_pbx(t, b, m_t2, m_b2)
    b.hangup_all()
    ok = b_got >= 1 and contact_ok and survived and bye_ok
    return report("session_refresh", "OK" if ok else "FAIL",
                  "B received refresh UPDATEs=%d, 200s via PBX Contact=%s, call outlived "
                  "Session-Expires=%s; %s" % (b_got, contact_ok, survived, bye_detail))


def sc_mwi(env):
    """#745: pjsua --mwi SUBSCRIBEs to message-summary after it registers. The PBX
    must 202 it and send a NOTIFY with a simple-message-summary body (empty
    mailbox: Messages-Waiting: no) that pjsua accepts with a 200."""
    m = env["M"]
    if not m.registered():
        return report("mwi", "FAIL", "M never registered")
    got = m.wait_log(r"RX \d+ bytes Request msg NOTIFY[^\n]*\n(?:.*\n){0,30}?Messages-Waiting: no", 10)
    log = m.log_since(0)
    accepted = re.search(r"Response msg 202/SUBSCRIBE", log) is not None
    acked = re.search(r"TX \d+ bytes Response msg 200/NOTIFY", log) is not None
    ok = bool(got) and accepted and acked
    return report("mwi", "OK" if ok else "FAIL",
                  "SUBSCRIBE 202=%s, NOTIFY Messages-Waiting: no=%s, pjsua 200 to NOTIFY=%s"
                  % (accepted, bool(got), acked))


# --- #739: the timer a caller asked for, and the 2xx the PBX writes itself -----
#
# pjsua at log level 5 prints every SIP message whole: a "TX|RX n bytes ..."
# line, the message, then "--end msg--". These helpers read the headers of one
# message off that trace.
#
# What the 200 to an INVITE must carry depends on what the INVITE asked (RFC 4028):
#   optional   (--use-timer=1) Supported: timer and a Session-Expires, no Require.
#              The 440 tone leg and a call pickup cannot answer the refresh a timer
#              would promise (440 declines a re-INVITE 488; a pickup relays it into
#              the peer's dialog) and only a 2xx counts as one (s10), so this caller
#              is owed none (s7.2): its 200 carries no Session-Expires and no Require.
#   mandatory  (--use-timer=2) the same plus Require: timer. s9 puts Session-Expires
#              and Require: timer in the 2xx to such an INVITE, and pjsua hangs up on
#              one without them (BYE, Reason cause=421 "Failed processing session
#              timer response"): its 200 carries both.
# --use-timer=3 adds no Require in this pjsua build, so it is not a variant here.
# Each variant has its own UAs, so no other scenario's calls carry a required timer.
# pjsua --use-timer=2 answers the PBX's register beep with 421 (the beep INVITE
# carries no timer) and the PBX frees the slot; that happens before any scenario
# window, and the checks below are scoped to the scenario's own call id anyway.
TIMER_OPTIONAL = ["--use-timer=1", "--timer-se=1800", "--timer-min-se=90"]
TIMER_MANDATORY = ["--use-timer=2", "--timer-se=1800", "--timer-min-se=90"]
# variant -> (caller UA, picker UA, whether its 200 must carry the timer)
TIMER_VARIANTS = {
    "optional": ("S", "K", False),
    "mandatory": ("SM", "KM", True),
}
CONFIRMED_RX = r"Call (\d+) state changed to CONFIRMED"
TX_INVITE_RX = r"TX \d+ bytes Request msg INVITE/cseq=\d+"
RX_200_INVITE_RX = r"RX \d+ bytes Response msg 200/INVITE/cseq=\d+"


def sip_messages(log, head):
    """Whole text of each SIP message in a pjsua log whose trace line starts with
    `head`, a regex such as RX_200_INVITE_RX."""
    return [m.group(0) for m in re.finditer(head + r"[^\n]*\n.*?--end msg--", log, re.S)]


def timer_lines(msg):
    """The Session-Expires (full or compact `x:`) and Require lines of one message."""
    return [l.strip() for l in
            re.findall(r"^(?:Session-Expires|x|Require)[ \t]*:[^\r\n]*", msg, re.M | re.I)]


def timer_state(msg):
    """(a Session-Expires or compact x: is present, a Require names timer) for one message."""
    lines = timer_lines(msg)
    return (any(re.match(r"(?:session-expires|x)\s*:", l, re.I) for l in lines),
            any(re.match(r"require\s*:.*\btimer\b", l, re.I) for l in lines))


def offer_is(required, invite):
    """True when the INVITE pjsua sent is the one this variant is for: a Session-Expires
    either way, and a Require: timer exactly when `required`. Otherwise the answer's
    shape says nothing about the PBX, and the scenario reports HARNESS."""
    has_se, req = timer_state(invite)
    return has_se and req == required


def answer_is_right(required, ok):
    """A 200 for a caller that `required` a timer carries Session-Expires AND Require:
    timer; for one that did not, it carries neither (nor any other Require)."""
    has_se, req = timer_state(ok)
    return (has_se and req) if required else not timer_lines(ok)


def admin_auth(env):
    """Admin session headers, logging in once per run: the PBX takes the shipped default
    login only until pbx_admin_login() replaces it, so a second login would fail."""
    if not env.get("ADMIN"):
        env["ADMIN"] = pbx_admin_login()
    return env["ADMIN"]


def pbx_clients(auth):
    """Extensions the PBX itself lists as registered, or None. The roster is withheld
    from an unauthenticated read (only clientCount is public, #207), so this needs the
    admin session."""
    code, _, body = pbx_http("GET", "/api/status", None, auth)
    try:
        st = json.loads(body)
    except ValueError:
        return None
    if code != 200 or not isinstance(st, dict) or not st.get("rosterVisible"):
        return None
    return {str(c.get("number")) for c in st.get("clients") or []}


def pbx_wait_registered(auth, exts, timeout=15.0):
    """True once the PBX's own roster lists every ext in `exts`. Registration is proved
    from the PBX, not from pjsua's log: "registration success" is not reliably in it."""
    return wait_for(lambda: set(exts) <= (pbx_clients(auth) or set()), timeout, 0.5) is not None


def sc_440(env, variant):
    """#739: S dials 440, and its 200 carries the timer S asked for and no other.

    `optional`: no Session-Expires, no Require. `mandatory`: Session-Expires AND
    Require: timer (see the block comment above). Passes only when ALL of: the PBX
    lists S as registered; S's first INVITE was the kind this variant is for (else
    HARNESS); pjsua reached CONFIRMED; every 200/INVITE S received is right for the
    variant and is 440's own (an SDP body and a sip:440@ Contact line, the positive
    control); and that call saw no DISCONNECTED in the 2 s after CONFIRMED (a UA
    that tears the call down on the answer did not establish). RTP is not judged:
    the loopback RTP counters read 0 under WSL."""
    name = "session_timer_440_" + variant
    s_name, _, required = TIMER_VARIANTS[variant]
    s = env[s_name]
    auth = admin_auth(env)
    if not auth:
        return report(name, "FAIL", "HARNESS: could not log in to the PBX web API")
    if not pbx_wait_registered(auth, [s.ext]):
        return report(name, "FAIL", "HARNESS: the PBX never listed %s as registered" % s.ext)
    m = s.mark()
    s.call("440")
    if not s.wait_log(CONFIRMED_RX, 10, m):
        s.hangup_all()
        return report(name, "FAIL", "440 never reached CONFIRMED")
    time.sleep(2.0)
    log = s.log_since(m)
    up = re.search(CONFIRMED_RX, log)
    gone = r"Call %s (?:is|state changed to) DISCONNECTED" % up.group(1)
    survived = re.search(gone, log[up.end():]) is None
    invites = sip_messages(log, TX_INVITE_RX)
    oks = sip_messages(log, RX_200_INVITE_RX)
    offered = bool(invites) and offer_is(required, invites[0])
    wrong = [timer_lines(ok) or ["no timer lines"] for ok in oks if not answer_is_right(required, ok)]
    own = bool(oks) and all("v=0" in ok and re.search(r"^Contact[ \t]*:[^\r\n]*sip:440@", ok, re.M | re.I)
                            for ok in oks)   # the Contact, not the To: the To carries sip:440@ whatever answers
    s.hangup_all()
    s.wait_log(gone, 6, m)                   # frees 440's single stream slot
    ok = offered and bool(oks) and own and not wrong and survived
    detail = ("%s: INVITE was the right kind=%s, 440 200s=%d (own SDP+Contact=%s), "
              "200s that are wrong=%s (must carry %s), call survived=%s"
              % (variant, offered, len(oks), own, wrong or "none",
                 "Session-Expires+Require: timer" if required else "no timer", survived))
    if not offered:
        detail = "HARNESS: the INVITE was not the %s kind -- %s" % (variant, detail)
    return report(name, "OK" if ok else "FAIL", detail)


def sc_pickup(env, variant):
    """#739: both call-pickup 200s carry the timer their caller asked for and no other.

    The caller UA dials R (604), which rings and never answers. The picker UA, in a
    ring group with R (pickup eligibility is ring-group co-membership, set over the
    web API and removed again), dials **604. The PBX completes the caller's still-open
    INVITE with the picker's SDP and the picker's INVITE with the caller's
    (CallPickup::complete; directed code PbxConfig.hpp directedPickupTarget). Every UA
    is registered in this run; no number outside it is dialled and nothing leaves
    loopback.

    Passes only when ALL of: the PBX lists caller, picker and R as registered; both
    INVITEs were the kind this variant is for (else HARNESS); both reached CONFIRMED;
    every 200/INVITE each received is right for the variant (`optional`: no
    Session-Expires, compact x: or Require; `mandatory`: Session-Expires AND
    Require: timer); each 200 is the pickup answer (the caller's carries the picker's
    media address, the picker's the caller's: the positive control); and neither call
    saw DISCONNECTED in the 2 s after both were CONFIRMED. RTP is not judged."""
    name = "session_timer_pickup_" + variant
    s_name, k_name, required = TIMER_VARIANTS[variant]
    s, k, r = env[s_name], env[k_name], env["R"]
    auth = admin_auth(env)
    if not auth:
        return report(name, "FAIL", "HARNESS: could not log in to the PBX web API")
    if not pbx_wait_registered(auth, [s.ext, k.ext, r.ext]):
        return report(name, "FAIL", "HARNESS: the PBX never listed %s, %s and %s as registered"
                      % (s.ext, k.ext, r.ext))
    group = "610"
    if not pbx_set_group(auth, group, "%s,%s" % (r.ext, k.ext)):
        return report(name, "FAIL", "HARNESS: POST /api/group refused the pickup group")
    try:
        ms, mk, mr = s.mark(), k.mark(), r.mark()
        s.call(r.ext)
        if not r.wait_log(REINVITE_RX, 8, mr):
            return report(name, "FAIL", "the ringing UA never got the INVITE (nothing to pick up)")
        time.sleep(0.8)                  # as cancel_ringing: R's 180 is up, the PBX session is Invited
        k.call("**" + r.ext)
        s_up = s.wait_log(CONFIRMED_RX, 10, ms) is not None
        k_up = k.wait_log(CONFIRMED_RX, 10, mk) is not None
        if not (s_up and k_up):
            return report(name, "FAIL", "pickup did not connect: caller CONFIRMED=%s, picker CONFIRMED=%s"
                          % (s_up, k_up))
        time.sleep(2.0)
        slog, klog = s.log_since(ms), k.log_since(mk)
        survived = True
        for log in (slog, klog):
            up = re.search(CONFIRMED_RX, log)
            gone = r"Call %s (?:is|state changed to) DISCONNECTED" % up.group(1)
            survived = survived and re.search(gone, log[up.end():]) is None
        invites = [sip_messages(slog, TX_INVITE_RX), sip_messages(klog, TX_INVITE_RX)]
        offered = all(bool(i) and offer_is(required, i[0]) for i in invites)
        s_oks = sip_messages(slog, RX_200_INVITE_RX)
        k_oks = sip_messages(klog, RX_200_INVITE_RX)
        wrong = [timer_lines(ok) or ["no timer lines"] for ok in s_oks + k_oks if not answer_is_right(required, ok)]
        own = bool(s_oks) and bool(k_oks) and \
            all(re.search(r"c=IN IP4 %s\b" % re.escape(k.ip), ok) for ok in s_oks) and \
            all(re.search(r"c=IN IP4 %s\b" % re.escape(s.ip), ok) for ok in k_oks)
        ok = offered and own and not wrong and survived
        detail = ("%s: INVITEs were the right kind=%s, 200s caller/picker=%d/%d (each carries the other "
                  "leg's SDP=%s), 200s that are wrong=%s (must carry %s), both calls survived=%s"
                  % (variant, offered, len(s_oks), len(k_oks), own, wrong or "none",
                     "Session-Expires+Require: timer" if required else "no timer", survived))
        if not offered:
            detail = "HARNESS: an INVITE was not the %s kind -- %s" % (variant, detail)
        return report(name, "OK" if ok else "FAIL", detail)
    finally:
        for ua in (s, k, r):
            ua.hangup_all()
        pbx_set_group(auth, group, "")   # the group must not outlive the scenario
        time.sleep(1.0)


SCENARIOS = [
    ("register", sc_register),
    ("echo777_rtp", sc_echo777_rtp),
    ("p2p_call", sc_p2p_call),
    ("hold_resume", sc_hold_resume),
    ("hold_bye_via_pbx", sc_hold_bye_via_pbx),
    ("cancel_ringing", sc_cancel_ringing),
    ("blind_transfer", sc_blind_transfer),
    ("attended_transfer", sc_attended_transfer),
    ("park_retrieve", sc_park_retrieve),
    ("dtmf_info_dnd", sc_dtmf_info_dnd),
    # ~75 s: must outlive a 90 s Session-Expires peer deadline (60 s). See #198.
    ("session_refresh", sc_session_refresh),
    ("mixed_stack", sc_mixed_stack),
    ("heap_telemetry", sc_heap_telemetry),
    ("mwi", sc_mwi),
    # #739: a caller that merely supports timers gets none on a 440 or pickup 200; one that
    # requires a timer gets Session-Expires and Require: timer back.
    ("session_timer_440_optional", lambda env: sc_440(env, "optional")),
    ("session_timer_440_mandatory", lambda env: sc_440(env, "mandatory")),
    ("session_timer_pickup_optional", lambda env: sc_pickup(env, "optional")),
    ("session_timer_pickup_mandatory", lambda env: sc_pickup(env, "mandatory")),
]


def find_pjsua():
    for c in [os.environ.get("PJSUA", "")] + [
            os.path.expanduser("~/pjproject/pjsip-apps/bin/pjsua-x86_64-pc-linux-gnu")]:
        if c and os.path.isfile(c) and os.access(c, os.X_OK):
            return c
    import glob
    for c in glob.glob(os.path.expanduser("~/pjproject/pjsip-apps/bin/pjsua-*")):
        if os.access(c, os.X_OK):
            return c
    return shutil.which("pjsua")


def find_server(explicit):
    for c in [explicit, os.path.join(ROOT, "build-wsl", "SipServer"),
              os.path.join(ROOT, "build_wsl", "SipServer"),
              os.path.join(ROOT, "build", "SipServer")]:
        if c and os.path.isfile(c) and os.access(c, os.X_OK):
            return c
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("server", nargs="?", default=None)
    ap.add_argument("--only", default="", help="comma-separated scenario names")
    args = ap.parse_args()

    server = find_server(args.server)
    if not server:
        print("SipServer binary not found (build-wsl/SipServer)"); return 2
    pjsua = find_pjsua()
    if not pjsua:
        print("pjsua not found; set PJSUA=/path/to/pjsua"); return 2

    if os.path.isdir(LOGDIR):
        shutil.rmtree(LOGDIR)
    os.makedirs(LOGDIR)

    print("== interop: server=%s" % server)
    print("==         pjsua=%s" % pjsua)
    pbx = Pbx(server).start()

    env = {}
    uas = [
        PjsuaUA("A", "601", 11, 5171, 6100, 2311),
        PjsuaUA("B", "602", 12, 5172, 6200, 2312),
        PjsuaUA("C", "603", 13, 5173, 6300, 2313),
        # R answers 180 and stays ringing: the only way to hold an INVITE open
        # long enough to CANCEL it.
        PjsuaUA("R", "604", 14, 5174, 6400, 2314, auto_answer=180),
        # T offers the RFC 4028 floor (Session-Expires 90) so session_refresh can
        # exercise a refresh inside a test-sized window. Its own UA, so no other
        # scenario's calls run with a 90 s timer.
        PjsuaUA("T", "606", 16, 5176, 6600, 2316,
                extra=["--timer-se=90", "--timer-min-se=90"]),
        # M subscribes to its own mailbox (RFC 3842 message-summary, #745). The
        # SUBSCRIBE targets the AOR (--id has no port, so 5060); the proxy routes
        # it to the PBX's test port instead.
        PjsuaUA("M", "607", 17, 5177, 6700, 2317,
                extra=["--mwi", "--proxy=sip:%s:%d;lr" % (PBX_IP, PBX_SIP_PORT)]),
        # #739 (session_timer_*): S and K send Supported: timer and a Session-Expires on
        # every INVITE (--use-timer=1); SM and KM add Require: timer (--use-timer=2).
        # Their own UAs, so no other scenario's calls carry either.
        PjsuaUA("S", "608", 18, 5178, 6800, 2318, extra=TIMER_OPTIONAL),
        PjsuaUA("K", "609", 19, 5179, 6900, 2319, extra=TIMER_OPTIONAL),
        PjsuaUA("SM", "611", 20, 5180, 7000, 2320, extra=TIMER_MANDATORY),
        PjsuaUA("KM", "612", 21, 5181, 7100, 2321, extra=TIMER_MANDATORY),
    ]
    for ua in uas:
        env[ua.name] = ua.start(pjsua)

    baresip = shutil.which("baresip")
    bs = None
    if baresip:
        try:
            bs = BaresipUA("BS", "605", 15, 5175, 4444).start(baresip)
            env["BS"] = bs
            print("==       baresip=%s" % baresip)
        except Exception as e:
            print("==       baresip present but would not start (%r) -- mixed_stack will SKIP" % e)
            bs = None
    else:
        print("==       baresip=absent (mixed_stack will SKIP)")
    time.sleep(2.5)

    wanted = [s.strip() for s in args.only.split(",") if s.strip()]
    print("\n== scenarios")
    try:
        for name, fn in SCENARIOS:
            if wanted and name not in wanted:
                continue
            try:
                fn(env)
            except Exception as e:
                report(name, "FAIL", "harness exception: %r" % e)
    finally:
        if bs:
            bs.stop()
        for ua in uas:
            ua.stop()
        pbx.stop()

    ok = sum(1 for _, s, _ in RESULTS if s == "OK")
    bad = sum(1 for _, s, _ in RESULTS if s == "FAIL")
    skip = sum(1 for _, s, _ in RESULTS if s == "SKIP")
    print("\n== %d passed, %d failed, %d skipped   (logs: %s)" % (ok, bad, skip, LOGDIR))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
