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
SKIP rather than FAIL, and the exit code ignores them.
"""
import argparse
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
LOGDIR = os.path.join(HERE, ".logs")

PBX_IP = "127.0.0.1"
PBX_SIP_PORT = 5070          # deliberately not 5060: a stale run_sipp.sh server
PBX_WEB_PORT = 8085          # must not silently absorb this harness's traffic

RESULTS = []   # (name, status, detail)  status in {"OK", "FAIL", "SKIP"}


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

    def log(self):
        try:
            with open(self.logfile, "r", errors="replace") as f:
                return f.read()
        except OSError:
            return ""

    def mark(self):
        """Byte offset into the log, so later waits ignore earlier scenarios."""
        try:
            return os.path.getsize(self.logfile)
        except OSError:
            return 0

    def log_since(self, mark):
        return self.log()[mark:]

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

    def write_config(self):
        os.makedirs(self.cfgdir, exist_ok=True)
        cfg = "\n".join([
            "sip_listen\t\t%s:%d" % (self.ip, self.sip_port),
            "audio_player\t\taufile,%s" % os.path.join(self.cfgdir, "out.wav"),
            "audio_source\t\tausine,440",
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
        acct = "<sip:%s@%s>;auth_pass=%s;outbound=\"sip:%s:%d\";regint=300;answermode=auto;audio_codecs=PCMU,PCMA\n" % (
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
    """A<->B established, then A REFERs B to C with no Replaces."""
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
    b_torn = b.wait_log(r"BYE|(is|to) DISCONNECTED", 8, mb2) is not None
    c_invited = c.wait_log(r"INVITE", 8, mc2) is not None
    for ua in (a, b, c):
        ua.hangup_all()
    ok = accepted and b_torn and c_invited
    return report("blind_transfer", "OK" if ok else "FAIL",
                  "202 to REFER=%s, transferee torn down=%s, target INVITEd=%s"
                  % (accepted, b_torn, c_invited))


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
    a.cmd("call transfer_replaces %d" % ab_id, 3.5)
    accepted = a.wait_log(r"202 Accepted|202/REFER", 8, ma3) is not None
    b_spliced = b.wait_log(r"Received Request msg INVITE|RX .*INVITE", 8, mb2) is not None
    c_spliced = c.wait_log(r"Received Request msg INVITE|RX .*INVITE", 8, mc2) is not None
    for ua in (a, b, c):
        ua.hangup_all()
    ok = accepted and b_spliced and c_spliced
    return report("attended_transfer", "OK" if ok else "FAIL",
                  "202 to REFER=%s, B re-INVITEd=%s, C re-INVITEd=%s"
                  % (accepted, b_spliced, c_spliced))


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
    bye_relayed = a.wait_log(r"BYE|(is|to) DISCONNECTED", 8, m_bye) is not None
    a.hangup_all()
    ok = parked and hold_sdp and retrieved and bye_relayed
    return report("park_retrieve", "OK" if ok else "FAIL",
                  "park 200 w/ a=inactive=%s, retrieve CONFIRMED=%s, BYE relayed to parker=%s"
                  % (parked and hold_sdp, retrieved, bye_relayed))


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


SCENARIOS = [
    ("register", sc_register),
    ("echo777_rtp", sc_echo777_rtp),
    ("p2p_call", sc_p2p_call),
    ("hold_resume", sc_hold_resume),
    ("cancel_ringing", sc_cancel_ringing),
    ("blind_transfer", sc_blind_transfer),
    ("attended_transfer", sc_attended_transfer),
    ("park_retrieve", sc_park_retrieve),
    ("dtmf_info_dnd", sc_dtmf_info_dnd),
    ("mixed_stack", sc_mixed_stack),
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
