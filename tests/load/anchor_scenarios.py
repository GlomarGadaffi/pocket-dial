#!/usr/bin/env python3
"""The `anchor` scenario kind (H2) for the milestone-4 harness (#384).

    python3 tests/load/sip_stress.py --scenario x4_cancel_ringing --host <rig-ip> \\
        --approval-url <recorded approval> \\
        --checkout-url <#428 comment URL> --checkout-expiry 2026-10-03T22:00Z [--set-syslog] [--dry-run]

A scenario is a named entry in SCENARIOS (the @scenario decorator below). Each one
pre-registers the log counter that proves its path ran: a run whose counter is 0
is INVALID, never PASS (#384 S3). The script, not a person, computes the verdict.

Safety, all checked before the first packet (exit 2, nothing sent):
  * a discussion #428 CHECK-OUT link whose expiry covers the run
    (load_profile.checkout_problems);
  * an approval link that is one of APPROVALS (the recorded desmo approvals) or
    EXTRA_APPROVALS; nothing else;
  * the far end comes from a 0600 file named by PD_ANCHOR_FAR_END_FILE, or from
    PD_ANCHOR_FAR_END; never from argv. A number-shaped argument is refused
    without echoing it. 911, 933 (anywhere in it), 112, 113, 999, the owner
    extensions (1001, 1002, 1003, 113, plus --owner-ext / PD_OWNER_EXTS), the test
    UAs and every PBX service number are refused as the far end;
  * the board is one of RIG_HOSTS (or loopback, for the fakes in the tests);
  * the board admin PIN comes from PD_BOARD_ADMIN_PIN, never from argv;
  * a scenario's test UAs are only 6101-6104, and its phantom detector is 6104.
Safety, checked against the board before the first call and through the run
(INVALID, the run stops):
  * S1 pin: a /api/did-mapping row maps the active anchor slot's route DN to
    6104, and 6104 is registered by THIS run (the authenticated roster shows it
    at this agent's own address). A lapse would make an inbound anchor call ring
    every phone, so it is re-checked between calls and every --pin-check-s.
  * 6104 and 6101 refuse every INVITE (486) and record it. One from anything but
    the register beep (From user "pbx") is a phantom inbound: FAIL.
  * the far end must not be registered on the board (it would ring locally).

x4_cancel_ringing times each CANCEL from a ringing reference, not from the INVITE. The PBX's 180
is local ringback, sent at INVITE time (RequestsHandler.cpp originateAnchorCall) before the 3CX call
is even requested, and no 183 or early RTP follows, so no SIP message says the far leg rings. The
witness is the syslog line "Upset <leg> -> control leg <leg> status '<not Connected>'": 3CX's
participant list shows our leg and it is not yet Connected, the state the firmware itself treats as
ringing (#667). x379_cancel_before_leg is the other race: its CANCEL goes 0.3-0.8 s after the INVITE,
before the makecall response, so before any 3CX leg exists.

The far end must not route back into this board. The board exposes its route DN and its DID rows
but not the tenant's own numbers, so a far end equal to the route DN or to a DID row is INVALID
before the first packet, and any phantom verdict says it holds only if the far end cannot route back.

Probe scenarios (x349_unread_makecall, x379_never_opened, x518_403_clean_giveup,
x279_degraded_bye) drive the bench probe image (docs/BENCH_PROBE.md, #384 H1):
they need --expect-version with a -probe stamp, read /api/bench/fault's counters
before and after, arm only their pre-registered faults (never for an emergency far
end, never while the probe reports an emergency), and always disarm every fault and
release the ballast in a finally block. The counters must show nothing armed at the
end, and every pre-registered fault must show fired >= 1, or the run is INVALID.

Syslog carries esp_log lines only. RequestsHandler's queueLog() lines (e.g. "anchor
call torn down: ...", "no rx audio, dropping leg") go to stdout and never reach it
(#533/#603), so the scenarios count the esp_log witnesses instead: "pbx: endCall
<Call-ID> reason=...", "MediaBridge: stopBridge ..." and TelephonyAnchorClient's lines.

Evidence (--out): run.log, manifest.json, calls.json, syslog.log, status.jsonl
(tools/soak/status_logger.sh), pcap/*.pcap (pulled after every call: the ring
holds 16 messages), SHA256SUMS and a .tar.gz. Every text line goes through
rig_policy.redact plus this run's literal secrets (the far end, the PIN, the
session cookie and CSRF token, the tenant host and client id) before it reaches
disk or the terminal. The pcap is masked byte for byte at the same length, so
it stays a valid capture. Every file is then scanned; a hit withholds that file,
and a PASS becomes INVALID. The pcap still holds LAN addresses: never post it.

Exit status (run_soak.py's): 0 PASS, 1 FAIL, 2 refused before anything ran,
3 INVALID, 4 ABORTED (signal). stdlib only.
"""
import argparse
import collections
import datetime
import hashlib
import inspect
import json
import os
import re
import signal
import socket
import stat
import struct
import sys
import tarfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.normpath(os.path.join(HERE, "..", ".."))
for _p in (HERE, os.path.join(REPO, "tools", "soak")):
    if _p not in sys.path:
        sys.path.insert(0, _p)
import load_profile as lp  # noqa: E402
import rig_policy  # noqa: E402
import run_soak  # noqa: E402
import sip_agent  # noqa: E402

EXIT = run_soak.EXIT
REFUSED = run_soak.REFUSED
APPROVALS = (
    # desmo, 2026-10-03: the harness, new scenario names, 20-30 calls a run, .195 and .244.
    "https://github.com/GlomarGadaffi/pocket-dial/issues/384#issuecomment-5966736679",
    # desmo, 2026-09-27: rows X1-X7 to the designated far end only.
    "https://github.com/GlomarGadaffi/pocket-dial/discussions/451#discussioncomment-18621141",
)
EXTRA_APPROVALS = ()          # a later recorded approval is added here by a reviewed PR
RIG_HOSTS = ("192.168.12.195", "192.168.12.244")
TEST_UAS = ("6101", "6102", "6103", "6104")
PIN_UA = "6104"
OWNER_EXTS = ("1001", "1002", "1003", "113")
NEVER_EXACT = ("911", "933", "112", "113", "999")
OTHER_PBX_NUMBERS = ("440",) + tuple(str(n) for n in range(700, 710))
MAX_CALLS = 30                # the #384 approval: 20-30 anchored calls a run
MAX_CALL_S = 30               # each call <= ~30 s (d451 18621141)
BEEP_USER = "pbx"             # RegisterBeeper's From user (ServiceExtensions.hpp kServicePbx)
FAR_END_FILE_ENV = "PD_ANCHOR_FAR_END_FILE"
FAR_END_ENV = "PD_ANCHOR_FAR_END"
PIN_ENV = "PD_BOARD_ADMIN_PIN"
USER_ENV = "PD_BOARD_ADMIN_USER"
SECRET_ENVS = (PIN_ENV, "PD_ANCHOR_TENANT", "PD_ANCHOR_CLIENT_ID", "PD_ANCHOR_CLIENT_SECRET",
               "PD_OTA_USER", "PD_OTA_PASS")
LOGGER = os.path.join(REPO, "tools", "soak", "status_logger.sh")
# What the scenarios' timing rests on. The agent's own transaction bounds come from sip_agent, so a
# change there re-opens the per-call arithmetic below.
_AGENT_DEFAULTS = inspect.signature(sip_agent.Agent.__init__).parameters
AGENT_TXN_TIMEOUT_S = float(_AGENT_DEFAULTS["timeout"].default)            # a CANCEL or a BYE transaction
AGENT_INVITE_TIMEOUT_S = float(_AGENT_DEFAULTS["invite_timeout"].default)  # the INVITE transaction
CANCEL_FINAL_S = 2.0          # the PBX answers a CANCEL's INVITE with its 487 within this
# 3CX's makecall response took 1.8-3.2 s on a real tenant (#379, Stray's correction comment). A
# CANCEL 0.6-1.4 s after the INVITE therefore always lands before the 3CX leg exists.
MAKECALL_OBSERVED_MIN_S = 1.8
MAKECALL_OBSERVED_MAX_S = 3.2
MAX_NO_REF = 2                # calls in a row with no ringing reference before x4 stops ringing the far end
LOOPBACK_CAVEAT = ("this is a firmware finding only if the far end cannot route back to this board's route DN; "
                   "the harness refuses a far end equal to the route DN or to a DID row but cannot see the "
                   "tenant's own numbers, so confirm the far end before posting it")
RING_REQUIRED = ("RING-REQUIRED: the far end is not confirmed automated (#384 approval, 2026-10-03), "
                 "so a run against real 3CX needs desmo's OK for that run")

# Board log lines (syslog). Each pattern names the firmware line it counts.
LOG_COUNTERS = {
    # TelephonyAnchorClient.cpp startRxIfNeeded(): the two-rx-tasks window was entered (#370 a).
    "rx554_window": r"startRxIfNeeded: rx task for (\S+) (?:still exiting -- not restarting yet"
                    r"|had exited -- restarting) \(#554\)",
    "rx554_restart": r"startRxIfNeeded: rx task for (\S+) had exited -- restarting \(#554\)",
    "rx554_dropped_leg": r"startRxIfNeeded: (\S+) was dropped -- not re-priming \(#554\)",
    "rx_started": r"Rx stream task started for participant (\S+)",
    "initiated": r"Successfully initiated call to \S+ \(own leg (\S+)\)",
    # The upsert worker's status line for one of OUR outbound legs that is not yet fully up: 3CX's
    # participant list shows it (group 1 = the control leg) in a state that is not Connected. A
    # non-empty status is the firmware's own "ringing, not a #100 wedge" (#667); '' is "no evidence".
    "leg_listed": r"Upset \S+ -> control leg (\S+) status '(?!Connected')[^']+'",
    # The same worker's inbound branch: the leg was announced as an inbound call on the route DN.
    "inbound_call": r"Inbound call on DN .*?: participant (\S+) caller",
    "dropped": r"Successfully dropped participant (\S+)",
    "drop_failed": r"dropCall request failed for participant (\S+)",
    "drop_reconciled": r"dropCall: reconciled live participant (\S+)",
    # #681's attribution lines around refuseRingingAnchor(), which logs nothing itself.
    "makecall_failed": r"Failed to initiate outbound call to",
    "anchor_not_connected": r"Cannot make call: anchor not running/connected",
    "post_open_failed": r"httpPostBody: open failed",
    "makecall_status": r"makeCall request failed \(status=(-?\d+)\)",
    "worker_spawn_failed": r"asyncMakeCall: outbound worker xTaskCreate FAILED",
    "anchor_refused": r"anchor\(\S+\): (?:every anchor bridge slot busy|session pool full"
                      r"|virtual-peer pool exhausted)",
    "panic": r"Guru Meditation|CORRUPT HEAP|abort\(\) was called",
    # The bench probe (BenchProbe.cpp): one line per firing, and the rule-5 stops.
    "bench_fired": r"BENCHFAULT (\S+) fired",
    "bench_makecall_read_fail": r"BENCHFAULT makecall_read_fail fired",
    "bench_emergency": r"BENCHFAULT (?:every fault disarmed: emergency call|ballast released \(emergency\))",
    # makeCall() (#349): the unread response reconciled to our own leg, or not.
    "adopted_349": r"but 3CX has our leg (\S+) .*adopting the call instead of failing it \(#349\)",
    "orphaned_349": r"a call may be ORPHANED on 3CX \(#349/#328\)",
    # #903: each adopt re-read that found no leg yet, with what the list held (group 1 = the read).
    "adopt_reread_349": r"makeCall: no leg listed yet \(list status=-?\d+, read (\d+):",
    # runRxLoop()'s GET stream (#379, #518). A spent budget is attempt N/N.
    "get_refused": r"GET stream refused \(HTTP (\d+)\) for ",
    "get_refused_403": r"GET stream refused \(HTTP 403\) for \S*/participants/([^/\s]+)/stream",
    "get_budget_spent": r"GET stream (?:not ready \(HTTP -?\d+\)|transport failure \(no HTTP response, "
                        r"status=-?\d+\)|open failed \([^)]*\)), attempt (\d+)/\1(?!\d)",
    "get_transport_giveup": r"GET stream: \d+ consecutive transport failures",
    "get_rebuild_giveup": r"GET stream: could not rebuild client after transport failure",
    "get_never_opened": r"GET \(Telephony->device\) stream never opened",
    # #893: the far end's audio reached us (runRxLoop). With no ringing reference: a diversion.
    "get_open": r"GET \(Telephony->device\) audio stream OPEN: \S*/participants/([^/\s]+)/stream",
    "first_chunk": r"GET read: first chunk \d+ bytes <- Telephony \((\S+)\)",
    "post_open": r"POST \(device->Telephony\) audio stream OPEN: \S*/participants/([^/\s]+)/stream",
    # #533/#603's esp_log witnesses: every session teardown names its reason; a bridge stop.
    "endcall": r"endCall (\S+) reason=",
    "degraded_endcall": r"endCall (\S+) reason=anchor audio write failure",
    "stop_bridge": r"stopBridge call=(\S*) part=",
    # queueLog() lines: stdout only, so seen only if a console capture is merged in.
    "rh_never_opened_drop": r"no rx audio, dropping leg (\S+)",
    "rh_degraded": r"anchor call torn down: audio write repeatedly failed",
}
_RX = {k: re.compile(v) for k, v in LOG_COUNTERS.items()}
_ATTEMPT = re.compile(r"GET stream (?:not ready \(HTTP -?\d+\)|transport failure \(no HTTP response, "
                      r"status=-?\d+\)|open failed \([^)]*\)), attempt (\d+)/(\d+)")
_ENDCALL = re.compile(r"endCall (\S+) reason=(.*?)\s*$")


class Refused(Exception):
    pass


# ---------------------------------------------------------------- redaction
class Redactor:
    """rig_policy.redact plus this run's literal secrets. A literal is matched
    only where it is not part of a longer token, so a short far end does not
    mask every timestamp; the scan uses the same matcher."""

    TENANT = re.compile(r"\b[A-Za-z0-9-]+\.3cx\.[A-Za-z.]+")

    def __init__(self):
        self._lock = threading.Lock()
        self._rx = []

    def add(self, value):
        value = (value or "").strip()
        if len(value) < 3:
            return
        forms = {value}
        digits = value.lstrip("+")
        if digits.isdigit():
            forms.add(digits)
            if len(digits) >= 11:
                forms.add(digits[-10:])
        with self._lock:
            for f in forms:
                if f.isdigit():
                    rx = re.compile(r"(?<![0-9])%s(?![0-9])" % re.escape(f))
                else:
                    rx = re.compile(r"(?<![A-Za-z0-9])%s(?![A-Za-z0-9])" % re.escape(f))
                if all(r.pattern != rx.pattern for r in self._rx):
                    self._rx.append(rx)
            self._rx.sort(key=lambda r: len(r.pattern), reverse=True)

    def _literals(self):
        with self._lock:
            return list(self._rx)

    def text(self, s):
        for rx in self._literals():
            s = rx.sub("***", s)
        return rig_policy.redact(self.TENANT.sub("***", s))

    def same_length(self, data):
        """bytes -> bytes of the same length, every secret replaced by '*'."""
        s = data.decode("latin-1")

        def mask(m, sub=None):
            body = m.group(0)
            new = sub(m) if sub else ""
            return new + "*" * (len(body) - len(new)) if len(new) <= len(body) else "*" * len(body)
        for rx in self._literals() + [self.TENANT]:
            s = rx.sub(mask, s)
        for _, rx, sub in rig_policy.SECRET_PATTERNS:
            s = rx.sub(lambda m, sub=sub: mask(m, sub), s)
        return s.encode("latin-1")

    def hits(self, s):
        """[(line, kind)]: a literal, a tenant host, or a rig_policy secret pattern."""
        s = re.sub(r"\*{3,}", "***", s)
        found = [(n, kind) for n, kind in rig_policy.find_secrets(s)]
        lits = self._literals() + [self.TENANT]
        for n, line in enumerate(s.splitlines(), 1):
            if any(rx.search(line) for rx in lits):
                found.append((n, "a literal secret of this run"))
        return found


# ---------------------------------------------------------------- refusals (offline)
def owner_set(arg, env):
    extra = lp.parse_owner(arg, env) or set()
    return set(OWNER_EXTS) | extra


def is_never_dial(far):
    """911/933 anywhere in it, or 112, 113, 999 (with one trunk-access digit, EmergencyCall.hpp)."""
    d = (far or "").lstrip("+")
    bare = d[1:] if len(d) == 4 and d[0] == "9" else d
    return any(e in d for e in lp.EMERGENCY_SUBSTRINGS) or d in NEVER_EXACT or bare in NEVER_EXACT \
        or d in lp.EMERGENCY_EXACT


def far_end_problems(far, owner):
    """Every reason `far` may not be dialled, or []. Never echoes the number."""
    if not re.fullmatch(r"\+?[0-9]{3,15}", far or ""):
        return ["the far end is not 3-15 digits with an optional leading +: a URI or a name "
                "could route anywhere"]
    problems = []
    d = far.lstrip("+")
    if is_never_dial(far):
        problems.append("the far end is an emergency or never-dial number (911/933 anywhere in it, "
                        "112, 113, 999): refused")
    if d in owner:
        problems.append("the far end is an owner extension: refused")
    if d in TEST_UAS or d in lp.SERVICE or d in OTHER_PBX_NUMBERS:
        problems.append("the far end is a number this PBX owns (a test UA, a service number, an "
                        "orbit or a page zone): it would never reach the anchor")
    return problems


_NUMERIC = re.compile(r"\+?[0-9 ()./-]+")


def same_number(a, b):
    """True if a and b are one number as a route would see it: equal digits or, when both are
    full national numbers (10+ digits), the same last ten, so +1 555 010 4242 and 5550104242
    match (DidMapping::sameDid's E.164 equivalence). A name such as the route DN "rcv2" matches
    only itself, never by the digit in it."""
    a, b = str(a if a is not None else "").strip(), str(b if b is not None else "").strip()
    if not a or not b:
        return False
    if not (_NUMERIC.fullmatch(a) and _NUMERIC.fullmatch(b)):
        return a == b
    da, db = re.sub(r"[^0-9]", "", a), re.sub(r"[^0-9]", "", b)
    return da[-10:] == db[-10:]     # equal digits; or two long numbers that share their last ten


def far_end_loopback_problems(far, route_dn, rows):
    """Why `far` may route straight back into this board's own route point, or []. A call to such
    a far end arrives on the route DN as an inbound call and is offered to the DID row. The board
    exposes the route DN (/api/telephony-config) and its DID rows (/api/did-mapping), not the
    tenant's own inbound numbers, so only those can be checked; never echoes a number."""
    problems = []
    if same_number(far, route_dn):
        problems.append("the far end is this anchor slot's route DN: a call to it arrives back on the route "
                        "point as an inbound call")
    rows = [r for r in rows or [] if isinstance(r, dict)]
    if any(same_number(far, r.get("did")) for r in rows):
        problems.append("the far end is the number of a DID row (/api/did-mapping): a call to it routes back "
                        "into this board as an inbound call")
    if any(same_number(far, r.get("extension")) for r in rows):
        problems.append("the far end is the extension a DID row maps to: it never reaches the anchor")
    return problems


def cdr_callee_problems(rows, far_ends):
    """A CDR guard (#893, #901): every row's callee must be one of the far ends (same_number, so
    either of two lines matches). Never echoes a number: rows are named by their position."""
    return ["CDR row %d: the callee is not the far end (%s)" % (n, "missing" if not r.get("callee") else
                                                                 "another number or a participant id")
            for n, r in enumerate(rows or [], 1) if isinstance(r, dict)
            and not any(same_number(r.get("callee"), end) for end in far_ends)]


def load_far_end(env, stat_fn=os.stat, posix=None):
    """-> (the first far end, where it came from). Raises Refused, never echoing the value."""
    ends, src = load_far_ends(env, stat_fn, posix)
    return ends[0], src


def load_far_ends(env, stat_fn=os.stat, posix=None):
    """-> (one or two far ends, where they came from). The file may hold two lines (#893: two lines
    on one phone; x4 alternates them per call). Raises Refused, never echoing a value."""
    posix = (os.name == "posix") if posix is None else posix
    path, value = env.get(FAR_END_FILE_ENV), env.get(FAR_END_ENV)
    if path and value:
        raise Refused("both %s and %s are set: set exactly one" % (FAR_END_FILE_ENV, FAR_END_ENV))
    if path:
        try:
            st = stat_fn(path)
        except OSError as e:
            raise Refused("%s cannot be read (%s)" % (FAR_END_FILE_ENV, e.strerror))
        uid = getattr(os, "getuid", lambda: st.st_uid)()
        if posix and (stat.S_IMODE(st.st_mode) & 0o077 or st.st_uid != uid):
            raise Refused("%s must be a file of this user with mode 0600 (it is %o)"
                          % (FAR_END_FILE_ENV, stat.S_IMODE(st.st_mode)))
        try:
            with open(path, encoding="utf-8") as f:
                lines = [ln.strip() for ln in f if ln.strip() and not ln.strip().startswith("#")]
        except OSError as e:
            raise Refused("%s cannot be read (%s)" % (FAR_END_FILE_ENV, e.strerror))
        if len(lines) not in (1, 2):
            raise Refused("%s must hold one number, or two on separate lines" % FAR_END_FILE_ENV)
        if len(lines) == 2 and same_number(lines[0], lines[1]):
            raise Refused("%s holds the same number twice" % FAR_END_FILE_ENV)
        return tuple(lines), "file"
    if value:
        return (value.strip(),), "env"
    raise Refused("no far end: set %s (a 0600 file) or %s; it never goes on the command line"
                  % (FAR_END_FILE_ENV, FAR_END_ENV))


_FAR_FLAG = re.compile(r"^--?(?:far[-_]?end|far|target|dial|number|callee|to)(?:=|$)", re.I)
_NUMERIC_FLAGS = ("--port", "--http-port", "--syslog-port", "--pin-check-s", "--owner-ext")


def argv_problems(argv, redactor):
    """Refuse a far end or a secret on the command line, without echoing it (argparse would)."""
    problems = []
    for i, a in enumerate(argv):
        if _FAR_FLAG.match(a):
            problems.append("argument %d is a far-end flag: the far end never goes on an argv "
                            "(use %s or %s)" % (i + 1, FAR_END_FILE_ENV, FAR_END_ENV))
            continue
        if redactor.hits(a):
            problems.append("argument %d holds a secret: it never goes on an argv" % (i + 1))
            continue
        flag, eq, value = a.partition("=") if a.startswith("--") else ("", "", a)
        numeric_ok = (i > 0 and argv[i - 1] in _NUMERIC_FLAGS) or (eq and flag in _NUMERIC_FLAGS)
        if re.fullmatch(r"\+?[0-9]{3,}", value) and not numeric_ok:
            problems.append("argument %d is number-shaped: the far end never goes on an argv "
                            "(the value is not echoed)" % (i + 1))
    return problems


def approval_problems(url):
    if not url:
        return ["no --approval-url: pass the recorded approval this run relies on (%s)"
                % ", ".join(APPROVALS)]
    if url not in APPROVALS + EXTRA_APPROVALS:
        return ["--approval-url is not a recorded approval (APPROVALS / EXTRA_APPROVALS in "
                "anchor_scenarios.py)"]
    return []


def host_problems(host):
    if host in RIG_HOSTS or host.startswith("127."):
        return []
    return ["--host %s is not an approved rig (%s; loopback only for the fakes)"
            % (host, ", ".join(RIG_HOSTS))]


# ---------------------------------------------------------------- the bench probe's numbers
PROBE_FAULTS = ("makecall_read_fail", "get_status", "get_max_attempts", "post_stream_fail", "token_age")
BENCH_PATH = "/api/bench/fault"
PROBE_IMAGE = "anchor-bench-probe"
GET_MAX_ATTEMPTS = 240               # BenchProbeLogic.hpp kGetMaxAttempts; get_max_attempts only shrinks it
# runRxLoop()'s backoff after each attempt: 50 ms, doubling, capped at 500 ms.
GET_BACKOFF_MS = (50, 100, 200, 400)
GET_BACKOFF_CAP_MS = 500
# Worst case per attempt once the far end has answered: a forced refusal closes the real
# 200 unread (docs/BENCH_PROBE.md), so the next open pays a full TLS handshake, measured
# at 751-1311 ms on .244 (#379, #370's run; X1 logged 1072 ms).
GET_RECONNECT_WORST_S = 1.311
MAKECALL_WORST_S = 1.5               # makeCall()'s POST round trip before the rx task starts
GIVEUP_TO_BYE_S = 3.0                # the drop POST, 3CX's Remove event and the handset BYE
HANGUP_MARGIN_S = 2.0                # the harness's own BYE must also finish inside the cap


def get_giveup_worst_s(n):
    """Seconds from the INVITE to the handset BYE, worst case, with a GET budget of n."""
    sleeps = sum(GET_BACKOFF_MS[:n]) + GET_BACKOFF_CAP_MS * max(0, n - len(GET_BACKOFF_MS))
    return MAKECALL_WORST_S + n * GET_RECONNECT_WORST_S + sleeps / 1000.0 + GIVEUP_TO_BYE_S


def probe_problems(sc):
    n = sc.get("name", "<unnamed>")
    faults = sc.get("faults") or ()
    problems = [] if faults else ["%s: a probe scenario pre-registers the faults it arms" % n]
    for f in faults:
        if f not in PROBE_FAULTS:
            problems.append("%s: %s is not a bench probe fault (%s)" % (n, f, ", ".join(PROBE_FAULTS)))
    if "get_status" in faults and not 400 <= sc.get("get_status", 0) <= 599:
        problems.append("%s: get_status must be 400-599" % n)
    if "get_max_attempts" in faults:
        m = sc.get("get_max_attempts", 0)
        cap = sc.get("call_cap_s", 0) - HANGUP_MARGIN_S
        if not 1 <= m <= GET_MAX_ATTEMPTS:
            problems.append("%s: get_max_attempts must be 1-%d" % (n, GET_MAX_ATTEMPTS))
        elif get_giveup_worst_s(m) > cap:
            problems.append("%s: get_max_attempts=%d reaches the handset BYE after up to %.1f s (worst "
                            "case), past the %.0f s the call cap leaves" % (n, m, get_giveup_worst_s(m), cap))
    if sc.get("hold_s", 0) > sc.get("call_cap_s", 0) - HANGUP_MARGIN_S:
        problems.append("%s: hold_s leaves no room for the hangup inside the call cap" % n)
    return problems


# ---------------------------------------------------------------- scenario registry
SCENARIOS = {}


def sweep_problems(sc):
    ms = sc.get("cancel_ms")
    if isinstance(ms, (tuple, list)) and len(ms) == 2 and 0 <= ms[0] <= ms[1]:
        return []
    return ["%s: cancel_ms must be (low, high) in ms, 0 <= low <= high" % sc.get("name", "<unnamed>")]


def ref_call_worst_s(sc):
    """The longest an x4 call can take: the CANCEL leaves by ref_timeout_s + the sweep's high end,
    its own transaction may take AGENT_TXN_TIMEOUT_S, and so may a BYE after a 2xx that crossed it."""
    return sc["ref_timeout_s"] + sc["cancel_ms"][1] / 1000.0 + 2 * AGENT_TXN_TIMEOUT_S


def ref_timing_problems(sc):
    n = sc.get("name", "<unnamed>")
    problems = sweep_problems(sc)
    if problems:
        return problems
    t, hi = sc["ref_timeout_s"], sc["cancel_ms"][1] / 1000.0
    if t < 2 * MAKECALL_OBSERVED_MAX_S:
        problems.append("%s: ref_timeout_s %g is shorter than twice the slowest makecall response seen on a "
                        "board (%g s): a slow tenant would end calls INVALID" % (n, t, MAKECALL_OBSERVED_MAX_S))
    if t + hi + CANCEL_FINAL_S > AGENT_INVITE_TIMEOUT_S:
        problems.append("%s: the agent gives up on the INVITE after %g s, before a CANCEL due by %.1f s can be "
                        "answered with its 487" % (n, AGENT_INVITE_TIMEOUT_S, t + hi))
    if ref_call_worst_s(sc) > sc.get("call_cap_s", 0):
        problems.append("%s: a call can take up to %.1f s (reference wait %g + sweep %.1f + a CANCEL and a BYE "
                        "transaction of %g s each), past the %d s call cap"
                        % (n, ref_call_worst_s(sc), t, hi, AGENT_TXN_TIMEOUT_S, sc.get("call_cap_s", 0)))
    return problems


def x379_call_worst_s(sc):
    """The longest an x379 call can take: the agent part (the sweep, its CANCEL and a BYE) or the
    wait for the leg, whichever is longer, then the wait for the drop and the settle."""
    return max(sc["cancel_ms"][1] / 1000.0 + 2 * AGENT_TXN_TIMEOUT_S, sc["leg_wait_s"]) \
        + sc["drop_wait_s"] + sc["settle_s"]


def leg_wait_problems(sc):
    n = sc.get("name", "<unnamed>")
    problems = sweep_problems(sc)
    if problems:
        return problems
    hi = sc["cancel_ms"][1] / 1000.0
    if sc["leg_wait_s"] < 2 * MAKECALL_OBSERVED_MAX_S:
        problems.append("%s: leg_wait_s %g is shorter than twice the slowest makecall response seen on a "
                        "board (%g s)" % (n, sc["leg_wait_s"], MAKECALL_OBSERVED_MAX_S))
    if hi >= MAKECALL_OBSERVED_MIN_S:
        problems.append("%s: the CANCEL sweep reaches %.1f s, not before the fastest makecall response seen "
                        "on a board (%g s): the leg could exist first, which is not this race"
                        % (n, hi, MAKECALL_OBSERVED_MIN_S))
    if x379_call_worst_s(sc) > sc.get("call_cap_s", 0):
        problems.append("%s: a call can take up to %.1f s (leg wait, drop wait and settle after the agent's "
                        "own bound), past the %d s call cap" % (n, x379_call_worst_s(sc), sc.get("call_cap_s", 0)))
    return problems


def scenario_problems(sc):
    problems = []
    n = sc.get("name", "<unnamed>")
    if sc.get("path_counter") not in LOG_COUNTERS:
        problems.append("%s pre-registers no path-exercised counter (one of LOG_COUNTERS): "
                        "without one a run could PASS without running its path" % n)
    uas = sc.get("uas") or {}
    for role, ext in sorted(uas.items()):
        if ext not in TEST_UAS:
            problems.append("%s: UA %s (%s) is not a test UA (only %s)" % (n, ext, role, ", ".join(TEST_UAS)))
    if uas.get("detector") != PIN_UA:
        problems.append("%s: the phantom detector must be %s, the S1 pin's target" % (n, PIN_UA))
    if len(set(uas.values())) != len(uas):
        problems.append("%s: one UA in two roles" % n)
    cap = min(MAX_CALLS, sc.get("max_calls", MAX_CALLS))
    if not 1 <= sc.get("calls", 0) <= cap:
        problems.append("%s: calls must be 1-%d (%s)" % (
            n, cap, "the #384 approval" if cap == MAX_CALLS
            else "this scenario's own cap; the #384 approval allows %d" % MAX_CALLS))
    if not 0 < sc.get("call_cap_s", 0) <= MAX_CALL_S:
        problems.append("%s: call_cap_s must be 1-%d (each call <= ~30 s)" % (n, MAX_CALL_S))
    if not callable(sc.get("run")) or not callable(sc.get("judge")):
        problems.append("%s: needs a run and a judge" % n)
    if sc.get("probe"):
        problems += probe_problems(sc)
    if "ref_timeout_s" in sc:
        problems += ref_timing_problems(sc)
    if "leg_wait_s" in sc:
        problems += leg_wait_problems(sc)
    return problems


def scenario(**spec):
    """Register a scenario: @scenario(name=..., uas=..., path_counter=..., judge=fn)."""
    def register(fn):
        sc = dict(spec, run=fn)
        problems = scenario_problems(sc)
        if problems:
            raise ValueError("; ".join(problems))
        SCENARIOS[sc["name"]] = sc
        return fn
    return register


# ---------------------------------------------------------------- log counting
def count_lines(lines):
    """{counter: total} over the board's log lines."""
    out = {k: 0 for k in LOG_COUNTERS}
    for line in lines:
        for k, rx in _RX.items():
            if rx.search(line):
                out[k] += 1
    return out


def per_leg(lines, counter):
    c = collections.Counter()
    for line in lines:
        m = _RX[counter].search(line)
        if m:
            c[m.group(1)] += 1
    return c


def undropped_legs(lines):
    """Legs with an own-leg line and no drop line yet."""
    legs, drops = per_leg(lines, "initiated"), per_leg(lines, "dropped")
    return sorted(leg for leg in legs if not drops[leg])


def drop_problems(lines):
    """Every initiated leg is dropped exactly once; no drop failed (syslog is the only witness, S2)."""
    problems = []
    legs, drops = per_leg(lines, "initiated"), per_leg(lines, "dropped")
    for leg in sorted(set(legs) | set(drops)):
        if legs[leg] and not drops[leg]:
            problems.append("leg %s was initiated but never dropped: a possible orphan "
                            "(syslog is the only witness, S2)" % leg)
        elif drops[leg] > 1:
            problems.append("leg %s was dropped %d times" % (leg, drops[leg]))
    for leg, n in sorted(per_leg(lines, "drop_failed").items()):
        problems.append("the drop of leg %s failed %d time(s)" % (leg, n))
    return problems


def rx_task_problems(lines):
    """A second rx task for one participant, not preceded by a #554 restart: #370's shape."""
    started, restarts = per_leg(lines, "rx_started"), per_leg(lines, "rx554_restart")
    return ["leg %s: %d 'Rx stream task started' lines with %d #554 restart(s): two rx tasks on "
            "one leg (#370)" % (leg, n, restarts[leg])
            for leg, n in sorted(started.items()) if n > 1 + restarts[leg]]


def matches(entries, counter, key=None):
    """[(t, match)] for one counter, optionally only where group 1 == key."""
    rx = _RX[counter]
    out = []
    for t, line in entries:
        m = rx.search(line)
        if m and (key is None or m.group(1) == key):
            out.append((t, m))
    return out


def endcalls(entries, call_id):
    """[(t, reason)] of endCall()'s #603 lines for one Call-ID."""
    out = []
    for t, line in entries:
        m = _ENDCALL.search(line)
        if m and m.group(1) == call_id:
            out.append((t, m.group(2)))
    return out


def started_legs(entries):
    return [m.group(1) for _, m in matches(entries, "initiated")]


# ---------------------------------------------------------------- /api/pcap (second witness)
def pcap_sip(data):
    """[{"ts_us", "src", "dst", "msg"}] from /api/pcap: a classic little-endian pcap,
    LINKTYPE_ETHERNET, one synthesized Ethernet+IPv4+UDP frame per SIP message
    (src/SIP/PcapCapture.hpp). Anything else is skipped, never guessed at."""
    out = []
    if len(data or b"") < 24 or data[:4] != b"\xd4\xc3\xb2\xa1" or struct.unpack_from("<I", data, 20)[0] != 1:
        return out
    off = 24
    while off + 16 <= len(data):
        sec, usec, incl, _ = struct.unpack_from("<IIII", data, off)
        off += 16
        frame, off = data[off:off + incl], off + incl
        if len(frame) < 42 or frame[12:14] != b"\x08\x00" or frame[23] != 17:
            continue
        udp = 14 + (frame[14] & 0x0F) * 4
        if len(frame) < udp + 8:
            continue
        sport, dport = struct.unpack_from("!HH", frame, udp)
        try:
            msg = sip_agent.SipMsg.parse(frame[udp + 8:])
        except Exception:  # noqa: BLE001 -- a truncated slot is skipped
            continue
        out.append({"ts_us": sec * 1000000 + usec, "src": (socket.inet_ntoa(frame[26:30]), sport),
                    "dst": (socket.inet_ntoa(frame[30:34]), dport), "msg": msg})
    return out


def ruri_keeps_contact(ruri, contact):
    """Rule 1 (#797/#798): the Request-URI toward a phone is its registered Contact with
    its URI parameters intact. Looser than RFC 3261 s19.1.4 on purpose: s19.1.4 ignores a
    parameter present in only one URI, and a Snom 370 answers 404/481 without its ;line=."""
    def parts(u):
        m = re.match(r"(?i)^(sips?):(?:([^@;]*)@)?([^;?>]+)((?:;[^?>]*)?)", u or "")
        if not m:
            return None
        host, _, port = m.group(3).partition(":")
        params = {}
        for p in m.group(4).split(";")[1:]:
            if p:
                k, _, v = p.partition("=")
                params[k.lower()] = v
        return m.group(1).lower(), m.group(2) or "", host.lower(), port, params
    r, c = parts(ruri), parts(contact)
    if r is None or c is None or r[:4] != c[:4]:
        return False
    return all(k in r[4] and r[4][k] == v for k, v in c[4].items())


def bye_record(dlg, agent):
    """The BYEs the PBX sent into one dialog, as the UA saw them (first witness)."""
    log = list(dlg.bye_log)
    contact = sip_agent.uri_of(agent.contact)
    return {"pbx_byes": dlg.byes, "bye_tag_mismatches": dlg.bye_mismatches,
            "bye_481": sum(1 for b in list(agent.bye_481) if b["call_id"] == dlg.call_id),
            "bye_answers": [b["status"] for b in log],
            "bye_ruri_keeps_contact": [ruri_keeps_contact(b["ruri"], contact) for b in log],
            "contact_params": contact.partition(";")[2] or None}


def bye_problems(c, who, count=True):
    """FAIL reasons for "exactly one BYE, matching Call-ID and tags, answered 200"."""
    out = []
    if count and c.get("pbx_byes") != 1:
        out.append("%s got %s BYE(s) from the PBX in the dialog, not exactly 1" % (who, c.get("pbx_byes")))
    if c.get("bye_tag_mismatches"):
        out.append("%s got %d BYE(s) with this Call-ID but the wrong tags (answered 481)"
                   % (who, c["bye_tag_mismatches"]))
    if c.get("bye_481"):
        out.append("%s answered %d BYE(s) for this call with 481" % (who, c["bye_481"]))
    return out


def ruri_problems(c, who):
    keeps = c.get("bye_ruri_keeps_contact") or [False]
    if keeps[0]:
        return []
    return ["the BYE's Request-URI is not %s's registered Contact with its parameters (%s): rule 1, #797/#798; "
            "a Snom answers such a BYE 404/481 and stays on the call" % (who, c.get("contact_params"))]


def session_problems(c, ext):
    """(fails, invalid) for "sessionCount is back to its baseline after the call"."""
    s = c.get("sessions") or {}
    if s.get("test_ua_sessions"):
        return ["a session of %s is still up after the call ended: a leg that was never torn down" % ext], []
    if s.get("baseline") is None or s.get("after") is None:
        return [], ["sessionCount could not be read before and after the call"]
    if s["after"] > s["baseline"]:
        return [], ["sessionCount is %d after the call, baseline %d, and no session involves %s: another "
                    "call is up on the rig, so the count cannot be compared" % (s["after"], s["baseline"], ext)]
    return [], []


# ---------------------------------------------------------------- syslog collector
class SyslogListener:
    """A UDP syslog (RFC 5424 / 3164) collector. Each line is kept in memory as
    (monotonic time, message) and appended, redacted, to `path`."""

    HEADER = re.compile(r"^<\d{1,3}>(?:1 \S+ \S+ \S+ \S+ \S+ (?:-|\[.*?\]) ?)?")

    def __init__(self, bind_ip, port, path, redact, max_lines=200000):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((bind_ip, port))
        self.sock.settimeout(0.2)
        self.port = self.sock.getsockname()[1]
        self.path, self.redact, self.max_lines = path, redact, max_lines
        self._lines, self.datagrams, self.overflow = [], 0, 0
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._f = open(path, "a", encoding="utf-8")
        self._thread = threading.Thread(target=self._loop, name="syslog", daemon=True)
        self._thread.start()

    def _loop(self):
        while not self._stop.is_set():
            try:
                data, _ = self.sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            now = time.monotonic()
            text = self.HEADER.sub("", data.decode("utf-8", "replace").strip())
            with self._lock:
                self.datagrams += 1
                for line in text.splitlines() or [""]:
                    if len(self._lines) >= self.max_lines:
                        self.overflow += 1
                        continue
                    self._lines.append((now, line))
                    self._f.write("%.3f %s\n" % (now, self.redact(line)))
                self._f.flush()

    def lines(self, since=None, until=None):
        return [ln for _, ln in self.entries(since, until)]

    def entries(self, since=None, until=None):
        """[(monotonic arrival time, line)]: for ordering lines against the harness's own acts."""
        with self._lock:
            return [(t, ln) for t, ln in self._lines
                    if (since is None or t >= since) and (until is None or t < until)]

    def stop(self):
        self._stop.set()
        self._thread.join(2.0)
        try:
            self.sock.close()
        finally:
            with self._lock:
                self._f.close()


# ---------------------------------------------------------------- the board's HTTP API
class BoardHttp:
    """/api/status unauthenticated; everything else behind one admin session. The
    PIN is read from the environment at login and is never stored or printed."""

    def __init__(self, host, http_port, redactor, env, timeout=5.0):
        self.base = "http://%s" % (host if http_port == 80 else "%s:%d" % (host, http_port))
        self.redactor, self.env, self.timeout = redactor, env, timeout
        self.cookie = self.csrf = None
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def _req(self, method, path, fields=None, auth=False, csrf=False):
        headers = {}
        if auth and self.cookie:
            headers["Cookie"] = "pd_session=" + self.cookie
        if csrf and self.csrf:
            headers["X-CSRF"] = self.csrf
        data = urllib.parse.urlencode(fields).encode("utf-8") if fields is not None else None
        req = urllib.request.Request(self.base + path, data=data, headers=headers, method=method)
        try:
            with self.opener.open(req, timeout=self.timeout) as r:
                return r.status, r.headers, r.read()
        except urllib.error.HTTPError as e:
            try:
                return e.code, e.headers, e.read()
            finally:
                e.close()
        except (OSError, ValueError):
            return None, None, b""

    def login(self):
        st, hdrs, body = self._req("POST", "/api/admin/login",
                                   {"username": self.env.get(USER_ENV) or "admin",
                                    "password": self.env.get(PIN_ENV) or ""})
        if st != 200:
            raise run_soak.Abort("INVALID", "the admin login answered %s" % st)
        m = re.search(r"pd_session=([0-9A-Za-z]+)", "\n".join(hdrs.get_all("Set-Cookie") or []))
        try:
            csrf = json.loads(body.decode("utf-8", "replace")).get("csrf")
        except (ValueError, AttributeError):
            csrf = None
        if not m or not csrf:
            raise run_soak.Abort("INVALID", "the admin login returned no session cookie or CSRF token")
        self.cookie, self.csrf = m.group(1), str(csrf)
        self.redactor.add(self.cookie)
        self.redactor.add(self.csrf)

    def _authed(self, method, path, fields=None, csrf=False):
        if self.cookie is None:
            self.login()
        st, hdrs, body = self._req(method, path, fields, auth=True, csrf=csrf)
        if st == 401:                        # the session expired (30 min TTL): once more
            self.login()
            st, hdrs, body = self._req(method, path, fields, auth=True, csrf=csrf)
        return st, body

    @staticmethod
    def _json(st, body):
        if st != 200:
            return None
        try:
            v = json.loads(body.decode("utf-8", "replace"))
        except ValueError:
            return None
        return v if isinstance(v, dict) else None

    def status(self):
        st, _, body = self._req("GET", "/api/status")
        return self._json(st, body)

    def get_json(self, path):
        return self._json(*self._authed("GET", path))

    def get_bytes(self, path):
        st, body = self._authed("GET", path)
        return body if st == 200 else None

    def post_form(self, path, fields):
        st, body = self._authed("POST", path, fields, csrf=True)
        return self._json(st, body)

    def request_json(self, method, path, fields=None):
        """-> (HTTP status or None, a JSON object or None), whatever the status: the bench
        probe answers 400/409/503 with a reason the caller must tell apart."""
        st, body = self._authed(method, path, fields, csrf=method == "POST")
        try:
            v = json.loads(body.decode("utf-8", "replace")) if body else None
        except ValueError:
            v = None
        return st, v if isinstance(v, dict) else None

    def logout(self):
        if self.cookie:
            self._req("POST", "/api/admin/logout", {}, auth=True, csrf=True)
            self.cookie = self.csrf = None


class BenchProbe:
    """GET/POST /api/bench/fault on the probe image (docs/BENCH_PROBE.md): owner-gated,
    CSRF-checked, form-encoded, one fault per POST. Every failure is an INVALID Abort
    that says why; a 409 (an emergency is live, rule 5) is never retried."""

    def __init__(self, http, tries=3, pause_s=0.2):
        self.http, self.tries, self.pause_s = http, tries, pause_s

    def _call(self, method, fields=None):
        st, body = None, None
        for i in range(self.tries):
            st, body = self.http.request_json(method, BENCH_PATH, fields)
            if st != 503 or i + 1 == self.tries:   # 503: "counters busy", another reader holds them
                break
            time.sleep(self.pause_s)
        return st, body

    @staticmethod
    def _counters(st, body, what):
        if st == 200 and isinstance(body, dict) and body.get("image") == PROBE_IMAGE \
                and isinstance(body.get("faults"), dict):
            return body
        why = {404: "404: the board is not running the probe image (POCKETDIAL_ANCHOR_BENCH_PROBE)",
               403: "403: the probe is owner-gated (or the CSRF token was refused); once an owner "
                    "credential exists, PD_BOARD_ADMIN_USER must name the owner login",
               409: "409: the probe refused (an emergency call is live, rule 5, or a ballast is held)",
               400: "400: the probe refused the request as malformed",
               None: "no answer"}.get(st, "HTTP %s" % st)
        if st == 200:
            why = "200 without the probe's counters (no image %r)" % PROBE_IMAGE
        raise run_soak.Abort("INVALID", "%s: %s" % (what, why))

    def counters(self):
        return self._counters(*self._call("GET"), what="GET %s" % BENCH_PATH)

    def arm(self, name, value=None):
        fields = {"fault": name}
        if value is not None:
            fields["value"] = str(int(value))
        body = self._counters(*self._call("POST", fields), what="arming %s" % name)
        f = body["faults"].get(name)
        if not isinstance(f, dict) or f.get("armed") is not True or \
                (value is not None and f.get("value") != int(value)):
            raise run_soak.Abort("INVALID", "arming %s: the counters do not show it armed%s"
                                 % (name, "" if value is None else " with value %d" % int(value)))
        return body

    def disarm_all(self):
        """POST fault=disarm, POST ballast=release, then GET. -> (counters or None, [problems])."""
        problems = []
        for fields in ({"fault": "disarm"}, {"ballast": "release"}):
            st, _ = self._call("POST", fields)
            if st != 200:
                problems.append("POST %s answered %s" % (urllib.parse.urlencode(fields), st))
        try:
            after = self.counters()
        except run_soak.Abort as e:
            return None, problems + [e.reason]
        armed = sorted(n for n, f in after["faults"].items() if isinstance(f, dict) and f.get("armed"))
        if armed:
            problems.append("still armed: %s" % ", ".join(armed))
        if (after.get("ballast") or {}).get("held"):
            problems.append("a ballast is still held")
        return after, problems


def moh_problems(http):
    """The Held variant of x279 needs a hold clip. Without one an outbound anchor hold falls
    back to the silent a=inactive hold, no writeAudio() runs, and post_stream_fail could
    never fire (docs/FEATURE_ROADMAP.md, music on hold). GET /api/moh (sysop-gated)
    answers {"supported", "loaded", "seconds", ...}."""
    st = http.get_json("/api/moh")
    if st is None:
        return ["GET /api/moh failed"]
    if st.get("supported") is not True:
        return ["this build has no SD card, so it can hold no clip (/api/moh supported=false)"]
    if st.get("loaded") is not True:
        return ["no hold clip is loaded (/api/moh loaded=false): a held anchor call is silent and "
                "never writes audio"]
    return []


# ---------------------------------------------------------------- the run
class AnchorRun:
    def __init__(self, args, sc, far_end, redactor, http, agent_factory, start_logger, out):
        self.a, self.sc, self.red = args, sc, redactor
        self.far_ends = tuple(far_end) if isinstance(far_end, (list, tuple)) else (far_end,)
        self.far_end = self.far_ends[0]
        self.http, self.agent_factory, self.start_logger, self.out = http, agent_factory, start_logger, out
        self.stop = threading.Event()
        self.ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        self.dir = os.path.join(os.path.abspath(args.out), "anchor-%s-%s" % (sc["name"], self.ts))
        self.agents = {}
        self.calls, self.fails, self.invalid, self.log_lines = [], [], [], []
        self.syslog = self.logger = self.watch = None
        self.route_dn = None
        self.did_rows = None             # the last /api/did-mapping read, for the far-end check
        self.syslog_restore = None
        self.baseline = {}
        self.last_reg = 0.0
        self.aborted = False
        self.rtp_pump = None
        self.pcap_reqs = {}              # every SIP request /api/pcap showed, deduplicated
        self.probe = self.probe_before = self.probe_after = None
        self.probe_clean = False
        self.probe_end_problems = []
        self.manifest = {"scenario": sc["name"], "issues": list(sc.get("issues", ())),
                         "about": sc.get("about"), "host": args.host, "approval": args.approval_url,
                         "checkout": {"url": args.checkout_url, "expiry": args.checkout_expiry},
                         "far_end": "set (%s); never recorded" % args.far_end_source,
                         "ring_required": RING_REQUIRED if sc.get("ring_required") else None,
                         "path_counter": {"name": sc["path_counter"],
                                          "regex": LOG_COUNTERS[sc["path_counter"]]},
                         "params": {k: v for k, v in sc.items() if k not in ("run", "judge")},
                         "notes": []}

    # -- output / helpers ----------------------------------------------------
    def say(self, text):
        line = "[%s] %s" % (datetime.datetime.now(datetime.timezone.utc).strftime("%H:%M:%S"),
                            self.red.text(text))
        self.log_lines.append(line)
        self.out(line)

    def p(self, *names):
        return os.path.join(self.dir, *names)

    def stopped(self):
        return self.stop.is_set()

    def idle(self, seconds):
        """Wait, re-checking the pin and the board every pin_check_s."""
        end = time.monotonic() + seconds
        while True:
            left = end - time.monotonic()
            if left <= 0 or self.stop.wait(min(left, self.a.pin_check_s)):
                break
            self.checkpoint()

    # -- preflight -----------------------------------------------------------
    def preflight(self):
        st = self.http.status()
        if not st or not isinstance(st.get("uptime"), (int, float)):
            raise run_soak.Abort("INVALID", "preflight: no /api/status answer")
        cd = st.get("coredump") if isinstance(st.get("coredump"), dict) else {}
        problems = []
        if cd.get("supported") is not True:
            problems.append("the board reports no coredump partition (a panic would leave no dump)")
        if cd.get("present") is True:
            problems.append("a coredump is already present: read and erase it first")
        if st.get("resetReason") not in run_soak.BENIGN_RESETS:
            problems.append("resetReason %r is not benign" % st.get("resetReason"))
        if self.a.expect_version and st.get("version") != self.a.expect_version:
            problems.append("the board runs %r, not --expect-version %r" % (st.get("version"),
                                                                            self.a.expect_version))
        self.baseline = {"version": st.get("version"), "uptime": st.get("uptime"),
                         "resetReason": st.get("resetReason"), "coredump": cd}
        self.manifest["version_at_start"] = st.get("version")
        tel = self.http.get_json("/api/telephony-config") or {}
        active = [s for s in tel.get("slots") or [] if isinstance(s, dict) and s.get("active")]
        for s in active:
            self.red.add(urllib.parse.urlparse(s.get("baseUrl") or "").hostname)
            self.red.add(s.get("clientId"))
        if len(active) != 1 or not active[0].get("routeDn"):
            problems.append("no single active anchor slot with a route DN (/api/telephony-config)")
        else:
            self.route_dn = str(active[0]["routeDn"])
            if len(re.sub(r"[^0-9]", "", self.route_dn)) >= 7:
                self.red.add(self.route_dn)  # a DID-shaped route DN is never posted
            if self.read_did_rows() is None:
                problems.append("GET /api/did-mapping failed: the far end cannot be checked against the DID rows")
            else:
                problems += self.far_end_loopback()
        if problems:
            raise run_soak.Abort("INVALID", "preflight: " + "; ".join(problems))

    def setup_syslog(self):
        cur = self.http.get_json("/api/syslog")
        if cur is None:
            raise run_soak.Abort("INVALID", "preflight: GET /api/syslog failed")
        want = (self.a.local_ip, self.syslog.port)
        here = cur.get("enabled") is True and (cur.get("host"), cur.get("port")) == want
        self.manifest["syslog_before"] = cur
        if here:
            return
        if not self.a.set_syslog:
            raise run_soak.Abort("INVALID", "the board does not send syslog to %s:%d (pass --set-syslog "
                                 "to point it here for the run; it is restored after)" % want)
        self.syslog_restore = {"host": cur.get("host") if cur.get("enabled") else "",
                               "port": str(cur.get("port") or 514)}
        if self.http.post_form("/api/syslog", {"host": want[0], "port": str(want[1])}) is None:
            raise run_soak.Abort("INVALID", "POST /api/syslog was refused")
        self.say("the board now logs to %s:%d (restored after the run)" % want)

    def read_did_rows(self):
        """GET /api/did-mapping -> its rows (kept for the far-end check), or None."""
        rows = (self.http.get_json("/api/did-mapping") or {}).get("mappings")
        self.did_rows = rows if isinstance(rows, list) else None
        return self.did_rows

    def far_end_loopback(self):
        """Why the far end may route back into this board, from the route DN and the last DID rows read."""
        return [p for far in self.far_ends for p in far_end_loopback_problems(far, self.route_dn, self.did_rows)]

    def pin_problem(self):
        """Why the S1 pin does not hold right now, or None."""
        rows = self.read_did_rows()
        if rows is None:
            return "GET /api/did-mapping failed"
        # DidMapping::sameDid(): exact first, then E.164 equivalence for a numeric DN.
        numeric = re.fullmatch(r"\+?[0-9 ()-]+", self.route_dn) is not None
        dn_digits = re.sub(r"[^0-9]", "", self.route_dn) if numeric else ""
        same = [r for r in rows if isinstance(r, dict) and (
            r.get("did") == self.route_dn or (dn_digits and re.sub(r"[^0-9]", "", str(r.get("did"))) == dn_digits))]
        if not any(r.get("did") == self.route_dn for r in same) or any(r.get("extension") != PIN_UA for r in same):
            return "no DID row maps the route DN to %s alone" % PIN_UA
        st = self.http.get_json("/api/status") or {}
        if st.get("rosterVisible") is not True:
            return "the roster is not visible (the admin session was not accepted)"
        det = self.agents["detector"]
        mine = "%s:%d" % (det.lip, det.lport)
        clients = [c for c in st.get("clients") or [] if isinstance(c, dict)]
        if not any(c.get("number") == PIN_UA and c.get("address") == mine for c in clients):
            return "%s is not registered at this run's address %s" % (PIN_UA, mine)
        for end in self.far_ends:
            if any(str(c.get("number")) in (end, end.lstrip("+")) for c in clients):
                return "the far end is registered on this board: it would ring a local phone"
        return None

    def register_all(self, expires):
        for role, ua in self.agents.items():
            status = ua.register(expires)
            if expires and (status != 200 or not ua.registered):
                return "%s %s could not register (%s)" % (role, ua.ext, status)
        self.last_reg = time.monotonic()
        return None

    def checkpoint(self):
        """The S1 pin and the board, between calls and while idle."""
        if time.monotonic() - self.last_reg >= self.a.register_refresh_s:
            why = self.register_all(self.a.register_expires)
            if why:
                raise run_soak.Abort("INVALID", "the S1 pin lapsed: " + why)
        why = self.pin_problem()
        if why:
            raise run_soak.Abort("INVALID", "the S1 pin lapsed: " + why)
        loop = self.far_end_loopback()           # the DID rows pin_problem just read
        if loop:
            raise run_soak.Abort("INVALID", "the far end now routes back into this board: " + "; ".join(loop))
        if self.phantoms():
            raise run_soak.Abort("FAIL", "a phantom inbound reached a test UA: no more calls")
        self.watch_board()

    def phantoms(self):
        """Every INVITE a test UA refused that was not the register beep."""
        return [(role, ua.ext, r["from_user"]) for role, ua in sorted(self.agents.items())
                for r in list(ua.rejected) if r["from_user"] != BEEP_USER]

    def watch_call(self, until, stop_when=None, step=0.05):
        """Wait until `until` (monotonic) or stop_when(). A phantom inbound stops the run at
        once (FAIL, so the call is hung up in teardown); the S1 pin and the board are
        re-checked every pin_check_s. -> True if stop_when() came true."""
        next_check = time.monotonic() + self.a.pin_check_s
        while True:
            if stop_when is not None and stop_when():
                return True
            if self.phantoms():
                raise run_soak.Abort("FAIL", "a phantom inbound reached a test UA during the call: the run stops")
            now = time.monotonic()
            if now >= until or self.stop.wait(min(step, until - now)):
                return stop_when is not None and stop_when()
            if time.monotonic() >= next_check:
                self.checkpoint()
                next_check = time.monotonic() + self.a.pin_check_s

    def wait_line(self, counter, since, timeout, key=None):
        """The first (t, match) of a syslog counter after `since`, watching for phantoms meanwhile."""
        found = []

        def seen():
            found[:] = matches(self.syslog.entries(since), counter, key)[:1]
            return bool(found)
        self.watch_call(time.monotonic() + timeout, stop_when=seen)
        return found[0] if found else (None, None)

    def session_count(self):
        n = (self.http.status() or {}).get("sessionCount")
        return n if isinstance(n, int) else None

    def sessions_settle(self, baseline, ext, wait_s):
        """sessionCount once it is back at `baseline` (or wait_s passed), and how many
        sessions in the authenticated list still involve `ext`. Counts only: the list
        also names the far end."""
        deadline = time.monotonic() + wait_s
        while True:
            after = self.session_count()
            if (baseline is not None and after is not None and after <= baseline) \
                    or time.monotonic() >= deadline or self.stop.wait(0.2):
                break
        st = self.http.get_json("/api/status") or {}
        mine = [s for s in st.get("sessions") or [] if isinstance(s, dict)
                and ext in (str(s.get("caller")), str(s.get("callee")))]
        return {"baseline": baseline, "after": after, "test_ua_sessions": len(mine)}

    # -- the bench probe -------------------------------------------------------
    def probe_preflight(self):
        """Before any SIP: the probe image answers, no emergency is live, nothing is armed."""
        probe = BenchProbe(self.http)
        before = probe.counters()        # a 404/403 ends the run here: nothing armed, nothing to disarm
        self.probe, self.probe_before = probe, before
        self.manifest["probe"] = {"before": before, "faults": list(self.sc["faults"])}
        problems = []
        if before.get("emergencyLive") is not False:
            problems.append("the probe reports an emergency call live (rule 5): nothing is armed")
        stale = sorted(n for n, f in before["faults"].items() if isinstance(f, dict) and f.get("armed"))
        if stale:
            problems.append("%s already armed before this run (an earlier run's leftover?): this run "
                            "arms nothing and disarms it at the end" % ", ".join(stale))
        if (before.get("ballast") or {}).get("held"):
            problems.append("a ballast is already held: this run releases it at the end")
        missing = [f for f in self.sc["faults"] if f not in before["faults"]]
        if missing:
            problems.append("the probe image has no %s fault" % ", ".join(missing))
        if problems:
            raise run_soak.Abort("INVALID", "probe preflight: " + "; ".join(problems))
        self.say("probe image answers: nothing armed, no ballast, no emergency live")

    def arm(self, name, value=None):
        """Arm one pre-registered fault. Never for an emergency or never-dial far end (the
        probe would refuse to fire anyway, rule 5)."""
        if name not in self.sc.get("faults", ()):
            raise run_soak.Abort("INVALID", "%s arms %s, which it did not pre-register" % (self.sc["name"], name))
        if any(is_never_dial(end) for end in self.far_ends):
            raise run_soak.Abort("INVALID", "refusing to arm %s: the far end is an emergency or never-dial "
                                 "number (rule 5)" % name)
        self.probe.arm(name, value)
        self.manifest["probe"].setdefault("armed", []).append({"fault": name, "value": value})
        self.say("armed %s%s" % (name, "" if value is None else "=%d" % value))

    def probe_finish(self):
        """Disarm every fault and release the ballast, then read the counters back. Runs in
        the scenario's finally and again at the top of teardown until it verifies clean."""
        if self.probe is None or self.probe_clean:
            return
        after, problems = self.probe.disarm_all()
        if after is not None:
            self.probe_after = after
            self.manifest.setdefault("probe", {})["after"] = after
        self.probe_end_problems, self.probe_clean = problems, not problems
        self.say("probe: every fault disarmed and the ballast released (read back)" if not problems else
                 "probe NOT verified clean (%s): disarm it by hand, POST %s fault=disarm and ballast=release"
                 % ("; ".join(problems), BENCH_PATH))

    def probe_verdict(self):
        """INVALID reasons from the probe: not clean at the end, a fault that never fired,
        or an emergency that touched the probe (rule 5 stopped it; the run proves nothing)."""
        out = []
        if not self.probe_clean:
            out.append("the probe was not verified disarmed at the end (%s): disarm it by hand"
                       % "; ".join(self.probe_end_problems or ["never read back"]))
        b, a = self.probe_before, self.probe_after
        if b is None or a is None:
            return out
        fired, skips = {}, 0
        for name in self.sc["faults"]:
            fb, fa = b["faults"].get(name) or {}, a["faults"].get(name) or {}
            fired[name] = fa.get("fired", 0) - fb.get("fired", 0)
            skips += fa.get("emergencySkips", 0) - fb.get("emergencySkips", 0)
        self.manifest["probe"]["fired"] = fired
        lines = self.syslog.lines() if self.syslog else []
        logged = per_leg(lines, "bench_fired")
        self.manifest["probe"]["fired_lines"] = {n: logged[n] for n in self.sc["faults"]}
        stopped = count_lines(lines)["bench_emergency"]
        if self.calls:
            for name, n in sorted(fired.items()):
                if n < 1:
                    out.append("the fault %s fired %d times: its path was not driven (INVALID, never PASS)"
                               % (name, n))
        refused = a.get("refusedArms", 0) - b.get("refusedArms", 0)
        disarms = a.get("emergencyDisarms", 0) - b.get("emergencyDisarms", 0)
        if refused or disarms or skips or stopped or a.get("emergencyLive"):
            out.append("an emergency call touched the probe during the run (refusedArms +%d, emergencyDisarms "
                       "+%d, emergencySkips +%d, %d BENCHFAULT emergency line(s)): rule 5 stopped it, so this "
                       "run proves nothing" % (refused, disarms, skips, stopped))
        return out

    def watch_board(self):
        if self.logger is not None and self.logger.poll() is not None:
            raise run_soak.Abort("INVALID", "the status logger exited during the run")
        ev = self.watch.poll(time.time(), self.logger_started)
        if ev and ev[0] == "stalled":
            raise run_soak.Abort("INVALID", ev[1])
        if ev:
            self.fails.append("board: " + ev[1])
            raise run_soak.Abort("FAIL", ev[1])

    # -- evidence --------------------------------------------------------------
    def pull_pcap(self, name):
        data = self.http.get_bytes("/api/pcap")
        if data is None:
            self.manifest["notes"].append("the /api/pcap pull %s failed" % name)
            return
        for rec in pcap_sip(data):            # parsed before masking; only these fields are kept
            m = rec["msg"]
            if m.is_response:
                continue
            key = (m.method, m.call_id(), m.branch(), rec["dst"])
            self.pcap_reqs.setdefault(key, {"method": m.method, "call_id": m.call_id(), "dst": rec["dst"],
                                            "from_user": sip_agent.user_of(sip_agent.uri_of(m.get("from"))),
                                            "to_tag": sip_agent.tag_of(m.get("to"))})
        with open(self.p("pcap", name + ".pcap"), "wb") as f:
            f.write(self.red.same_length(data))

    def pcap_count(self, method, agent, call_id=None, phantom=False):
        """Distinct `method` transactions /api/pcap shows the board sending to `agent`."""
        dst = (agent.lip, agent.lport)
        return sum(1 for r in self.pcap_reqs.values()
                   if r["method"] == method and r["dst"] == dst
                   and (call_id is None or r["call_id"] == call_id)
                   and (not phantom or (r["from_user"] != BEEP_USER and not r["to_tag"])))

    def coredump_problems(self, end_status):
        problems, base = [], self.baseline.get("coredump") or {}
        samples = []
        try:
            with open(self.p("status.jsonl"), encoding="utf-8", errors="replace") as f:
                for line in f:
                    try:
                        s = json.loads(line).get("s")
                    except (ValueError, AttributeError):
                        continue
                    if isinstance(s, dict):
                        samples.append(s)
        except OSError:
            pass
        if end_status:
            samples.append(end_status)
        for s in samples:
            cd = s.get("coredump") if isinstance(s.get("coredump"), dict) else {}
            if cd.get("present") is True or (cd.get("size") not in (None, base.get("size"))):
                problems.append("the coredump changed during the run (present %s, size %s): a panic"
                                % (cd.get("present"), cd.get("size")))
                break
        return problems

    # -- the whole run -----------------------------------------------------------
    def execute(self):
        os.makedirs(self.p("pcap"), exist_ok=True)
        self.syslog = SyslogListener(self.a.local_ip, self.a.syslog_port, self.p("syslog.log"), self.red.text)
        self.preflight()
        self.setup_syslog()
        if self.sc.get("probe"):
            self.probe_preflight()
        self.logger = self.start_logger([LOGGER, self.http.base[len("http://"):], self.p("status.jsonl")],
                                        self.p("logger.log"))
        self.logger_started = time.time()
        self.watch = run_soak.Watch(self.p("status.jsonl"))
        for role, ext in sorted(self.sc["uas"].items()):
            opts = dict((self.sc.get("agent_opts") or {}).get(role) or {})
            if opts.pop("rtp", False):
                self.rtp_pump = self.rtp_pump or sip_agent.RtpPump()
                opts["rtp_pump"] = self.rtp_pump
            self.agents[role] = self.agent_factory(ext, **opts) if opts else self.agent_factory(ext)
        why = self.register_all(self.a.register_expires)
        if why:
            raise run_soak.Abort("INVALID", "preflight: " + why)
        self.stop.wait(self.a.beep_wait_s)       # the register beep goes out ~0.5 s after a new binding
        deadline = time.monotonic() + self.a.roster_wait_s
        why = self.pin_problem()
        while why and time.monotonic() < deadline and not self.stopped():
            self.stop.wait(1.0)
            why = self.pin_problem()
        if why:
            raise run_soak.Abort("INVALID", "preflight (S1 pin): " + why)
        self.say("S1 pin holds: route DN -> %s, registered at this run's address" % PIN_UA)
        self.manifest["route_dn"] = self.route_dn
        self.sc["run"](self, self.sc)
        if self.stopped():
            raise run_soak.Abort("ABORTED", "interrupted by a signal")
        self.say("tail: %s stays registered %.0f s for late phantoms" % (PIN_UA, self.a.tail_s))
        self.idle(self.a.tail_s)
        self.checkpoint()

    def teardown(self):
        try:
            self.probe_finish()          # the backstop: before any BYE, before the logout
        except Exception as e:  # noqa: BLE001 -- teardown continues; probe_verdict reports it
            self.probe_end_problems = ["the disarm raised %r" % (e,)]
        for ua in self.agents.values():
            for dlg in ua.live_dialogs():
                if dlg.ok and not dlg.ended.is_set():
                    dlg.bye()
                dlg.close()
        for ua in self.agents.values():
            try:
                ua.register(0)
            except Exception:  # noqa: BLE001 -- teardown continues
                pass
        end = None
        try:
            if self.http.cookie:
                self.pull_pcap("end")
            end = self.http.status()
            if self.syslog_restore is not None:
                ok = self.http.post_form("/api/syslog", self.syslog_restore) is not None
                self.say("syslog setting %s" % ("restored" if ok else "NOT restored: fix it by hand"))
            self.http.logout()
        finally:
            if self.logger is not None and self.logger.poll() is None:
                self.logger.terminate()
            if self.syslog is not None:
                self.syslog.stop()
            for ua in self.agents.values():
                ua.close()
            if self.rtp_pump is not None:
                self.rtp_pump.stop()
        return end

    def judge(self, end_status):
        lines = self.syslog.lines() if self.syslog else []
        counts = count_lines(lines)
        self.manifest["log_counters"] = counts
        self.manifest["syslog_lines"] = len(lines)
        fails, invalid = list(self.fails), list(self.invalid)
        for role, ext, who in self.phantoms():
            fails.append("an INVITE from %r reached test UA %s (%s): a phantom inbound (S1); %s"
                         % (who, ext, role, LOOPBACK_CAVEAT))
        fails += self.coredump_problems(end_status)
        if end_status and self.baseline.get("version") and end_status.get("version") != self.baseline["version"]:
            fails.append("the version changed during the run: %r -> %r"
                         % (self.baseline["version"], end_status.get("version")))
        self.manifest["version_at_end"] = (end_status or {}).get("version")
        if self.calls and not lines:
            invalid.append("no syslog line arrived: the board's log never reached this run")
        if self.calls and counts[self.sc["path_counter"]] == 0:
            invalid.append("the pre-registered counter %s is 0: the path was not shown to run "
                           "(INVALID, never PASS; #384 S3)" % self.sc["path_counter"])
        if self.sc.get("probe"):
            invalid += self.probe_verdict()
        if self.calls or not self.aborted:
            more_fails, more_invalid, summary = self.sc["judge"](self, self.sc, lines)
            fails += more_fails
            invalid += more_invalid
            self.manifest["summary"] = summary
        self.manifest["fail_reasons"], self.manifest["invalid_reasons"] = fails, invalid
        return fails, invalid

    def bundle(self, verdict, reason):
        os.makedirs(self.dir, exist_ok=True)
        public = [{k: v for k, v in c.items() if not k.startswith("_")} for c in self.calls]
        with open(self.p("calls.json"), "w", encoding="utf-8") as f:   # "_" keys: Call-IDs (LAN addresses)
            f.write(self.red.text(json.dumps(public, indent=1)))
        withheld = self.scan()
        if withheld and verdict == "PASS":
            verdict, reason = "INVALID", "the secret scan withheld %s" % ", ".join(withheld)
            self.say("INVALID: " + reason)
        self.manifest.update({"verdict": verdict, "exit_code": EXIT[verdict], "reason": reason,
                              "withheld": withheld, "finished_at": time.time(),
                              "tools": {"python": sys.version.split()[0],
                                        "scripts": {n: run_soak.sha256_file(os.path.join(HERE, n))
                                                    for n in ("anchor_scenarios.py", "sip_agent.py")}}})
        for name, text in (("manifest.json", json.dumps(self.manifest, indent=1, sort_keys=True, default=str)),
                           ("run.log", "\n".join(self.log_lines) + "\n")):
            text = self.red.text(text)
            if self.red.hits(text):
                text = "withheld: the secret scan found a hit in this file\n"
            with open(self.p(name), "w", encoding="utf-8") as f:
                f.write(text)
        names = sorted(os.path.relpath(os.path.join(d, n), self.dir).replace(os.sep, "/")
                       for d, _, files in os.walk(self.dir) for n in files if n != "SHA256SUMS")
        with open(self.p("SHA256SUMS"), "w", encoding="utf-8") as f:
            for n in names:
                f.write("%s  %s\n" % (run_soak.sha256_file(self.p(n)), n))
        with tarfile.open(self.dir + ".tar.gz", "w:gz") as t:
            t.add(self.dir, arcname=os.path.basename(self.dir))
        return verdict

    def scan(self):
        """Scan every evidence file; a file with a hit is replaced by a notice."""
        withheld = []
        for d, _, files in os.walk(self.dir):
            for n in files:
                path = os.path.join(d, n)
                with open(path, "rb") as f:
                    hits = self.red.hits(f.read().decode("latin-1"))
                if hits:
                    with open(path, "w", encoding="utf-8") as f:
                        f.write("withheld: the secret scan found %d hit(s) in this file\n" % len(hits))
                    withheld.append(os.path.relpath(path, self.dir).replace(os.sep, "/"))
        return withheld


# ---------------------------------------------------------------- x4_cancel_ringing
def call_record(i, cancel_ms, dlg, t_start):
    t0 = dlg.invite_sent_at

    def ms(t):
        return None if t is None or t0 is None else int(round((t - t0) * 1000))
    final_at = next((t for t, s in dlg.responses if s >= 200), None)
    return {"call": i + 1, "cancel_planned_ms": int(round(cancel_ms)),
            "cancel_sent_ms": ms(dlg.cancel_sent_at), "cancel_status": dlg.cancel_status,
            "cancel_answered_ms": ms(dlg.cancel_answered_at),
            "final": dlg.final_status, "final_ms": ms(final_at),
            "provisional": [[s, ms(t)] for t, s in dlg.responses if s < 200],
            "bye": None, "t_start": t_start}


def x4_classify(c):
    """-> (bucket, problem or None) for one call (RFC 3261 s9.1, #548). A call whose CANCEL went at
    the reference timeout, not after a ringing signal, is counted apart: it keeps any real fault
    (a 503, no final) but is not a CANCEL while ringing."""
    bucket, problem = _x4_bucket(c)
    if c.get("ref_timeout") and bucket == "cancelled":
        # #893: the far end's audio opened with no ringing reference: voicemail or another
        # answering service took the call, so the far leg never rang.
        bucket = "diverted" if c.get("audio_opened") else "no_ringing_ref"
    return bucket, problem


def _x4_bucket(c):
    st = c["final"]
    if st == 487:
        if c["cancel_status"] != 200:
            return "cancelled", "the CANCEL itself was answered %s, not 200" % c["cancel_status"]
        return "cancelled", None
    if st is not None and 200 <= st < 300:
        # s9.1: a 2xx may legally beat the CANCEL; the call is then ACKed and BYEd.
        bye = None if c["bye"] == 200 else "the BYE after its 2xx got %s" % c["bye"]
        if c["cancel_sent_ms"] is None:
            return "answered_before_cancel", bye
        if None not in (c["cancel_answered_ms"], c["final_ms"]) and c["final_ms"] > c["cancel_answered_ms"]:
            return "answered_after_cancel", "a 2xx after the CANCEL was accepted (s9.2)"
        return "crossed_cancel", bye
    rang = any(p[0] == 180 for p in c["provisional"])
    if st is None:
        return "no_final", "no final response to the INVITE after the CANCEL (the #548 shape)"
    return "refused", "final %d instead of 487 (%s 180 before it; #681)" % (st, "a" if rang else "no")


def calls_text(numbers):
    return ("call %s" if len(numbers) == 1 else "calls %s") % ", ".join(str(n) for n in numbers)


def x4_when(run, delay_ms, st):
    """cancel_when for one x4 call: the CANCEL is due delay_ms after the first syslog line that shows
    3CX listing a leg THIS INVITE started (an "own leg" line since the INVITE) as not yet Connected.
    Records what it saw in `st`. A phantom INVITE at a test UA makes the CANCEL due at once, so the
    call is torn down and the next checkpoint stops the run."""
    def when(since):
        if run.phantoms():
            st["phantom"] = True
            return time.monotonic()
        ents = run.syslog.entries(since)
        legs = {}
        for t, m in matches(ents, "initiated"):
            legs.setdefault(m.group(1), t)
        if legs and st.get("leg_t") is None:
            st["leg_t"] = min(legs.values())
            st["own_leg"] = min(legs, key=legs.get)
        for t, m in matches(ents, "leg_listed"):
            if m.group(1) in legs:
                st["ref_t"], st["leg"] = t, m.group(1)
                return t + delay_ms / 1000.0
        return None
    return when


def ref_stage(st, dlg):
    """Why a call that waited out its reference timeout had none."""
    if dlg.cancel_when_error:
        return "the reference function failed: %s" % dlg.cancel_when_error
    if st.get("leg_t") is None:
        return "no own-leg line: the makecall response never came"
    if st.get("audio_opened"):
        return DIVERTED
    return "the leg was never listed as ringing"


DIVERTED = ("diverted: the far end's audio stream opened with no ringing reference (voicemail or another "
            "answering service; a person's phone as the far end does this on repeat calls, #893)")


def audio_opened(run, since, leg):
    """True if the board logged the GET stream opening, or its first chunk, for `leg` since `since`."""
    if leg is None:
        return False
    ents = run.syslog.entries(since)
    return bool(matches(ents, "get_open", leg) or matches(ents, "first_chunk", leg))


def x4_run(run, sc):
    caller = run.agents["caller"]
    lo, hi = sc["cancel_ms"]
    n = sc["calls"]
    run.say("%d calls %s -> far end, CANCEL swept %d..%d ms after 3CX lists the far leg as ringing (the "
            "'Upset ... status' syslog line; not the INVITE), reference wait <= %g s, gap %.0f s"
            % (n, caller.ext, lo, hi, sc["ref_timeout_s"], sc["gap_s"]))
    misses = diverted = 0
    for i in range(n):
        if run.stopped():
            break
        run.checkpoint()
        cancel_ms = lo + (hi - lo) * i / (n - 1) if n > 1 else lo
        t_start = time.monotonic()
        st = {}
        far = run.far_ends[i % len(run.far_ends)]     # #893: two lines on one phone alternate per call
        dlg = caller.invite(far, cancel_when=x4_when(run, cancel_ms, st),
                            cancel_when_timeout_s=sc["ref_timeout_s"])
        rec = call_record(i, cancel_ms, dlg, t_start)
        rec["ring_ref_ms"] = ms_since(dlg.invite_sent_at, st.get("ref_t"))
        rec["ref_timeout"] = bool(dlg.cancel_when_expired) and st.get("ref_t") is None
        if rec["ref_timeout"]:
            st["audio_opened"] = audio_opened(run, dlg.invite_sent_at, st.get("own_leg"))
        rec["audio_opened"] = bool(st.get("audio_opened"))
        rec["ref_stage"] = ref_stage(st, dlg) if rec["ref_timeout"] else None
        rec["ref_leg"] = st.get("leg")
        rec["cancel_after_ref_ms"] = None if None in (rec["cancel_sent_ms"], rec["ring_ref_ms"]) \
            else rec["cancel_sent_ms"] - rec["ring_ref_ms"]
        try:
            if dlg.ok:
                rec["bye"] = dlg.bye()
        finally:
            dlg.close()
        rec["duration_s"] = round(time.monotonic() - t_start, 3)
        rec["bucket"], rec["problem"] = x4_classify(rec)
        run.calls.append(rec)
        run.say("call %2d/%d: ringing reference %s, CANCEL planned +%d ms after it, sent %s, final %s (%s)%s%s"
                % (i + 1, n, "+%d ms" % rec["ring_ref_ms"] if rec["ring_ref_ms"] is not None
                   else "NONE within %g s (%s)" % (sc["ref_timeout_s"], rec["ref_stage"] or "a final came first"),
                   rec["cancel_planned_ms"],
                   "+%d ms" % rec["cancel_sent_ms"] if rec["cancel_sent_ms"] is not None else "never",
                   rec["final"], rec["bucket"], ": " + rec["problem"] if rec["problem"] else "",
                   " [a phantom ended the wait]" if st.get("phantom") else ""))
        run.pull_pcap("call-%02d" % (i + 1))
        misses = misses + 1 if rec["ref_timeout"] else 0
        diverted = diverted + 1 if rec["bucket"] == "diverted" else 0
        if misses >= MAX_NO_REF:
            # #892: the last leg's drop line follows its stream stop by ~0.2-0.5 s; the abort closes
            # the syslog capture, so wait the drop window first. A leg still undropped then FAILs.
            run.watch_call(time.monotonic() + sc["drop_wait_s"],
                           stop_when=lambda: not undropped_legs(run.syslog.lines()))
            if diverted >= misses:
                raise run_soak.Abort("INVALID", "%d calls in a row were %s: the run stops rather than ring the "
                                     "far end for nothing" % (misses, DIVERTED))
            raise run_soak.Abort("INVALID", "%d calls in a row had no ringing reference within %g s (%s): the "
                                 "run stops rather than ring the far end for nothing"
                                 % (misses, sc["ref_timeout_s"], rec["ref_stage"]))
        if i + 1 < n:
            run.idle(sc["gap_s"])


def x4_judge(run, sc, lines):
    fails, invalid = [], []
    buckets = collections.Counter(c["bucket"] for c in run.calls)
    for c in run.calls:
        if c["problem"]:
            fails.append("call %d: %s" % (c["call"], c["problem"]))
        if c["duration_s"] > sc["call_cap_s"]:
            fails.append("call %d took %.1f s (cap %d s)" % (c["call"], c["duration_s"], sc["call_cap_s"]))
    if len(run.calls) < sc["calls"]:
        invalid.append("only %d of %d calls ran" % (len(run.calls), sc["calls"]))
    diverted = [c for c in run.calls if c["bucket"] == "diverted"]
    if diverted:
        invalid.append("%d of %d calls were %s (%s): the far leg never rang, so they do not count toward the "
                       "path (INVALID, never PASS)"
                       % (len(diverted), len(run.calls), DIVERTED, calls_text([c["call"] for c in diverted])))
    missed = [c for c in run.calls if c.get("ref_timeout") and c["bucket"] != "diverted"]
    if missed:
        stages = collections.Counter(c["ref_stage"] for c in missed)
        invalid.append("%d of %d calls had no ringing reference within %g s (%s; %s): each was CANCELled at the "
                       "timeout, not %d-%d ms after 3CX listed the far leg as ringing, so it does not count "
                       "toward the path (INVALID, never PASS)"
                       % (len(missed), len(run.calls), sc["ref_timeout_s"], calls_text([c["call"] for c in missed]),
                          "; ".join("%d x %s" % (k, why) for why, k in sorted(stages.items())),
                          sc["cancel_ms"][0], sc["cancel_ms"][1]))
    if run.calls and not buckets["cancelled"]:
        invalid.append("no call was CANCELled while ringing: the path was not exercised")
    fails += drop_problems(lines)
    fails += rx_task_problems(lines)
    if count_lines(lines)["panic"]:
        fails.append("a panic line reached the syslog")
    for i, c in enumerate(run.calls):
        nxt = run.calls[i + 1]["t_start"] if i + 1 < len(run.calls) else None
        c["log"] = {k: v for k, v in count_lines(run.syslog.lines(c["t_start"], nxt)).items() if v}
    return fails, invalid, {"buckets": dict(buckets), "calls": len(run.calls)}


scenario(name="x4_cancel_ringing", issues=("#370", "#681", "#379"),
         about="row X4: test UA 6101 -> the designated far end through the anchor, CANCELled 0.6-1.4 s "
               "after 3CX lists the far leg as ringing (the 'Upset ... status' syslog line, not the INVITE: "
               "makecall takes seconds); 6104 holds the S1 pin and detects phantoms",
         uas={"caller": "6101", "detector": PIN_UA}, calls=30, cancel_ms=(600, 1400), ref_timeout_s=8.0,
         call_cap_s=30, gap_s=12.0, drop_wait_s=5.0, path_counter="rx554_window", ring_required=True,
         judge=x4_judge)(x4_run)


# ---------------------------------------------------------------- probe scenarios (H1)
def probe_run(body):
    """A probe scenario's body runs in try/finally: every fault is disarmed and the ballast
    released the moment it returns or raises, before the tail and before teardown."""
    def run(r, sc):
        try:
            body(r, sc)
        finally:
            r.probe_finish()
    run.__name__ = body.__name__
    return run


def ms_since(t0, t):
    return None if t is None or t0 is None else int(round((t - t0) * 1000))


def start_call(run, sc, caller):
    """One INVITE to the far end. The record goes on run.calls first, so an abort keeps it."""
    t0 = time.monotonic()
    rec = {"call": 1, "t_start": t0, "final": None}
    run.calls.append(rec)
    dlg = caller.invite(run.far_end)
    rec.update(_call_id=dlg.call_id, final=dlg.final_status,
               provisional=[s for _, s in dlg.responses if s < 200])
    return dlg, rec


def hang_up(dlg, rec):
    """The harness's own BYE, once, if the dialog is still up (also on an abort)."""
    if dlg.ok and not dlg.ended.is_set() and "_t_hangup" not in rec:
        rec["_t_hangup"] = time.monotonic()
        rec["hangup_ms"] = ms_since(rec["t_start"], rec["_t_hangup"])
        rec["hangup_bye"] = dlg.bye()


def finish_call(caller, dlg, rec):
    hang_up(dlg, rec)
    rec.update(bye_record(dlg, caller))
    dlg.close()
    rec["duration_s"] = round(time.monotonic() - rec["t_start"], 3)


def after_call(run, sc, caller, rec, base):
    run.pull_pcap("call-01")             # the ring holds 16 messages: right after the call
    rec["pcap_byes"] = run.pcap_count("BYE", caller, rec.get("_call_id"))
    rec["sessions"] = run.sessions_settle(base, caller.ext, sc["settle_s"])


def answered(c):
    return c.get("final") is not None and 200 <= c["final"] < 300


def common_problems(run, lines):
    """(fails, invalid) every probe judge starts from."""
    fails = ["a panic line reached the syslog"] if count_lines(lines)["panic"] else []
    if not run.calls:
        return fails, ["the call never started"]
    return fails, []


def pcap_bye_problems(c, who):
    if c.get("pcap_byes", 0) > max(1, c.get("pbx_byes") or 0):
        return ["/api/pcap shows %d BYE transactions sent to %s for the call, the UA counted %s (second "
                "witness)" % (c["pcap_byes"], who, c.get("pbx_byes"))]
    return []


# -- x379_cancel_before_leg ------------------------------------------------------
def x379_run(run, sc):
    caller = run.agents["caller"]
    lo, hi = sc["cancel_ms"]
    n = sc["calls"]
    run.say("%d calls %s -> far end, CANCEL swept %d..%d ms after the INVITE (before the makecall response, so "
            "before the 3CX leg exists), then up to %g s for the own-leg line, %g s for its drop, gap %.0f s"
            % (n, caller.ext, lo, hi, sc["leg_wait_s"], sc["drop_wait_s"], sc["gap_s"]))
    for i in range(n):
        if run.stopped():
            break
        run.checkpoint()
        cancel_ms = lo + (hi - lo) * i / (n - 1) if n > 1 else lo
        t_start = time.monotonic()
        dlg = caller.invite(run.far_end, cancel_after_ms=cancel_ms)
        rec = call_record(i, cancel_ms, dlg, t_start)
        rec.update(leg=None, leg_ms=None, drop_ms=None, cancel_before_leg=False)
        run.calls.append(rec)                  # first: a phantom abort below keeps the record
        try:
            if dlg.ok:
                rec["bye"] = dlg.bye()
        finally:
            dlg.close()
        rec["bucket"], rec["problem"] = x4_classify(rec)
        # The call is over; the makecall response is still on the wire. Watch for the leg it creates,
        # for its drop, and for anything that follows, with the phantom detector on throughout.
        known = {r["leg"] for r in run.calls[:-1] if r.get("leg")}
        found = []

        def leg_seen():
            found[:] = [(t, m.group(1)) for t, m in matches(run.syslog.entries(t_start), "initiated")
                        if m.group(1) not in known][:1]
            return bool(found)
        run.watch_call(t_start + sc["leg_wait_s"], stop_when=leg_seen)
        if found:
            t_leg, leg = found[0]
            rec.update(leg=leg, leg_ms=ms_since(t_start, t_leg), _leg_t=t_leg,
                       cancel_before_leg=dlg.cancel_sent_at is not None and dlg.cancel_sent_at < t_leg)
            t_drop = []

            def dropped():
                t_drop[:] = [t for t, _ in matches(run.syslog.entries(t_leg), "dropped", leg)][:1]
                return bool(t_drop)
            if run.watch_call(time.monotonic() + sc["drop_wait_s"], stop_when=dropped):
                rec["drop_ms"] = ms_since(t_leg, t_drop[0])
            run.watch_call(time.monotonic() + sc["settle_s"])     # a second drop, an inbound line, a phantom
        rec["duration_s"] = round(time.monotonic() - t_start, 3)
        run.say("call %2d/%d: CANCEL planned +%d ms, sent %s, final %s (%s); leg %s, own-leg line %s, drop %s%s"
                % (i + 1, n, rec["cancel_planned_ms"],
                   "+%d ms" % rec["cancel_sent_ms"] if rec["cancel_sent_ms"] is not None else "never",
                   rec["final"], rec["bucket"], rec["leg"] or "NONE",
                   "+%d ms" % rec["leg_ms"] if rec["leg_ms"] is not None else "never",
                   "+%d ms after it" % rec["drop_ms"] if rec["drop_ms"] is not None else "never",
                   ": " + rec["problem"] if rec["problem"] else ""))
        run.pull_pcap("call-%02d" % (i + 1))
        if i + 1 < n:
            run.idle(sc["gap_s"])


def x379_judge(run, sc, lines):
    fails, invalid = [], []
    if count_lines(lines)["panic"]:
        fails.append("a panic line reached the syslog")
    calls = run.calls
    buckets = collections.Counter(c.get("bucket") for c in calls)
    no_leg, early, many, race = [], [], [], 0
    for i, c in enumerate(calls):
        n = c["call"]
        nxt = calls[i + 1]["t_start"] if i + 1 < len(calls) else None
        ents = run.syslog.entries(c["t_start"], nxt) if run.syslog else []
        c["log"] = {k: v for k, v in count_lines([ln for _, ln in ents]).items() if v}
        if c.get("problem"):
            fails.append("call %d: %s" % (n, c["problem"]))
        elif c.get("bucket") != "cancelled":
            fails.append("call %d ended %s, not 487: PASS needs the CANCEL to end the call" % (n, c.get("final")))
        if c.get("duration_s") is not None and c["duration_s"] > sc["call_cap_s"]:
            fails.append("call %d took %.1f s (cap %d s)" % (n, c["duration_s"], sc["call_cap_s"]))
        leg = c.get("leg")
        if not leg:
            no_leg.append(n)
            continue
        if len(matches(ents, "initiated")) > 1:
            many.append(n)
        if c.get("cancel_before_leg"):
            race += 1
        else:
            early.append(n)
        drops = matches(ents, "dropped", leg)
        if not drops:
            fails.append("call %d: leg %s was never dropped within %g s of its creation (syslog is the only "
                         "witness, S2): a live billable leg on 3CX?" % (n, leg, sc["drop_wait_s"]))
        elif len(drops) > 1:
            fails.append("call %d: leg %s was dropped %d times" % (n, leg, len(drops)))
        elif drops[0][0] < c["_leg_t"]:
            fails.append("call %d: the drop of leg %s was logged before its own-leg line" % (n, leg))
        failed = matches(ents, "drop_failed", leg)
        if failed:
            fails.append("call %d: the drop of leg %s failed %d time(s)" % (n, leg, len(failed)))
        if matches(ents, "inbound_call", leg):
            fails.append("call %d: 'Inbound call on DN' was logged for leg %s, the leg this call initiated and "
                         "had dropped: a dropped leg announced as an inbound call would ring the DID row's "
                         "phones; %s" % (n, leg, LOOPBACK_CAVEAT))
    if no_leg:
        invalid.append("no own-leg line within %g s of the INVITE for %s: the leg never came up, so the "
                       "CANCEL-before-the-leg race was not exercised (INVALID, never PASS)"
                       % (sc["leg_wait_s"], calls_text(no_leg)))
    if early:
        invalid.append("the makecall response (the own-leg line) came before the CANCEL for %s: the CANCEL did "
                       "not beat the leg, so the race was not exercised (INVALID, never PASS)" % calls_text(early))
    if many:
        invalid.append("more than one own-leg line during %s: one INVITE should start one leg" % calls_text(many))
    if len(calls) < sc["calls"]:
        invalid.append("only %d of %d calls ran" % (len(calls), sc["calls"]))
    phantom_pcap = sum(run.pcap_count("INVITE", ua, phantom=True) for ua in run.agents.values())
    if phantom_pcap:
        fails.append("/api/pcap shows %d INVITE(s) sent to a test UA that were not the register beep: a phantom "
                     "inbound (second witness); %s" % (phantom_pcap, LOOPBACK_CAVEAT))
    return fails, invalid, {"buckets": dict(buckets), "calls": len(calls), "race_exercised": race,
                            "pcap_phantom_invites": phantom_pcap,
                            "drop_witness": "syslog only (S2): the 3CX participant list is not readable here"}


scenario(name="x379_cancel_before_leg", issues=("#379", "#681"),
         about="test UA 6101 -> the designated far end through the anchor, CANCELled 0.3-0.8 s after the INVITE, "
               "before the makecall response so before the 3CX leg exists: 487, the leg dropped exactly once "
               "when it does, no inbound-call line for it, nothing at 6104",
         uas={"caller": "6101", "detector": PIN_UA}, calls=10, max_calls=10, cancel_ms=(300, 800),
         call_cap_s=30, gap_s=12.0, leg_wait_s=10.0, drop_wait_s=5.0, settle_s=2.0,
         path_counter="initiated", ring_required=True, judge=x379_judge)(x379_run)


# -- x349_unread_makecall ------------------------------------------------------
def x349_run(run, sc):
    caller = run.agents["caller"]
    run.say("1 call %s -> far end with makecall_read_fail armed (#349), hung up %.0f s after the INVITE; "
            "an INVITE at %s or %s stops the run" % (caller.ext, sc["hold_s"], PIN_UA, caller.ext))
    run.checkpoint()
    base = run.session_count()
    run.arm("makecall_read_fail")
    dlg, rec = start_call(run, sc, caller)
    try:
        if dlg.ok:
            if run.watch_call(rec["t_start"] + sc["hold_s"], stop_when=dlg.ended.is_set):
                rec["pbx_hung_up_ms"] = ms_since(rec["t_start"], dlg.bye_log[0]["t"] if dlg.bye_log else None)
        else:
            run.watch_call(time.monotonic() + sc["phantom_watch_s"])   # the #349 phantom comes ~750 ms later
    finally:
        finish_call(caller, dlg, rec)
    after_call(run, sc, caller, rec, base)
    run.say("call 1: final %s, %s" % (rec["final"], "hung up after %s ms (BYE %s)" % (rec.get("hangup_ms"),
                                                                                     rec.get("hangup_bye"))
                                      if "hangup_ms" in rec else "not hung up by the harness"))


def x349_judge(run, sc, lines):
    fails, invalid = common_problems(run, lines)
    if not run.calls:
        return fails, invalid, {}
    c = run.calls[0]
    caller = run.agents["caller"]
    ents = run.syslog.entries(c["t_start"]) if run.syslog else []
    legs = started_legs(ents)
    adopted, orphan = matches(ents, "adopted_349"), matches(ents, "orphaned_349")
    failed = matches(ents, "makecall_status")
    fail_end = [r for _, r in endcalls(ents, c.get("_call_id")) if r == "anchor call fail"]
    phantom_pcap = sum(run.pcap_count("INVITE", ua, phantom=True) for ua in run.agents.values())
    c["log"] = {"legs": len(legs), "adopted": len(adopted), "orphaned": len(orphan),
                "makecall_failed": len(failed) + len(fail_end), "pcap_phantom_invites": phantom_pcap}
    summary = dict(c["log"], drop_witness="syslog only (S2): the 3CX participant list is not readable here")
    if orphan:
        fails.append("makeCall logged a possible ORPHAN (#349/#328): a billable leg may be live on the 3CX "
                     "route point; check the tenant and drop it by hand")
        run.manifest["notes"].append("ORPHAN WARNING: check the 3CX route point for a live leg and drop it")
    if failed or fail_end:
        fails.append("the unread makecall response was treated as a failure (makeCall request failed / "
                     "endCall reason=anchor call fail): the #349 bug")
    if phantom_pcap:
        fails.append("/api/pcap shows %d INVITE(s) sent to a test UA that were not the register beep: a "
                     "phantom inbound (second witness)" % phantom_pcap)
    if len(adopted) > 1:
        fails.append("makeCall adopted %d times for one call" % len(adopted))
    if fails:
        return fails, invalid, summary
    if not adopted:
        invalid.append("the fault fired but no adopt line (#349) reached the syslog: a lost line cannot be told "
                       "from a missing path (S2)")
    if not answered(c):
        invalid.append("the far end did not answer (final %s): the adopted call could not proceed" % c["final"])
        return fails, invalid, summary
    if c.get("pbx_hung_up_ms") is not None:
        invalid.append("the call ended from the far side after %s ms, before the planned hangup: the drop at "
                       "hangup was not exercised" % c["pbx_hung_up_ms"])
        return fails, invalid, summary
    if len(legs) != 1:
        invalid.append("%d anchored legs started during the call, not 1" % len(legs))
        return fails, invalid, summary
    if c.get("hangup_bye") != 200:
        fails.append("the harness's BYE got %s, not 200" % c.get("hangup_bye"))
    fails += drop_problems(lines)
    sf, si = session_problems(c, caller.ext)
    return fails + sf, invalid + si, summary


scenario(name="x349_unread_makecall", issues=("#349",), probe=True, faults=("makecall_read_fail",),
         about="test UA 6101 -> the designated far end with makecall_read_fail armed: makeCall must adopt "
               "its own leg (#349), no phantom inbound may reach 6104, one drop at hangup",
         uas={"caller": "6101", "detector": PIN_UA}, calls=1, call_cap_s=20, hold_s=10.0,
         phantom_watch_s=5.0, settle_s=5.0, path_counter="bench_makecall_read_fail", ring_required=True,
         judge=x349_judge)(probe_run(x349_run))


# -- x379_never_opened / x518_403_clean_giveup -------------------------------------
def never_opened_run(run, sc):
    caller = run.agents["caller"]
    n, code = sc["get_max_attempts"], sc["get_status"]
    run.say("1 call %s -> far end with get_status=%d and get_max_attempts=%d armed: the GET budget is "
            "spent and the handset BYE due within %.0f s (worst case), cap %d s"
            % (caller.ext, code, n, get_giveup_worst_s(n), sc["call_cap_s"]))
    run.checkpoint()
    base = run.session_count()
    run.arm("get_status", code)
    run.arm("get_max_attempts", n)
    dlg, rec = start_call(run, sc, caller)
    rec.update(get_status=code, get_max_attempts=n)
    try:
        if dlg.ok and run.watch_call(rec["t_start"] + sc["call_cap_s"] - HANGUP_MARGIN_S,
                                     stop_when=dlg.ended.is_set):
            rec["pbx_bye_ms"] = ms_since(rec["t_start"], dlg.bye_log[0]["t"] if dlg.bye_log else None)
            run.watch_call(time.monotonic() + sc["dup_wait_s"])          # a second BYE lands here
    finally:
        finish_call(caller, dlg, rec)
    after_call(run, sc, caller, rec, base)
    run.say("call 1: final %s, PBX BYE at %s ms%s" % (rec["final"], rec.get("pbx_bye_ms"),
                                                      ", the harness hung up" if "hangup_ms" in rec else ""))


def never_opened_judge(run, sc, lines):
    fails, invalid = common_problems(run, lines)
    if not run.calls:
        return fails, invalid, {}
    c = run.calls[0]
    caller = run.agents["caller"]
    ents = run.syslog.entries(c["t_start"]) if run.syslog else []
    n = sc["get_max_attempts"]
    legs = started_legs(ents)
    ev = {"legs": len(legs)}
    c["log"] = ev
    if not answered(c):
        invalid.append("the far end did not answer (final %s): a give-up would have no dialog to BYE" % c["final"])
        return fails, invalid, ev
    if len(legs) != 1:
        invalid.append("%d anchored legs started during the call, not 1" % len(legs))
        return fails, invalid, ev
    leg = legs[0]
    attempts = [(int(m.group(1)), int(m.group(2))) for _, line in ents for m in [_ATTEMPT.search(line)] if m]
    spent = matches(ents, "get_budget_spent")
    transport, rebuild = matches(ents, "get_transport_giveup"), matches(ents, "get_rebuild_giveup")
    drops, drop_failed = matches(ents, "dropped", leg), matches(ents, "drop_failed", leg)
    ends = endcalls(ents, c.get("_call_id"))
    branch = "transport" if transport else "rebuild" if rebuild else "budget" if spent else "none"
    t_hang, t_spent = c.get("_t_hangup"), (spent[0][0] if spent else None)
    # MediaNeverOpened's witness on syslog (its own "no rx audio, dropping leg" line is
    # queueLog, stdout only): after the spent budget the board stops this call's bridge
    # (logged synchronously, before its drop is queued) or drops leg L, before any endCall
    # of the call and before any harness hangup. A teardown logs endCall first. The drop
    # line alone is not ordered against endCall: the tel_drop worker logs it after the
    # POST's answer, and 3CX's Remove (endCall "anchor hangup") can come first.
    stops = [t for t, _ in matches(ents, "stop_bridge", c.get("_call_id"))] + [t for t, _ in drops]
    t_first = min((t for t in stops if t_spent is None or t >= t_spent), default=None)
    on_its_own = t_first is not None and (t_hang is None or t_first < t_hang) \
        and not any(t <= t_first for t, _ in ends)
    ev.update(attempts=len(attempts), budgets=sorted({b for _, b in attempts}),
              max_attempt=max((a for a, _ in attempts), default=0),
              refused=dict(collections.Counter(m.group(1) for _, m in matches(ents, "get_refused"))),
              refused_403_this_leg=len(matches(ents, "get_refused_403", leg)), branch=branch,
              never_opened_lines=len(matches(ents, "get_never_opened")), drops=len(drops),
              drop_failed=len(drop_failed), endcall_reasons=[r for _, r in ends],
              dropped_by_the_board_on_its_own=on_its_own and branch == "budget",
              rh_never_opened_line=len(matches(ents, "rh_never_opened_drop", leg)),
              harness_hung_up=t_hang is not None, pcap_byes=c.get("pcap_byes"),
              drop_witness="syslog only (S2): 3CX is HTTPS and its participant list is not readable here")
    if ev["budgets"] and ev["budgets"] != [n]:
        invalid.append("the attempt lines count to /%s, not /%d: get_max_attempts did not reach this leg"
                       % ("/".join(str(b) for b in ev["budgets"]), n))
    if sc.get("require_refused") and not ev["refused_403_this_leg"]:
        invalid.append("no 'GET stream refused (HTTP 403)' line for leg %s reached the syslog (#518)" % leg)
    # S6: exactly one drop in every branch.
    if not drops:
        fails.append("leg %s was never dropped (syslog is the only witness, S2): a live billable leg on 3CX?"
                     % leg)
    elif len(drops) > 1:
        fails.append("leg %s was dropped %d times" % (leg, len(drops)))
    if drop_failed:
        fails.append("the drop of leg %s failed %d time(s)" % (leg, len(drop_failed)))
    if branch in ("transport", "rebuild"):
        invalid.append("S6: the GET loop gave up by the %s branch, not a spent budget, so MediaNeverOpened is "
                       "not raised by design; leg %s was dropped %d time(s), %s" % (
                           branch, leg, len(drops), "never" if not drops else
                           "by the board before any hangup" if on_its_own else "only after the harness hung up"))
        return fails, invalid, ev
    if branch == "none":
        invalid.append("the GET budget was not spent within the call (highest attempt %d/%d)"
                       % (ev["max_attempt"], n))
        return fails, invalid, ev
    if drops and not on_its_own:
        fails.append("the GET budget was spent but leg %s was dropped only by a teardown or the harness's "
                      "hangup, not by the board on its own (MediaNeverOpened, #379)" % leg)
    if t_hang is not None:
        fails.append("no BYE reached %s within the %d s cap after the give-up: the harness hung up"
                     % (caller.ext, sc["call_cap_s"]))
    fails += bye_problems(c, caller.ext, count=t_hang is None)
    if t_hang is None:
        fails += ruri_problems(c, caller.ext)
    fails += pcap_bye_problems(c, caller.ext)
    sf, si = session_problems(c, caller.ext)
    return fails + sf, invalid + si, ev


NEVER_OPENED = dict(probe=True, faults=("get_status", "get_max_attempts"), get_status=403,
                    get_max_attempts=12, uas={"caller": "6101", "detector": PIN_UA},
                    agent_opts={"caller": {"contact_params": ";line=pd6101"}}, calls=1,
                    call_cap_s=30, dup_wait_s=3.0, settle_s=5.0, ring_required=True,
                    judge=never_opened_judge)
scenario(name="x379_never_opened", issues=("#379",),
         about="test UA 6101 (Contact ;line=pd6101) -> the designated far end; every GET stream answer reads "
               "403 and the budget is 12: the board must drop the leg once on its own (MediaNeverOpened) and "
               "BYE 6101 once, at its registered Contact",
         path_counter="get_budget_spent", **NEVER_OPENED)(probe_run(never_opened_run))
scenario(name="x518_403_clean_giveup", issues=("#518", "#379"), require_refused=True,
         about="x379_never_opened plus the 'GET stream refused (HTTP 403)' line (#519): a 403 for the "
               "whole budget gives up cleanly; one run serves both issues",
         path_counter="get_refused_403", **NEVER_OPENED)(probe_run(never_opened_run))


# -- x279_degraded_bye (Connected; the Held variant is not registered) ----------------
def x279_run(run, sc):
    caller = run.agents["caller"]
    run.say("1 call %s -> far end with handset RTP; post_stream_fail armed %g s after the POST stream "
            "opens; the BYE is due within %g s" % (caller.ext, sc["write_settle_s"], sc["bye_wait_s"]))
    run.checkpoint()
    base = run.session_count()
    dlg, rec = start_call(run, sc, caller)
    rec["variant"] = "connected"

    def drive():
        if not dlg.ok:
            return
        _, m = run.wait_line("initiated", rec["t_start"], sc["post_open_wait_s"])
        t_open, m = run.wait_line("post_open", rec["t_start"], sc["post_open_wait_s"],
                                  key=m.group(1)) if m else (None, None)
        if m is None:
            return
        rec.update(leg=m.group(1), post_open_ms=ms_since(rec["t_start"], t_open))
        if run.watch_call(time.monotonic() + sc["write_settle_s"], stop_when=dlg.ended.is_set):
            rec["ended_before_arm"] = True
            return
        rec["rtp_sent_before_arm"] = dlg.media_counts()[0]
        if not rec["rtp_sent_before_arm"]:
            return
        run.arm("post_stream_fail")
        rec["_t_armed"] = time.monotonic()
        if run.watch_call(rec["_t_armed"] + sc["bye_wait_s"], stop_when=dlg.ended.is_set):
            rec["bye_after_arm_ms"] = ms_since(rec["_t_armed"], dlg.bye_log[0]["t"] if dlg.bye_log else None)
            run.watch_call(time.monotonic() + sc["dup_wait_s"])          # a second BYE lands here
            rec["reinvite"] = dlg.reinvite("sendonly")                   # the dead dialog: 481 (#611)
    try:
        drive()
    finally:
        finish_call(caller, dlg, rec)
    after_call(run, sc, caller, rec, base)
    run.say("call 1: final %s, BYE %s ms after the fault, re-INVITE %s" % (
        rec["final"], rec.get("bye_after_arm_ms"), rec.get("reinvite")))


def x279_judge(run, sc, lines):
    fails, invalid = common_problems(run, lines)
    if not run.calls:
        return fails, invalid, {}
    c = run.calls[0]
    caller = run.agents["caller"]
    ents = run.syslog.entries(c["t_start"]) if run.syslog else []
    ev = {}
    c["log"] = ev
    if not answered(c):
        invalid.append("the far end did not answer (final %s)" % c["final"])
    elif not c.get("leg"):
        invalid.append("no POST stream OPEN line for the call's leg within %g s: the fault had no stream to break"
                       % sc["post_open_wait_s"])
    elif c.get("ended_before_arm"):
        invalid.append("the call ended before the fault was armed")
    elif not c.get("rtp_sent_before_arm"):
        invalid.append("no handset RTP before the fault: writeAudio() never ran, so there was no good write "
                       "for the bridge to degrade from (MediaBridge::isAudioDegraded)")
    if invalid:
        return fails, invalid, ev
    leg, cid = c["leg"], c.get("_call_id")
    degraded = matches(ents, "degraded_endcall", cid)
    drops, drop_failed = matches(ents, "dropped", leg), matches(ents, "drop_failed", leg)
    ev.update(degraded_endcalls=len(degraded), endcall_reasons=[r for _, r in endcalls(ents, cid)],
              drops=len(drops), drop_failed=len(drop_failed), rh_teardown_line=len(matches(ents, "rh_degraded")),
              pcap_byes=c.get("pcap_byes"),
              drop_witness="syslog only (S2): 3CX is HTTPS and its participant list is not readable here")
    if not degraded:
        invalid.append("no 'endCall <this call> reason=anchor audio write failure' line: the degraded teardown "
                       "was not shown to run (its 'anchor call torn down' line is queueLog, never on syslog)")
        return fails, invalid, ev
    if len(degraded) > 1:
        fails.append("the degraded teardown ran %d times for one call" % len(degraded))
    fails += bye_problems(c, caller.ext, count=c.get("_t_hangup") is None)
    if c.get("_t_hangup") is not None:
        fails.append("no BYE reached %s within %g s of the fault: the harness hung up (#279)"
                     % (caller.ext, sc["bye_wait_s"]))
    else:
        fails += ruri_problems(c, caller.ext)
        if c.get("reinvite") != 481:
            fails.append("a re-INVITE on the torn-down dialog got %s, not 481" % c.get("reinvite"))
    if not drops:
        fails.append("leg %s was never dropped (syslog is the only witness, S2)" % leg)
    elif len(drops) > 1:
        fails.append("leg %s was dropped %d times" % (leg, len(drops)))
    if drop_failed:
        fails.append("the drop of leg %s failed %d time(s)" % (leg, len(drop_failed)))
    fails += pcap_bye_problems(c, caller.ext)
    sf, si = session_problems(c, caller.ext)
    return fails + sf, invalid + si, ev


scenario(name="x279_degraded_bye", issues=("#279",), probe=True, faults=("post_stream_fail",),
         about="test UA 6101 (Contact ;line=pd6101, sending RTP) -> the designated far end, answered; "
               "post_stream_fail breaks the POST stream: one BYE to 6101 at its registered Contact, one "
               "drop, sessionCount back to baseline, a re-INVITE on the dead dialog gets 481",
         uas={"caller": "6101", "detector": PIN_UA},
         agent_opts={"caller": {"rtp": True, "contact_params": ";line=pd6101"}},
         calls=1, call_cap_s=30, post_open_wait_s=8.0, write_settle_s=1.5, bye_wait_s=3.0, dup_wait_s=1.5,
         settle_s=5.0, path_counter="degraded_endcall", ring_required=True,
         judge=x279_judge)(probe_run(x279_run))


# ---------------------------------------------------------------- CLI
class _Parser(argparse.ArgumentParser):
    def error(self, message):
        raise Refused("usage: %s" % message)


def build_parser():
    ap = _Parser(prog="sip_stress.py --scenario", description=__doc__,
                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--scenario", required=True, choices=sorted(SCENARIOS))
    ap.add_argument("--host", required=True, help="the rig (%s)" % ", ".join(RIG_HOSTS))
    ap.add_argument("--port", type=int, default=5060, help="the board's SIP port")
    ap.add_argument("--http-port", type=int, default=80)
    ap.add_argument("--local-ip", default=None, help="this host's address on the rig's LAN "
                    "(SIP UAs and the syslog listener bind here; default: the route to --host)")
    ap.add_argument("--syslog-port", type=int, default=5514, help="UDP; above 1024, so no root")
    ap.add_argument("--set-syslog", action="store_true",
                    help="point the board's syslog here for the run (POST /api/syslog), restored after")
    ap.add_argument("--approval-url", default=None, help="one of APPROVALS")
    ap.add_argument("--checkout-url", default=None, help="the discussion #428 CHECK-OUT comment link")
    ap.add_argument("--checkout-expiry", default=None, help="its expiry, ISO-8601 with a zone")
    ap.add_argument("--owner-ext", default=None, help="owner extensions beyond %s (or PD_OWNER_EXTS)"
                    % ",".join(OWNER_EXTS))
    ap.add_argument("--expect-version", default=None,
                    help="the /api/status version the run must see (required for a real run)")
    ap.add_argument("--pin-check-s", type=float, default=5.0)
    ap.add_argument("--out", default="anchor-evidence")
    ap.add_argument("--dry-run", action="store_true", help="print the plan; contact nothing")
    return ap


RUN_DEFAULTS = {"register_expires": 120, "register_refresh_s": 60.0, "beep_wait_s": 3.0,
                "roster_wait_s": 10.0, "tail_s": 20.0}


def needed_s(sc):
    return 300 + sc["calls"] * (sc["call_cap_s"] + sc.get("gap_s", 0)) + RUN_DEFAULTS["tail_s"]


def main(argv=None, env=None, http=None, agent_factory=None, start_logger=None, out=print,
         overrides=None, run_defaults=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    env = os.environ if env is None else env
    red = Redactor()
    for name in SECRET_ENVS:
        red.add(env.get(name))
    try:
        for lit in rig_policy.literal_secrets(env.get("PD_SECRETS_FILE")):
            red.add(lit)
    except OSError:
        out("REFUSED: PD_SECRETS_FILE cannot be read: failing closed")
        return REFUSED

    def emit(text):
        out(red.text(text))

    problems = []
    far = src = None
    try:
        far, src = load_far_ends(env)
        for end in far:
            red.add(end)
    except Refused as e:
        problems.append(str(e))
    bad_argv = argv_problems(argv, red)
    if bad_argv:                 # before argparse, which would echo the value
        for p in bad_argv + problems:
            emit("REFUSED: " + p)
        return REFUSED
    try:
        args = build_parser().parse_args(argv)
    except Refused as e:
        emit("REFUSED: " + str(e))
        return REFUSED
    for k, v in dict(RUN_DEFAULTS, **(run_defaults or {})).items():
        setattr(args, k, v)
    sc = dict(SCENARIOS[args.scenario], **(overrides or {}))
    owner = owner_set(args.owner_ext, env.get("PD_OWNER_EXTS"))
    problems += scenario_problems(sc) + host_problems(args.host) + approval_problems(args.approval_url)
    if far is not None:
        for end in far:
            problems += far_end_problems(end, owner)
    if not args.dry_run and not args.expect_version:
        problems.append("no --expect-version: the closure rule needs a provenance-checked image "
                        "(the release stamp, or that commit's -probe stamp)")
    if sc.get("probe") and args.expect_version and "-probe" not in args.expect_version:
        problems.append("--expect-version is not a -probe stamp: %s drives the bench probe image "
                        "(docs/BENCH_PROBE.md), which a release image does not carry" % sc["name"])
    if not env.get(PIN_ENV):
        problems.append("no %s in the environment: the S1 pin cannot be checked without an admin "
                        "session" % PIN_ENV)
    problems += lp.checkout_problems(args.checkout_url, args.checkout_expiry, time.time(), needed_s(sc))
    args.far_end_source = src
    args.local_ip = args.local_ip or sip_agent.local_ip_for(args.host, args.port)

    emit("sip_stress.py --scenario %s%s" % (sc["name"], "  (DRY RUN: nothing is contacted)" if args.dry_run else ""))
    emit("  issues    %s (Part of #384): %s" % (" ".join(sc.get("issues", ())), sc.get("about")))
    emit("  board     %s  SIP :%d  HTTP :%d" % (args.host, args.port, args.http_port))
    emit("  test UAs  %s; the S1 pin is <route DN> -> %s" % (
        ", ".join("%s %s" % kv for kv in sorted(sc["uas"].items())), PIN_UA))
    emit("  far end   %s (never printed)%s" % ("from " + {"file": FAR_END_FILE_ENV, "env": FAR_END_ENV}[src]
                                               if src else "<not set>",
                                               "; two numbers, x4 alternates them per call" if far and len(far) == 2
                                               else ""))
    emit("  calls     %d, each <= %d s; counter %s (INVALID if 0)" % (sc["calls"], sc["call_cap_s"],
                                                                     sc["path_counter"]))
    emit("  approval  %s" % (args.approval_url or "<none>"))
    emit("  CHECK-OUT %s until %s" % (args.checkout_url or "<none>", args.checkout_expiry or "<none>"))
    if sc.get("probe"):
        emit("  probe     arms %s (each one-shot), disarms every fault and releases the ballast in a "
             "finally, then reads the counters back" % ", ".join(
                 "%s=%s" % (f, sc[f]) if f in sc else f for f in sc["faults"]))
        emit("  PROBE IMAGE: never leave it on a rig; CHECK-IN (#428) puts a release image back")
    if sc.get("ring_required"):
        emit("  " + RING_REQUIRED)
    if problems:
        for p in problems:
            emit("REFUSED: " + p)
        emit("nothing was sent")
        return REFUSED
    if args.dry_run:
        return 0

    http = http or BoardHttp(args.host, args.http_port, red, env)
    http.redactor = red
    factory = agent_factory or (lambda ext, **kw: sip_agent.Agent(
        ext, args.host, args.port, local_ip=args.local_ip, strict_dialogs=True, reject_invites=486, **kw))
    starter = start_logger or run_soak.RealRunner().start
    run = AnchorRun(args, sc, far, red, http, factory, starter, out)
    old = {}

    def on_signal(signum, frame):
        run.stop.set()
    for sig in (signal.SIGINT, signal.SIGTERM, getattr(signal, "SIGHUP", None)):
        if sig is None:
            continue
        try:
            old[sig] = signal.signal(sig, on_signal)
        except ValueError:
            pass                     # not the main thread (a test driving main())
    verdict, reason = "INVALID", ""
    end = None
    try:
        os.makedirs(run.dir, exist_ok=True)
        run.say("evidence: %s" % run.dir)
        run.execute()
    except run_soak.Abort as e:
        verdict, reason = e.verdict, e.reason
        run.aborted = True
        run.say("%s: %s" % (e.verdict, e.reason))
        if e.verdict == "INVALID":
            run.invalid.append(e.reason)
    except Exception as e:  # noqa: BLE001 -- a harness fault still ends in evidence
        run.aborted = True
        reason = "harness exception: %r" % (e,)
        run.invalid.append(reason)
        run.say(reason)
    finally:
        try:
            end = run.teardown()
        except Exception as e:  # noqa: BLE001
            run.invalid.append("teardown: %r" % (e,))
        for sig, h in old.items():
            signal.signal(sig, h)
    if verdict != "ABORTED":
        fails, invalid = run.judge(end)
        verdict = "FAIL" if fails else "INVALID" if invalid else "PASS"
        reason = "; ".join(fails or invalid) or "completed"
        for p in fails:
            run.say("FAIL: " + p)
        for p in invalid:
            run.say("INVALID: " + p)
    verdict = run.bundle(verdict, reason)
    run.say("evidence: %s.tar.gz" % run.dir)
    run.say("ANCHOR SCENARIO %s: %s (exit %d)" % (sc["name"], verdict, EXIT[verdict]))
    return EXIT[verdict]


if __name__ == "__main__":
    sys.exit(main())
