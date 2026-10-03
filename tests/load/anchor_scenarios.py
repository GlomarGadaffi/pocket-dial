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
import json
import os
import re
import signal
import socket
import stat
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
}
_RX = {k: re.compile(v) for k, v in LOG_COUNTERS.items()}


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


def far_end_problems(far, owner):
    """Every reason `far` may not be dialled, or []. Never echoes the number."""
    if not re.fullmatch(r"\+?[0-9]{3,15}", far or ""):
        return ["the far end is not 3-15 digits with an optional leading +: a URI or a name "
                "could route anywhere"]
    problems = []
    d = far.lstrip("+")
    bare = d[1:] if len(d) == 4 and d[0] == "9" else d      # one trunk-access digit (EmergencyCall.hpp)
    if any(e in d for e in lp.EMERGENCY_SUBSTRINGS) or d in NEVER_EXACT or bare in NEVER_EXACT \
            or d in lp.EMERGENCY_EXACT:
        problems.append("the far end is an emergency or never-dial number (911/933 anywhere in it, "
                        "112, 113, 999): refused")
    if d in owner:
        problems.append("the far end is an owner extension: refused")
    if d in TEST_UAS or d in lp.SERVICE or d in OTHER_PBX_NUMBERS:
        problems.append("the far end is a number this PBX owns (a test UA, a service number, an "
                        "orbit or a page zone): it would never reach the anchor")
    return problems


def load_far_end(env, stat_fn=os.stat, posix=None):
    """-> (far end, where it came from). Raises Refused, never echoing the value."""
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
        if len(lines) != 1:
            raise Refused("%s must hold exactly one number" % FAR_END_FILE_ENV)
        return lines[0], "file"
    if value:
        return value.strip(), "env"
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


# ---------------------------------------------------------------- scenario registry
SCENARIOS = {}


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
    if not 1 <= sc.get("calls", 0) <= MAX_CALLS:
        problems.append("%s: calls must be 1-%d (the #384 approval)" % (n, MAX_CALLS))
    if not 0 < sc.get("call_cap_s", 0) <= MAX_CALL_S:
        problems.append("%s: call_cap_s must be 1-%d (each call <= ~30 s)" % (n, MAX_CALL_S))
    if not callable(sc.get("run")) or not callable(sc.get("judge")):
        problems.append("%s: needs a run and a judge" % n)
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
        with self._lock:
            return [ln for t, ln in self._lines
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

    def logout(self):
        if self.cookie:
            self._req("POST", "/api/admin/logout", {}, auth=True, csrf=True)
            self.cookie = self.csrf = None


# ---------------------------------------------------------------- the run
class AnchorRun:
    def __init__(self, args, sc, far_end, redactor, http, agent_factory, start_logger, out):
        self.a, self.sc, self.far_end, self.red = args, sc, far_end, redactor
        self.http, self.agent_factory, self.start_logger, self.out = http, agent_factory, start_logger, out
        self.stop = threading.Event()
        self.ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        self.dir = os.path.join(os.path.abspath(args.out), "anchor-%s-%s" % (sc["name"], self.ts))
        self.agents = {}
        self.calls, self.fails, self.invalid, self.log_lines = [], [], [], []
        self.syslog = self.logger = self.watch = None
        self.route_dn = None
        self.syslog_restore = None
        self.baseline = {}
        self.last_reg = 0.0
        self.aborted = False
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

    def pin_problem(self):
        """Why the S1 pin does not hold right now, or None."""
        rows = (self.http.get_json("/api/did-mapping") or {}).get("mappings")
        if not isinstance(rows, list):
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
        far = self.far_end.lstrip("+")
        if any(str(c.get("number")) in (self.far_end, far) for c in clients):
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
        if self.phantoms():
            raise run_soak.Abort("FAIL", "a phantom inbound reached a test UA: no more calls")
        self.watch_board()

    def phantoms(self):
        """Every INVITE a test UA refused that was not the register beep."""
        return [(role, ua.ext, r["from_user"]) for role, ua in sorted(self.agents.items())
                for r in list(ua.rejected) if r["from_user"] != BEEP_USER]

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
        with open(self.p("pcap", name + ".pcap"), "wb") as f:
            f.write(self.red.same_length(data))

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
        self.logger = self.start_logger([LOGGER, self.http.base[len("http://"):], self.p("status.jsonl")],
                                        self.p("logger.log"))
        self.logger_started = time.time()
        self.watch = run_soak.Watch(self.p("status.jsonl"))
        for role, ext in sorted(self.sc["uas"].items()):
            self.agents[role] = self.agent_factory(ext)
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
        return end

    def judge(self, end_status):
        lines = self.syslog.lines() if self.syslog else []
        counts = count_lines(lines)
        self.manifest["log_counters"] = counts
        self.manifest["syslog_lines"] = len(lines)
        fails, invalid = list(self.fails), list(self.invalid)
        for role, ext, who in self.phantoms():
            fails.append("an INVITE from %r reached test UA %s (%s): a phantom inbound (S1)" % (who, ext, role))
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
        if self.calls or not self.aborted:
            more_fails, more_invalid, summary = self.sc["judge"](self, self.sc, lines)
            fails += more_fails
            invalid += more_invalid
            self.manifest["summary"] = summary
        self.manifest["fail_reasons"], self.manifest["invalid_reasons"] = fails, invalid
        return fails, invalid

    def bundle(self, verdict, reason):
        os.makedirs(self.dir, exist_ok=True)
        with open(self.p("calls.json"), "w", encoding="utf-8") as f:
            f.write(self.red.text(json.dumps(self.calls, indent=1)))
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
    """-> (bucket, problem or None) for one call (RFC 3261 s9.1, #548)."""
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


def x4_run(run, sc):
    caller = run.agents["caller"]
    lo, hi = sc["cancel_ms"]
    n = sc["calls"]
    run.say("%d calls %s -> far end, CANCEL swept %d..%d ms after the INVITE, gap %.0f s"
            % (n, caller.ext, lo, hi, sc["gap_s"]))
    for i in range(n):
        if run.stopped():
            break
        run.checkpoint()
        cancel_ms = lo + (hi - lo) * i / (n - 1) if n > 1 else lo
        t_start = time.monotonic()
        dlg = caller.invite(run.far_end, cancel_after_ms=cancel_ms)
        rec = call_record(i, cancel_ms, dlg, t_start)
        try:
            if dlg.ok:
                rec["bye"] = dlg.bye()
        finally:
            dlg.close()
        rec["duration_s"] = round(time.monotonic() - t_start, 3)
        rec["bucket"], rec["problem"] = x4_classify(rec)
        run.calls.append(rec)
        run.say("call %2d/%d: CANCEL planned +%d ms, sent %s, final %s (%s)%s"
                % (i + 1, n, rec["cancel_planned_ms"],
                   "+%d ms" % rec["cancel_sent_ms"] if rec["cancel_sent_ms"] is not None else "never",
                   rec["final"], rec["bucket"], ": " + rec["problem"] if rec["problem"] else ""))
        run.pull_pcap("call-%02d" % (i + 1))
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
         about="row X4: test UA 6101 -> the designated far end through the anchor, CANCELled "
               "0.6-1.4 s after the INVITE; 6104 holds the S1 pin and detects phantoms",
         uas={"caller": "6101", "detector": PIN_UA}, calls=30, cancel_ms=(600, 1400),
         call_cap_s=30, gap_s=12.0, path_counter="rx554_window", ring_required=True,
         judge=x4_judge)(x4_run)


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
    ap.add_argument("--expect-version", default=None, help="the /api/status version the run must see")
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
        far, src = load_far_end(env)
        red.add(far)
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
        problems += far_end_problems(far, owner)
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
    emit("  far end   %s (never printed)" % ("from " + {"file": FAR_END_FILE_ENV, "env": FAR_END_ENV}[src]
                                             if src else "<not set>"))
    emit("  calls     %d, each <= %d s; counter %s (INVALID if 0)" % (sc["calls"], sc["call_cap_s"],
                                                                     sc["path_counter"]))
    emit("  approval  %s" % (args.approval_url or "<none>"))
    emit("  CHECK-OUT %s until %s" % (args.checkout_url or "<none>", args.checkout_expiry or "<none>"))
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
    factory = agent_factory or (lambda ext: sip_agent.Agent(
        ext, args.host, args.port, local_ip=args.local_ip, strict_dialogs=True, reject_invites=486))
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
