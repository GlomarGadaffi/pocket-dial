#!/usr/bin/env python3
"""The #401 release smoke / soak orchestrator (item 0.2). Entry point: run_soak.sh.

One code path, three profiles:
  post-ota  10 min, after every deploy; verdict thresholds scale with --duration
  smoke     1 h, the rc.1 gate: soak_verdict.py --min-hours 1
  soak      4.5 h, #401 box 2: soak_verdict.py --min-hours 4
A shorter --duration never weakens smoke or soak: their verdict keeps its
min-hours, so a shortened smoke fails on `duration`.

The run, in order:
  refusals    (exit 2, nothing done) the candidate checkout's stamp (the rule of
              tools/ci/check_app_version.py: `git describe --tags --always --dirty`,
              or <hash>[-dirty] past 31 chars) is dirty; the image's sha256 is not
              --image-sha256; the image does not carry this checkout's stamp; the rig
              lease is not held by --holder (rig_checkout.sh status); the #428
              CHECK-OUT link is malformed or its expiry does not cover the run; without
              --ota, the board does not already run the stamp.
  preflight   The board must report coredump supported and empty, a benign
              resetReason and pendingVerify false. Any failure is INVALID and blocks
              the OTA. The OTA path (--ota, or a board already on the candidate) NEVER
              opens the serial port: remote_ota.sh's own checks and the proven
              bootloader rollback are its safety net, and the skipped backup is
              recorded as a waiver. Only the full-flash path (--full-flash) reads nvs
              and coredump over serial first (each twice, sha256s compared), then
              leaves the ROM loader with --boot-cmd (default: esptool --after
              hard_reset chip_id), always on the stable by-id port RIG_SERIAL.
  ota         (--ota) tools/ota/remote_ota.sh stage 3; credentials only through the
              inherited environment (PD_OTA_USER / PD_OTA_PASS), never an argv.
  version     /api/status version must equal the stamp (INVALID otherwise). The heap
              baseline is taken here, after the last reset.
  logger      tools/soak/status_logger.sh starts BEFORE the load.
  load        tests/load/sip_stress.py --profile rc1, for --duration plus its quiesce.
  watch       the logger's own JSONL is tailed (no second poller, #534): an uptime
              regression or a resetReason change stops the load first, captures
              /api/status (with its coredump present/size), stops the logger: FAIL.
              The raw dump is owner-gated (GET /api/coredump) and serial is never
              opened here, so it is marked unavailable for a human to fetch. 30 s
              with no good sample does the same once the board answers again; 5 min
              with none gets ONE /usr/sbin/uhubctl cycle of the pinned port (it needs
              root and may fail), then NEEDS-HUMAN. No retries. A dead or stalled
              logger is INVALID (a harness fault).
  post-roll   the logger keeps running >= 60 s after the load stops.
  verdict     the version is rechecked, then soak_verdict.py judges the log.
  evidence    soak-<ts>/ and soak-<ts>.tar.gz: manifest (stamp, commit, tree, dirty
              flag, image sha256s, versions at start and end, tool versions and
              script sha256s), preflight, backups, load JSON, status log, verdict,
              SHA256SUMS.
  check-in    ALWAYS (also on SIGINT/SIGTERM): rig_checkout.sh release --verdict ...
              writes the CHECK-IN post; posting it stays a separate explicit step.

Exit status: 0 PASS, 1 FAIL, 2 refused before anything ran, 3 INVALID (the run
cannot judge the candidate), 4 ABORTED (signal), 5 NEEDS-HUMAN.
--dry-run prints every command and executes none. stdlib only.
"""
import argparse
import datetime
import hashlib
import json
import os
import re
import shlex
import signal
import subprocess
import sys
import tarfile
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
TOOLS_ROOT = os.path.normpath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, os.path.join(TOOLS_ROOT, "tools", "ci"))
import check_app_version as gate  # noqa: E402

EXIT = {"PASS": 0, "FAIL": 1, "INVALID": 3, "ABORTED": 4, "NEEDS-HUMAN": 5}
REFUSED = 2
# The rig's serial port, by its stable by-id name (never /dev/ttyACMn, which
# moves between boots). Opening it resets the board. The other board on glolab,
# the LilyGO DNS box (E0:72:A1:CC:1C:04), is never touched.
RIG_SERIAL = "/dev/serial/by-id/usb-Espressif_USB_JTAG_serial_debug_unit_28:84:85:4A:24:68-if00"
NEVER_SERIAL = ("E0:72:A1:CC:1C:04",)
UHUBCTL = "/usr/sbin/uhubctl"     # not on claude-agent's PATH; needs root, so a cycle may fail
BENIGN_RESETS = {"POWERON", "SW_RESTART", "USB", "EXT_PIN"}
LOAD_PROFILE = "rc1"
LOAD_QUIESCE_S = 210          # tests/load/load_profile.py's rc1 quiesce_s
CHECKOUT_URL_RX = re.compile(
    r"^https://github\.com/GlomarGadaffi/pocket-dial/discussions/428#discussioncomment-[0-9]+$")
# 16 MB layout, partitions.csv
NVS = ("nvs", 0x9000, 0x6000)
COREDUMP = ("coredump", 0xC20000, 0x20000)

PROFILES = {
    "post-ota": {"duration_s": 600, "min_hours": None, "warmup_s": 60, "preroll_s": 30, "postroll_s": 90},
    "smoke": {"duration_s": 3600, "min_hours": 1.0, "warmup_s": 900, "preroll_s": 60, "postroll_s": 90},
    "soak": {"duration_s": 16200, "min_hours": 4.0, "warmup_s": 900, "preroll_s": 60, "postroll_s": 90},
}
SILENCE_S = 30
UNREACHABLE_S = 300
AFTER_CYCLE_S = 120
LOAD_STOP_GRACE_S = 90
BOOT_WAIT_S = 300
PREFLIGHT_BUDGET_S = 900      # backups + boot + OTA, for the CHECK-OUT expiry check
END_BUDGET_S = 600


class Abort(Exception):
    def __init__(self, verdict, reason):
        super().__init__(reason)
        self.verdict = verdict
        self.reason = reason


# ---------------------------------------------------------------- plumbing
def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def parse_iso(text):
    s = (text or "").strip()
    if s[-1:] in ("Z", "z"):
        s = s[:-1] + "+00:00"
    try:
        dt = datetime.datetime.fromisoformat(s)
    except ValueError:
        return None
    return None if dt.tzinfo is None else dt.timestamp()


def http_json(url, timeout=3.0):
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            body = json.loads(r.read().decode("utf-8", "replace"))
            return body if isinstance(body, dict) else None
    except Exception:  # noqa: BLE001 -- unreachable reads as "no answer"
        return None


class RealClock:
    def now(self):
        return time.monotonic()

    def wall(self):
        return time.time()

    def sleep(self, s):
        time.sleep(s)


class RealRunner:
    """Runs commands for real. start() puts each child in its own session, so a
    terminal Ctrl-C reaches only this orchestrator and the stop order stays ours."""

    def run(self, argv, out_path=None, timeout=None):
        if out_path:
            with open(out_path, "ab") as f:
                return subprocess.run(argv, stdout=f, stderr=subprocess.STDOUT, timeout=timeout).returncode
        return subprocess.run(argv, timeout=timeout).returncode

    def capture(self, argv, timeout=60):
        try:
            p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
            return p.returncode, p.stdout + p.stderr
        except (OSError, subprocess.TimeoutExpired) as e:
            return 127, str(e)

    def start(self, argv, out_path):
        f = open(out_path, "ab")
        try:
            return subprocess.Popen(argv, stdout=f, stderr=subprocess.STDOUT, start_new_session=True)
        finally:
            f.close()


class Watch:
    """Tails status_logger.sh's JSONL: reboot, reset-reason change, silence, stall."""

    def __init__(self, path):
        self.path = path
        self.offset = 0
        self.buf = ""
        self.last_line_wall = None
        self.last_good = None
        self.last_uptime = None
        self.reason = None
        self.lines = 0

    def poll(self, now_wall, started_wall):
        try:
            with open(self.path, encoding="utf-8", errors="replace") as f:
                f.seek(self.offset)
                chunk = f.read()
                self.offset = f.tell()
        except OSError:
            chunk = ""
        self.buf += chunk
        *complete, self.buf = self.buf.split("\n")
        for line in complete:
            line = line.strip()
            if not line:
                continue
            self.lines += 1
            self.last_line_wall = now_wall
            try:
                rec = json.loads(line)
            except ValueError:
                continue
            s = rec.get("s") if isinstance(rec, dict) else None
            if not isinstance(s, dict) or not isinstance(s.get("uptime"), (int, float)):
                continue
            up, rr = s["uptime"], s.get("resetReason")
            if self.last_uptime is not None and up < self.last_uptime:
                return ("reboot", "uptime went %s -> %s (resetReason %s)" % (self.last_uptime, up, rr))
            if self.reason is not None and rr is not None and rr != self.reason:
                return ("reset-reason", "resetReason changed %s -> %s" % (self.reason, rr))
            self.last_uptime = up
            self.reason = rr if rr is not None else self.reason
            self.last_good = now_wall
        if now_wall - (self.last_line_wall or started_wall) >= SILENCE_S:
            return ("stalled", "the status logger wrote nothing for %d s" % SILENCE_S)
        if now_wall - (self.last_good or started_wall) >= SILENCE_S:
            return ("silence", "no good /api/status sample for %d s" % SILENCE_S)
        return None


# ---------------------------------------------------------------- the run
class Run:
    def __init__(self, args, runner, clock, http_get, out):
        self.a = args
        self.runner = runner
        self.clock = clock
        self.http_get = http_get
        self.say_raw = out
        self.prof = dict(PROFILES[args.profile])
        self.duration = args.duration if args.duration is not None else self.prof["duration_s"]
        if self.prof["min_hours"] is None:          # post-ota scales with its own window
            self.min_hours = round(self.duration / 3600.0, 4)
            self.warmup = min(self.prof["warmup_s"], self.duration // 5)
        else:
            self.min_hours = self.prof["min_hours"]
            self.warmup = self.prof["warmup_s"]
        self.flash_backup = args.full_flash and not args.skip_flash_backup
        self.repo = os.path.abspath(args.repo)
        self.tools = {
            "logger": os.environ.get("PD_SOAK_LOGGER", os.path.join(TOOLS_ROOT, "tools/soak/status_logger.sh")),
            "verdict": os.environ.get("PD_SOAK_VERDICT", os.path.join(TOOLS_ROOT, "tools/soak/soak_verdict.py")),
            "load": os.environ.get("PD_SOAK_LOAD", os.path.join(TOOLS_ROOT, "tests/load/sip_stress.py")),
            "ota": os.environ.get("PD_SOAK_OTA", os.path.join(TOOLS_ROOT, "tools/ota/remote_ota.sh")),
            "rig": os.environ.get("PD_SOAK_RIG_CHECKOUT", os.path.join(TOOLS_ROOT, "tools/soak/rig_checkout.sh")),
            "esptool": os.environ.get("PD_SOAK_ESPTOOL", "esptool.py"),
            "uhubctl": os.environ.get("PD_SOAK_UHUBCTL", UHUBCTL),
        }
        self.ts = datetime.datetime.fromtimestamp(clock.wall(), datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        self.dir = os.path.join(os.path.abspath(args.out), "soak-" + self.ts)
        self.stamp = None
        self.manifest = {"profile": args.profile, "duration_s": self.duration,
                         "verdict_min_hours": self.min_hours, "verdict_warmup_s": self.warmup,
                         "host": args.host, "holder": args.holder, "notes": [], "waivers": [],
                         "uhubctl_cycles": [], "commands": []}
        self.logger = None
        self.load = None
        self.stop_requested = False
        self.log_lines = []
        self.expected_regs = None

    # -- output / commands -------------------------------------------------
    def say(self, text):
        line = "[%s] %s" % (datetime.datetime.fromtimestamp(self.clock.wall(), datetime.timezone.utc)
                            .strftime("%H:%M:%S"), text)
        self.log_lines.append(line)
        self.say_raw(line)

    def p(self, name):
        return os.path.join(self.dir, name)

    def url(self, path):
        return "http://%s%s" % (self.a.host, path)

    def status(self):
        return self.http_get(self.url("/api/status"))

    def cmd_logger(self):
        return [self.tools["logger"], self.a.host, self.p("status.jsonl")]

    def cmd_load(self):
        return ["python3", self.tools["load"], "--profile", LOAD_PROFILE, "--host", self.a.host.split(":")[0],
                "--port", str(self.a.sip_port), "--status-url", self.url("/api/status"),
                "--exts", self.a.exts, "--owner-ext", self.a.owner_ext, "--duration", str(self.duration),
                "--report", self.p("load.json"), "--checkout-url", self.a.checkout_url,
                "--checkout-expiry", self.a.checkout_expiry]

    def cmd_verdict(self, regs=None):
        c = ["python3", self.tools["verdict"], self.p("status.jsonl"), "--min-hours", str(self.min_hours),
             "--warmup-s", str(self.warmup), "--load-report", self.p("load.json")]
        regs = regs if regs is not None else self.expected_regs
        if regs is not None:
            c += ["--expect-registrations", str(regs)]
        c.append("--json")
        return c + (["--allow-no-coredump"] if self.a.allow_no_coredump else [])

    def cmd_read_flash(self, part, offset, size, out):
        return [self.tools["esptool"], "--port", self.a.serial_port, "--after", "no_reset",
                "read_flash", hex(offset), hex(size), out]

    def cmd_boot(self):
        if self.a.boot_cmd:
            return shlex.split(self.a.boot_cmd)
        return [self.tools["esptool"], "--port", self.a.serial_port, "--after", "hard_reset", "chip_id"]

    def cmd_ota(self):
        return [self.tools["ota"], "--host", self.a.host, "--stage", "3", "--image", self.a.image or "<image>",
                "--expect-version", self.stamp or "<stamp>"]

    def cmd_uhubctl(self):
        return [self.tools["uhubctl"], "-l", self.a.uhubctl_loc or "<hub>", "-p", self.a.uhubctl_port or "<port>",
                "-a", "cycle"]

    def cmd_release(self, verdict, evidence, note):
        return [self.tools["rig"], "release", "--holder", self.a.holder, "--verdict", verdict,
                "--evidence", evidence, "--note", note[:300]]

    def runc(self, argv, out_name=None, timeout=None):
        self.manifest["commands"].append(argv)
        self.say("+ " + " ".join(shlex.quote(x) for x in argv))
        return self.runner.run(argv, out_path=self.p(out_name) if out_name else None, timeout=timeout)

    def check_stop(self):
        if self.stop_requested:
            raise Abort("ABORTED", "interrupted by a signal")

    def sleep(self, s):
        end = self.clock.now() + s
        while self.clock.now() < end:
            self.check_stop()
            self.clock.sleep(min(1.0, end - self.clock.now()))

    def wait_status(self, limit_s, why):
        end = self.clock.now() + limit_s
        while True:
            st = self.status()
            if st is not None and isinstance(st.get("uptime"), (int, float)):
                return st
            if self.clock.now() >= end:
                raise Abort("INVALID", "%s: no /api/status answer within %d s" % (why, limit_s))
            self.sleep(2)

    # -- phases ------------------------------------------------------------
    def flash_backups(self):
        if not self.flash_backup:
            why = ("--skip-flash-backup" if self.a.full_flash else
                   "the OTA path never opens serial; remote_ota.sh's checks and the bootloader "
                   "rollback are its safety net")
            self.manifest["waivers"].append("no raw nvs/coredump backup (%s)" % why)
            self.say("flash backup waived (%s)" % why)
            return
        out = {}
        for name, off, size in (NVS, COREDUMP):
            shas = []
            for n in (1, 2):
                path = self.p("%s-%d.bin" % (name, n))
                rc = self.runc(self.cmd_read_flash(name, off, size, path), out_name="esptool.log", timeout=900)
                if rc != 0 or not os.path.exists(path):
                    raise Abort("INVALID", "preflight: read_flash %s failed (rc %s): OTA blocked" % (name, rc))
                shas.append(sha256_file(path))
            if shas[0] != shas[1]:
                raise Abort("INVALID", "preflight: two reads of %s differ: OTA blocked" % name)
            out[name] = {"offset": hex(off), "size": hex(size), "sha256": shas[0]}
        self.manifest["flash_backup"] = out
        rc = self.runc(self.cmd_boot(), out_name="boot.log", timeout=120)   # leave the ROM loader
        if rc != 0:
            self.manifest["notes"].append("the boot command after the backup returned %s" % rc)

    def preflight(self):
        st = self.wait_status(BOOT_WAIT_S, "preflight")
        ota = self.http_get(self.url("/api/ota/status")) or {}
        cd = st.get("coredump") if isinstance(st.get("coredump"), dict) else {}
        problems = []
        if cd.get("supported") is False and not self.a.allow_no_coredump:
            problems.append("the board has no coredump partition (pass --allow-no-coredump to accept)")
        if cd.get("present") is True:
            problems.append("a coredump is already present (size %s): read and erase it first" % cd.get("size"))
        if not cd:
            problems.append("/api/status has no coredump object")
        if st.get("resetReason") not in BENIGN_RESETS:
            problems.append("resetReason %r is not benign (%s)" % (st.get("resetReason"), ", ".join(sorted(BENIGN_RESETS))))
        if ota.get("pendingVerify") is not False:
            problems.append("/api/ota/status pendingVerify is %r, not false" % ota.get("pendingVerify"))
        self.manifest["preflight"] = {"status": st, "ota_status": ota, "problems": problems}
        if problems:
            raise Abort("INVALID", "preflight: " + "; ".join(problems) + ": OTA blocked")

    def ota_and_version(self):
        if self.a.ota:
            rc = self.runc(self.cmd_ota(), out_name="ota.log", timeout=1800)
            if rc != 0:
                raise Abort("FAIL", "remote_ota.sh stage 3 stopped (rc %s, see ota.log)" % rc)
        st = self.wait_status(BOOT_WAIT_S, "after the OTA" if self.a.ota else "version check")
        self.manifest["version_at_start"] = st.get("version")
        if st.get("version") != self.stamp:
            raise Abort("INVALID", "the board runs %r, the candidate is %r" % (st.get("version"), self.stamp))
        self.manifest["baseline"] = {k: st.get(k) for k in sorted(st) if k.startswith(("uptime", "resetReason", "freeHeap",
                                     "minFreeHeap", "largestFreeBlock", "clientCount", "sessionCount",
                                     "parkedCount", "msgPool", "stackHwm_"))}
        self.say("baseline after the last reset: uptime %s s, freeHeapInternal %s"
                 % (st.get("uptime"), st.get("freeHeapInternal")))
        # Phones already registered on the rig stay registered through the quiesce,
        # so the leak gate expects them plus the load's test UAs. A device that
        # registers or drops DURING the run still changes the count and fails it:
        # that is a rig-isolation fault, and it stays visible.
        uas = len([e for e in self.a.exts.split(",") if e.strip()])
        before = st.get("clientCount")
        if isinstance(before, int) and not isinstance(before, bool):
            self.expected_regs = before + uas
            self.manifest["expected_registrations"] = self.expected_regs
            self.manifest["expected_registrations_from"] = {"on_rig_before_load": before, "test_uas": uas}
            self.say("expected registrations at quiesce: %d (%d on the rig before the load + %d test UAs)"
                     % (self.expected_regs, before, uas))
        else:
            self.manifest["notes"].append("preflight /api/status had no clientCount: the verdict expects "
                                          "the load report's test UAs at quiesce")

    def start_logger(self):
        self.manifest["commands"].append(self.cmd_logger())
        self.say("+ " + " ".join(self.cmd_logger()) + " &")
        self.logger = self.runner.start(self.cmd_logger(), self.p("logger.log"))
        self.logger_started = self.clock.wall()

    def stop_proc(self, proc, grace):
        if proc is None or proc.poll() is not None:
            return
        proc.terminate()
        end = self.clock.now() + grace
        while proc.poll() is None and self.clock.now() < end:
            self.clock.sleep(1)
        if proc.poll() is None:
            proc.kill()

    def stop_load(self):
        if self.load is not None and self.load.poll() is None:
            self.say("stopping the load first (SIGTERM: it hangs up and de-registers)")
        self.stop_proc(self.load, LOAD_STOP_GRACE_S)

    def stop_logger(self):
        if self.logger is not None and self.logger.poll() is None:
            self.say("stopping the status logger")
        self.stop_proc(self.logger, 5)

    def capture_after_abort(self):
        """Status (with its coredump present/size), then stop the logger. Never serial:
        the raw dump is owner-gated (GET /api/coredump), so it is marked unavailable."""
        st = self.status()
        if st is not None:
            with open(self.p("abort-status.json"), "w", encoding="utf-8") as f:
                json.dump(st, f, indent=1)
        cd = (st or {}).get("coredump")
        self.manifest["coredump_after_abort"] = {
            "status": cd if isinstance(cd, dict) else None,
            "raw": "unavailable: GET /api/coredump needs an owner login and this run never opens "
                   "serial; fetch it by hand"}
        self.stop_logger()
        return st

    def wait_good_sample(self, watch, limit_s):
        end = self.clock.now() + limit_s
        while self.clock.now() < end:
            ev = watch.poll(self.clock.wall(), self.logger_started)
            if ev and ev[0] in ("reboot", "reset-reason"):
                return ev
            if watch.last_good is not None and self.clock.wall() - watch.last_good < 2:
                return ("back", "")
            self.clock.sleep(1)
        return None

    def on_board_event(self, ev, watch):
        kind, detail = ev
        self.say("ABORT: " + detail)
        self.stop_load()
        if kind == "silence":
            back = self.wait_good_sample(watch, UNREACHABLE_S - SILENCE_S)
            if back is None:
                if self.a.uhubctl_loc and self.a.uhubctl_port:
                    self.manifest["uhubctl_cycles"].append(self.clock.wall())
                    self.say("unreachable for %d s: ONE power cycle of the pinned port" % UNREACHABLE_S)
                    rc = self.runc(self.cmd_uhubctl(), out_name="uhubctl.log", timeout=60)
                    if rc != 0:
                        note = "the uhubctl cycle failed (rc %s; it needs root)" % rc
                    else:
                        came = self.wait_good_sample(watch, AFTER_CYCLE_S) is not None
                        note = "came back after the cycle" if came else "did not come back after the cycle"
                else:
                    note = "no pinned uhubctl port configured, so no cycle"
                self.capture_after_abort()
                raise Abort("NEEDS-HUMAN", "%s; unreachable for %d s; %s" % (detail, UNREACHABLE_S, note))
            detail += "; the board answered again"
        self.capture_after_abort()
        raise Abort("FAIL", detail)

    def run_load(self):
        self.manifest["commands"].append(self.cmd_load())
        self.say("+ " + " ".join(shlex.quote(x) for x in self.cmd_load()) + " &")
        self.load = self.runner.start(self.cmd_load(), self.p("load.log"))
        watch = Watch(self.p("status.jsonl"))
        limit = self.duration + LOAD_QUIESCE_S + 300
        started = self.clock.now()
        while True:
            self.check_stop()
            if self.load.poll() is not None:
                break
            if self.logger.poll() is not None:
                raise Abort("INVALID", "the status logger exited during the load")
            ev = watch.poll(self.clock.wall(), self.logger_started)
            if ev and ev[0] == "stalled":
                raise Abort("INVALID", ev[1])
            if ev:
                self.on_board_event(ev, watch)
            if self.clock.now() - started > limit:
                raise Abort("INVALID", "the load overran its window by 300 s")
            self.clock.sleep(1)
        self.manifest["load_exit"] = self.load.returncode
        self.say("load finished (exit %s); post-roll %d s" % (self.load.returncode, self.prof["postroll_s"]))
        end = self.clock.now() + self.prof["postroll_s"]
        while self.clock.now() < end:
            self.check_stop()
            ev = watch.poll(self.clock.wall(), self.logger_started)
            if ev and ev[0] in ("reboot", "reset-reason", "silence"):
                self.on_board_event(ev, watch)
            self.clock.sleep(1)
        self.stop_logger()

    def judge(self):
        st = self.status() or {}
        self.manifest["version_at_end"] = st.get("version")
        rc = self.runc(self.cmd_verdict(), out_name="verdict.json", timeout=600)
        verdict = {0: "PASS", 1: "FAIL"}.get(rc, "INVALID")
        if st.get("version") != self.stamp:
            self.manifest["notes"].append("version at the end %r is not the candidate %r"
                                          % (st.get("version"), self.stamp))
            verdict = "FAIL" if verdict == "PASS" else verdict
        if self.manifest.get("load_exit") not in (0, None):
            self.manifest["notes"].append("the load reported failures (exit %s, see load.json)"
                                          % self.manifest["load_exit"])
            verdict = "FAIL" if verdict == "PASS" else verdict
        return verdict

    def execute(self):
        os.makedirs(self.dir, exist_ok=True)
        self.flash_backups()
        self.preflight()
        self.ota_and_version()
        self.start_logger()
        self.sleep(self.prof["preroll_s"])
        self.run_load()
        return self.judge()

    # -- always ------------------------------------------------------------
    def cleanup(self):
        self.stop_load()
        self.stop_logger()

    def tool_versions(self):
        out = {"python": sys.version.split()[0]}
        rc, text = self.runner.capture(["git", "--version"])
        out["git"] = text.strip() if rc == 0 else None
        scripts = {}
        for name, path in self.tools.items():
            if os.path.isfile(path):
                scripts[name] = {"path": path, "sha256": sha256_file(path)}
        lp = os.path.join(os.path.dirname(self.tools["load"]), "load_profile.py")
        if os.path.isfile(lp):
            scripts["load_profile"] = {"path": lp, "sha256": sha256_file(lp)}
        scripts["run_soak"] = {"path": __file__, "sha256": sha256_file(__file__)}
        out["scripts"] = scripts
        return out

    def bundle(self, verdict, reason):
        os.makedirs(self.dir, exist_ok=True)
        self.manifest.update({"verdict": verdict, "exit_code": EXIT[verdict], "reason": reason,
                              "finished_at": self.clock.wall(), "tools": self.tool_versions()})
        with open(self.p("manifest.json"), "w", encoding="utf-8") as f:
            json.dump(self.manifest, f, indent=1, sort_keys=True)
        with open(self.p("run.log"), "w", encoding="utf-8") as f:
            f.write("\n".join(self.log_lines) + "\n")
        names = sorted(n for n in os.listdir(self.dir) if n != "SHA256SUMS")
        with open(self.p("SHA256SUMS"), "w", encoding="utf-8") as f:
            for n in names:
                f.write("%s  %s\n" % (sha256_file(self.p(n)), n))
        tar = self.dir + ".tar.gz"
        with tarfile.open(tar, "w:gz") as t:
            t.add(self.dir, arcname=os.path.basename(self.dir))
        return tar

    def release(self, verdict, evidence, reason):
        argv = self.cmd_release(verdict, evidence, reason)
        self.say("+ " + " ".join(shlex.quote(x) for x in argv))
        rc, text = self.runner.capture(argv, timeout=120)
        for line in text.splitlines():
            self.say("  " + line)
        if rc != 0:
            self.say("NO CHECK-IN WAS WRITTEN (rc %s). Release by hand: %s"
                     % (rc, " ".join(shlex.quote(x) for x in argv)))
        return rc == 0


# ---------------------------------------------------------------- refusals
def refusals(args, run, now_wall):
    problems = []
    try:
        stamp = gate.expected_version(run.repo, gate.read_max_len())
    except gate.GateFailure as e:
        return ["the candidate checkout %s cannot be described: %s" % (run.repo, e)]
    run.stamp = stamp
    if stamp.endswith("-dirty"):
        problems.append("the candidate checkout is dirty (%s): commit or stash first" % stamp)
    for name, rev in (("commit", "HEAD"), ("tree", "HEAD^{tree}")):
        rc, text = run.runner.capture(["git", "-C", run.repo, "rev-parse", rev])
        run.manifest[name] = text.strip() if rc == 0 else None
    run.manifest.update({"stamp": stamp, "dirty": stamp.endswith("-dirty"), "repo": run.repo})
    if not args.image or not os.path.isfile(args.image):
        problems.append("--image must name the candidate's app image")
    else:
        sha = sha256_file(args.image)
        run.manifest["image"] = {"path": os.path.abspath(args.image), "sha256": sha,
                                 "expected_sha256": args.image_sha256}
        if not args.image_sha256 or sha != args.image_sha256.lower():
            problems.append("the image's sha256 %s is not --image-sha256 %s (the build artifact)"
                            % (sha, args.image_sha256 or "<none>"))
        try:
            gate.check(args.image, repo=run.repo)
        except gate.GateFailure as e:
            problems.append("the image does not carry this checkout's stamp: %s" % e)
    port = args.serial_port or ""
    if not port.startswith("/dev/serial/by-id/"):
        problems.append("--serial-port must be a stable /dev/serial/by-id/ path, never /dev/ttyACM*")
    if any(mac in port for mac in NEVER_SERIAL):
        problems.append("--serial-port names the LilyGO DNS board: never touched")
    if args.full_flash and args.ota:
        problems.append("--full-flash and --ota are different install paths: pick one")
    if args.uhubctl_loc and not args.uhubctl_port or args.uhubctl_port and not args.uhubctl_loc:
        problems.append("--uhubctl-loc and --uhubctl-port go together (one pinned port)")
    if not args.checkout_url or not CHECKOUT_URL_RX.match(args.checkout_url):
        problems.append("--checkout-url must be the discussion #428 CHECK-OUT comment link")
    needed = PREFLIGHT_BUDGET_S + run.prof["preroll_s"] + run.duration + LOAD_QUIESCE_S + \
        run.prof["postroll_s"] + END_BUDGET_S
    exp = parse_iso(args.checkout_expiry)
    if exp is None:
        problems.append("--checkout-expiry must be ISO-8601 with a zone")
    elif exp < now_wall + needed:
        problems.append("the CHECK-OUT expires before this run would end (needs %d min from now)"
                        % (needed // 60 + 1))
    for flag in ("exts", "owner_ext"):
        if not getattr(args, flag):
            problems.append("--%s is required (passed to the load generator)" % flag.replace("_", "-"))
    rc, text = run.runner.capture([run.tools["rig"], "status"])
    if rc != 0 or not re.search(r"^pd195: checked out by %s until" % re.escape(args.holder), text, re.M):
        problems.append("the rig lease is not held by %s (rig_checkout.sh status): claim it and post "
                        "the CHECK-OUT first" % args.holder)
    if not args.ota and not problems:
        st = run.status()
        if st is None or st.get("version") != stamp:
            problems.append("the board runs %r, not the candidate %r (pass --ota to install it)"
                            % (st.get("version") if st else None, stamp))
    return problems


def dry_run(run, out):
    a = run.a
    out("run_soak --profile %s  (DRY RUN: nothing is executed)" % a.profile)
    out("  load %d s + %d s quiesce; verdict --min-hours %s --warmup-s %d; evidence %s.tar.gz"
        % (run.duration, LOAD_QUIESCE_S, run.min_hours, run.warmup, run.dir))
    steps = [("refuse", ["git", "-C", run.repo, "describe", "--tags", "--always", "--dirty"]),
             ("refuse", ["sha256sum", a.image or "<image>"]),
             ("refuse", ["# check_app_version.check(%s, repo=%s)" % (a.image or "<image>", run.repo)]),
             ("refuse", [run.tools["rig"], "status"])]
    if not a.ota:
        steps.append(("refuse", ["GET", run.url("/api/status"), "(version == <stamp>)"]))
    if run.flash_backup:
        for name, off, size in (NVS, COREDUMP):
            for n in (1, 2):
                steps.append(("preflight", run.cmd_read_flash(name, off, size, run.p("%s-%d.bin" % (name, n)))))
        steps.append(("preflight", run.cmd_boot()))
    else:
        steps.append(("preflight", ["# no serial: flash backup waived"]))
    steps += [("preflight", ["GET", run.url("/api/status"), "(coredump empty, benign resetReason)"]),
              ("preflight", ["GET", run.url("/api/ota/status"), "(pendingVerify false)"])]
    if a.ota:
        steps.append(("ota", run.cmd_ota()))
    steps += [("version", ["GET", run.url("/api/status"), "(version == <stamp>; heap baseline)"]),
              ("logger", run.cmd_logger() + ["&"]),
              ("load", run.cmd_load() + ["&"]),
              ("abort only", run.cmd_uhubctl()),
              ("verdict", run.cmd_verdict(regs="<clientCount-before-the-load+test-UAs>")),
              ("check-in", run.cmd_release("<verdict>", run.dir + ".tar.gz", "<reason>"))]
    for phase, argv in steps:
        out("  %-10s %s" % (phase, " ".join(shlex.quote(x) if not x.startswith("<") else x for x in argv)))
    return 0


def build_parser():
    ap = argparse.ArgumentParser(prog="run_soak.sh", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--profile", required=True, choices=sorted(PROFILES))
    ap.add_argument("--host", required=True, help="the rig's address (host or host:http-port)")
    ap.add_argument("--sip-port", type=int, default=5060)
    ap.add_argument("--holder", required=True, help="who holds the rig lease (rig_checkout.sh claim)")
    ap.add_argument("--duration", type=int, default=None, help="load window, seconds")
    ap.add_argument("--repo", default=TOOLS_ROOT, help="the candidate's checkout (default: this one)")
    ap.add_argument("--image", default=None, help="the candidate's app image")
    ap.add_argument("--image-sha256", default=None, help="the build artifact's sha256")
    ap.add_argument("--ota", action="store_true", help="install --image with remote_ota.sh stage 3 first")
    ap.add_argument("--checkout-url", default=None)
    ap.add_argument("--checkout-expiry", default=None)
    ap.add_argument("--exts", default="", help="the 4 test UAs (passed to the load)")
    ap.add_argument("--owner-ext", default="", help="the owner's extensions (passed to the load)")
    ap.add_argument("--full-flash", action="store_true",
                    help="the full-flash (non-OTA) path: back up nvs and coredump over serial first")
    ap.add_argument("--serial-port", default=RIG_SERIAL, help="by-id path only (default: the rig's)")
    ap.add_argument("--skip-flash-backup", action="store_true", help="recorded as a waiver")
    ap.add_argument("--boot-cmd", default=None,
                    help="leaves the ROM loader after the backup (default: esptool --after hard_reset chip_id)")
    ap.add_argument("--uhubctl-loc", default=None)
    ap.add_argument("--uhubctl-port", default=None)
    ap.add_argument("--allow-no-coredump", action="store_true")
    ap.add_argument("--out", default="soak-evidence")
    ap.add_argument("--dry-run", action="store_true")
    return ap


def main(argv=None, runner=None, clock=None, http_get=None, out=print):
    args = build_parser().parse_args(argv)
    run = Run(args, runner or RealRunner(), clock or RealClock(), http_get or http_json, out)
    if args.dry_run:
        return dry_run(run, out)
    problems = refusals(args, run, run.clock.wall())
    if problems:
        for p in problems:
            out("REFUSED: " + p)
        out("nothing was run; the lease is untouched")
        return REFUSED

    def on_signal(signum, frame):
        run.stop_requested = True
    old = {}
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            old[sig] = signal.signal(sig, on_signal)
        except ValueError:
            pass
    verdict, reason = "INVALID", ""
    try:
        verdict = run.execute()
        reason = "; ".join(run.manifest["notes"]) or "completed"
    except Abort as e:
        verdict, reason = e.verdict, e.reason
        run.say("%s: %s" % (verdict, reason))
    except Exception as e:  # noqa: BLE001 -- a harness fault still ends in a bundle and a check-in
        verdict, reason = "INVALID", "harness exception: %r" % (e,)
        run.say(reason)
    finally:
        run.cleanup()
        tar = run.bundle(verdict, reason)
        run.say("evidence: %s" % tar)
        run.release(verdict, os.path.basename(tar), reason)
        for sig, h in old.items():
            signal.signal(sig, h)
    out("SOAK RUN: %s (exit %d)" % (verdict, EXIT[verdict]))
    return EXIT[verdict]


if __name__ == "__main__":
    sys.exit(main())
