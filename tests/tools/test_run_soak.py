#!/usr/bin/env python3
"""Self-test for tools/soak/run_soak.py (#401 item 0.2). Runs in CI:

    python3 -m unittest discover -s tests/tools -p 'test_run_soak.py'

Everything runs against fakes with a fake clock: a fake board behind an
injected /api/status, a fake status logger and a fake load driven by the
clock, and recording stand-ins for esptool, uhubctl, remote_ota.sh and
rig_checkout.sh. The real soak_verdict.py judges the fake log, and the real
check_app_version.py rules judge a throwaway git repository and a synthetic
image. No board, no network, no hardware.
"""
import hashlib
import json
import os
import shutil
import signal
import struct
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "tools", "soak"))
sys.path.insert(0, os.path.join(ROOT, "tools", "ci"))
import check_app_version as gate  # noqa: E402
import run_soak as rs  # noqa: E402

VERDICT = os.path.join(ROOT, "tools", "soak", "soak_verdict.py")
CHECKOUT = "https://github.com/GlomarGadaffi/pocket-dial/discussions/428#discussioncomment-1"
FAKE_SECRET = "correct-horse-battery"


def git(repo, *args):
    env = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@t",
               GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@t")
    return subprocess.run(["git", "-C", repo, *args], check=True, text=True,
                          capture_output=True, env=env).stdout.strip()


def make_image(path, version):
    img = bytearray(512)
    img[0] = gate.IMAGE_MAGIC
    struct.pack_into("<I", img, gate.APP_DESC_OFFSET, gate.APP_DESC_MAGIC)
    raw = version.encode("ascii")
    img[gate.APP_DESC_OFFSET + 16:gate.APP_DESC_OFFSET + 16 + len(raw)] = raw
    with open(path, "wb") as f:
        f.write(img)


class FakeClock:
    def __init__(self):
        self.t = 0.0
        self.base = float(int(time.time()))
        self.listeners = []

    def now(self):
        return self.t

    def wall(self):
        return self.base + self.t

    def sleep(self, s):
        target = self.t + s
        while self.t < target - 1e-9:
            self.t += min(1.0, target - self.t)
            for fn in list(self.listeners):
                fn()


class FakeBoard:
    def __init__(self, clock, version):
        self.clock = clock
        self.version = version
        self.boot_wall = clock.wall() - 1000
        self.reason = "POWERON"
        self.coredump = {"supported": True, "present": False, "size": 0}
        self.pending = False
        self.down = []            # [(from_wall, until_wall)]
        self.busy = False
        self.hits = 0
        self.phones = 0           # devices registered on the rig before the load
        self.test_uas = 0         # the load's own registrations

    def up(self):
        w = self.clock.wall()
        return not any(a <= w < b for a, b in self.down)

    def status(self):
        if not self.up():
            return None
        busy = self.busy
        return {"version": self.version, "uptime": int(self.clock.wall() - self.boot_wall),
                "resetReason": self.reason, "freeHeapInternal": 120000, "minFreeHeapInternal": 60000,
                "largestFreeBlockInternal": 40000, "clientCount": self.phones + self.test_uas,
                "recvErrors": 0, "sessions": [],
                "sessionCount": 1 if busy else 0, "oldestSessionSec": 5 if busy else 0,
                "parkedCount": 0, "parkedCalls": [], "stackHwm_sip_server_task": 1500,
                "coredump": dict(self.coredump)}

    def reboot(self, reason, core=True):
        self.boot_wall = self.clock.wall()
        self.reason = reason
        if core:
            self.coredump = {"supported": True, "present": True, "size": 47264}

    def http_get(self, url):
        self.hits += 1
        if not self.up():
            return None
        if url.endswith("/api/ota/status"):
            return {"pendingVerify": self.pending, "running": "ota_0", "boot": "ota_0"}
        return self.status()


class FakeProc:
    def __init__(self, world, name):
        self.world, self.name, self.returncode = world, name, None

    def poll(self):
        return self.returncode

    def terminate(self):
        if self.returncode is None:
            self.world.events.append(("terminate", self.name, self.world.clock.wall()))
            self.returncode = -15

    def kill(self):
        self.terminate()


class FakeLogger(FakeProc):
    def __init__(self, world, path):
        super().__init__(world, "logger")
        self.path = path
        self.last = None
        self.die_at = world.logger_dies_at

    def tick(self):
        if self.returncode is not None:
            return
        w = int(self.world.clock.wall())
        if self.die_at is not None and w >= self.die_at:
            self.returncode = 1
            return
        if w == self.last:
            return
        self.last = w
        s = self.world.board.status()
        rec = {"t": w, "s": s} if s else {"t": w, "s": None, "code": 0}
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec) + "\n")


class FakeLoad(FakeProc):
    """Registers its test UAs, calls 20 s of every 60 s for --duration, holds the
    registrations through the quiesce, then writes a report shaped like
    sip_stress.py --profile's and de-registers."""

    def __init__(self, world, argv):
        super().__init__(world, "load")
        self.start = world.clock.wall()
        self.duration = int(argv[argv.index("--duration") + 1])
        self.report = argv[argv.index("--report") + 1]
        self.exts = argv[argv.index("--exts") + 1].split(",")
        self.calls = 0
        self.last_call_end = None
        world.board.test_uas = len(self.exts)

    def tick(self):
        if self.returncode is not None:
            self.world.board.busy = False
            return
        el = self.world.clock.wall() - self.start
        if self.world.registers_mid_run_at is not None and int(el) == self.world.registers_mid_run_at:
            self.world.board.phones += 1           # someone's phone joins the rig mid-run
        was = self.world.board.busy
        self.world.board.busy = el < self.duration and (el % 60) < 20
        if self.world.board.busy and not was:
            self.calls += 1
        if was and not self.world.board.busy:
            self.last_call_end = self.world.clock.wall()
        if el >= self.duration + rs.LOAD_QUIESCE_S:
            n = self.calls
            with open(self.report, "w", encoding="utf-8") as f:
                json.dump({"profile": "rc1", "pass": self.world.load_rc == 0, "dry_run": False,
                           "exts": self.exts,
                           "scenarios": {"echo777": {"planned": n, "attempted": n, "ok": n, "failed": 0}},
                           "registrations": {"planned": 4, "attempted": 4, "ok": 4, "failed": 0},
                           "started_at": self.start, "load_end_at": self.start + self.duration,
                           "last_call_end_at": self.last_call_end,
                           "quiesce_check_at": self.start + self.duration + rs.LOAD_QUIESCE_S - 1}, f)
            self.world.events.append(("load-done", "load", self.world.clock.wall()))
            self.world.board.test_uas = 0          # de-registered
            self.returncode = self.world.load_rc

    def terminate(self):
        super().terminate()
        self.world.board.busy = False
        self.world.board.test_uas = 0


class World:
    """The fake rig: clock, board, and a runner that records every command."""

    def __init__(self, version):
        self.clock = FakeClock()
        self.board = FakeBoard(self.clock, version)
        self.calls = []
        self.events = []
        self.procs = {}
        self.logger_dies_at = None
        self.registers_mid_run_at = None
        self.load_rc = 0
        self.differ_second_nvs_read = False
        self.uhubctl_rc = 0
        self.lease_holder = "BigDog"
        self.clock.listeners.append(self.tick)

    def tick(self):
        for p in list(self.procs.values()):
            p.tick()

    # the runner interface
    def run(self, argv, out_path=None, timeout=None):
        self.calls.append(list(argv))
        base = os.path.basename(argv[0])
        if base == "python3" and argv[1].endswith("soak_verdict.py"):
            with open(out_path, "ab") as f:
                return subprocess.run(argv, stdout=f, stderr=subprocess.STDOUT).returncode
        self.events.append(("run", base, self.clock.wall()))
        if base.startswith("esptool"):
            if "read_flash" in argv:
                out = argv[-1]
                body = os.path.basename(out).rsplit("-", 1)[0].encode()    # "nvs", "coredump"
                if self.differ_second_nvs_read and out.endswith("nvs-2.bin"):
                    body += b"!"
                with open(out, "wb") as f:
                    f.write(body)
            return 0
        if base == "uhubctl":
            return self.uhubctl_rc
        if base == "remote_ota.sh":
            self.board.version = argv[argv.index("--expect-version") + 1]
            self.board.reboot("SW_RESTART", core=False)
            return 0
        return 0

    def capture(self, argv, timeout=60):
        self.calls.append(list(argv))
        base = os.path.basename(argv[0])
        if base == "git":
            p = subprocess.run(argv, capture_output=True, text=True)
            return p.returncode, p.stdout + p.stderr
        if base == "rig_checkout.sh" and argv[1] == "status":
            if self.lease_holder:
                return 0, "pd195: checked out by %s until 2099-01-01T00:00Z (rc.1 smoke)\n" % self.lease_holder
            return 0, "pd195: no lease on record\n"
        if base == "rig_checkout.sh" and argv[1] == "release":
            self.events.append(("release", argv[argv.index("--verdict") + 1], self.clock.wall()))
            return 0, "released pd195 glolab\n"
        return 127, "unexpected command"

    def start(self, argv, out_path):
        self.calls.append(list(argv))
        if os.path.basename(argv[0]) == "status_logger.sh":
            p = FakeLogger(self, argv[2])
        else:
            p = FakeLoad(self, argv)
        self.procs[p.name] = p
        self.events.append(("start", p.name, self.clock.wall()))
        return p

    def names(self):
        return [os.path.basename(c[1] if c[0] == "python3" else c[0]) for c in self.calls]

    def touched_serial(self):
        return [c for c in self.calls if any("/dev/" in x for x in c) or
                os.path.basename(c[0]).startswith("esptool")]

    def released(self):
        return [e[1] for e in self.events if e[0] == "release"]


class RunSoakTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="pd401-")
        self.repo = os.path.join(self.tmp, "repo")
        os.makedirs(self.repo)
        git(self.repo, "init", "-q")
        with open(os.path.join(self.repo, "f.txt"), "w") as f:
            f.write("one\n")
        git(self.repo, "add", "f.txt")
        git(self.repo, "commit", "-qm", "one")
        self.stamp = gate.expected_version(self.repo, gate.read_max_len())
        self.image = os.path.join(self.tmp, "SipServer.bin")
        make_image(self.image, self.stamp)
        with open(self.image, "rb") as f:
            self.sha = hashlib.sha256(f.read()).hexdigest()
        self.out = os.path.join(self.tmp, "evidence")
        self.world = World(self.stamp)
        os.environ["PD_SOAK_RIG_CHECKOUT"] = "/fake/rig_checkout.sh"
        os.environ["PD_SOAK_ESPTOOL"] = "/fake/esptool.py"
        os.environ["PD_SOAK_UHUBCTL"] = "/fake/uhubctl"
        os.environ["PD_SOAK_OTA"] = "/fake/remote_ota.sh"
        os.environ["PD_SOAK_LOGGER"] = "/fake/status_logger.sh"

    def tearDown(self):
        for k in ("PD_SOAK_RIG_CHECKOUT", "PD_SOAK_ESPTOOL", "PD_SOAK_UHUBCTL", "PD_SOAK_OTA",
                  "PD_SOAK_LOGGER", "PD_OTA_PASS"):
            os.environ.pop(k, None)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def argv(self, profile="post-ota", duration="300", *extra):
        expiry = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + 6 * 3600))
        return ["--profile", profile, "--duration", duration, "--host", "192.0.2.10",
                "--holder", "BigDog", "--repo", self.repo, "--image", self.image,
                "--image-sha256", self.sha, "--checkout-url", CHECKOUT, "--checkout-expiry", expiry,
                "--exts", "6101,6102,6103,6104", "--owner-ext", "4242", "--out", self.out] + list(extra)

    def go(self, argv, **kw):
        lines = []
        rc = rs.main(argv, runner=self.world, clock=self.world.clock,
                     http_get=self.world.board.http_get, out=lines.append, **kw)
        return rc, "\n".join(lines)

    def bundle(self):
        (tar,) = [n for n in os.listdir(self.out) if n.endswith(".tar.gz")]
        dest = os.path.join(self.tmp, "x")
        with tarfile.open(os.path.join(self.out, tar)) as t:
            if hasattr(tarfile, "data_filter"):
                t.extractall(dest, filter="data")
            else:
                t.extractall(dest)
        (d,) = os.listdir(dest)
        return tar, os.path.join(dest, d)

    def manifest(self, d):
        with open(os.path.join(d, "manifest.json"), encoding="utf-8") as f:
            return json.load(f)

    # ---- done-when -------------------------------------------------------
    def test_a_300_s_run_yields_a_verified_bundle_and_exits_with_the_verdicts_code(self):
        rc, out = self.go(self.argv())
        self.assertEqual(rc, 0, out)
        tar, d = self.bundle()
        self.assertRegex(tar, r"^soak-\d{8}T\d{6}Z\.tar\.gz$")
        with open(os.path.join(d, "SHA256SUMS"), encoding="utf-8") as f:
            sums = [ln.split("  ") for ln in f.read().splitlines()]
        for digest, name in sums:
            with open(os.path.join(d, name), "rb") as g:
                self.assertEqual(hashlib.sha256(g.read()).hexdigest(), digest, name)
        names = {n for _, n in sums}
        self.assertLessEqual({"manifest.json", "status.jsonl", "load.json", "verdict.json", "run.log"}, names)
        m = self.manifest(d)
        self.assertEqual((m["stamp"], m["dirty"], m["verdict"], m["exit_code"]), (self.stamp, False, "PASS", 0))
        self.assertEqual(m["commit"], git(self.repo, "rev-parse", "HEAD"))
        self.assertEqual(m["tree"], git(self.repo, "rev-parse", "HEAD^{tree}"))
        self.assertEqual(m["image"]["sha256"], self.sha)
        self.assertEqual((m["version_at_start"], m["version_at_end"]), (self.stamp, self.stamp))
        self.assertIn("soak_verdict", json.dumps(m["tools"]))
        # the exit code is the verdict's own, on the bundled log
        own = subprocess.run(["python3", VERDICT, os.path.join(d, "status.jsonl"),
                              "--min-hours", str(m["verdict_min_hours"]), "--warmup-s",
                              str(m["verdict_warmup_s"])], capture_output=True, text=True)
        self.assertEqual(own.returncode, rc, own.stdout)
        self.assertEqual(self.world.released(), ["PASS"])

    def verdict_argv(self):
        (v,) = [c for c in self.world.calls if len(c) > 1 and c[1].endswith("soak_verdict.py")]
        return v

    def test_phones_already_on_the_rig_are_expected_at_quiesce(self):
        self.world.board.phones = 2                # two real phones registered before the load
        rc, out = self.go(self.argv())
        self.assertEqual(rc, 0, out)
        v = self.verdict_argv()
        self.assertEqual(v[v.index("--expect-registrations") + 1], "6")
        self.assertTrue(v[v.index("--load-report") + 1].endswith("load.json"))
        self.assertIn("expected registrations at quiesce: 6 (2 on the rig before the load + 4 test UAs)", out)
        tar, d = self.bundle()
        m = self.manifest(d)
        self.assertEqual(m["expected_registrations"], 6)
        self.assertEqual(m["expected_registrations_from"], {"on_rig_before_load": 2, "test_uas": 4})
        with open(os.path.join(d, "verdict.json"), encoding="utf-8") as f:
            q = {c["name"]: c for c in json.load(f)["checks"]}["idle-quiesce"]
        self.assertTrue(q["judged"] and q["ok"], q["detail"])

    def test_a_phone_registering_mid_run_still_fails_naming_the_count(self):
        self.world.board.phones = 2
        self.world.registers_mid_run_at = 100      # a rig-isolation fault: it must stay visible
        rc, out = self.go(self.argv())
        self.assertEqual(rc, 1, out)
        tar, d = self.bundle()
        with open(os.path.join(d, "verdict.json"), encoding="utf-8") as f:
            q = {c["name"]: c for c in json.load(f)["checks"]}["idle-quiesce"]
        self.assertFalse(q["ok"])
        self.assertIn("registrations 7 (want exactly 6)", q["detail"])
        self.assertEqual(self.world.released(), ["FAIL"])

    def test_the_logger_starts_before_the_load_and_stops_60_s_after_it(self):
        rc, out = self.go(self.argv())
        self.assertEqual(rc, 0, out)
        ev = {(k, n): w for k, n, w in self.world.events if k in ("start", "terminate", "load-done")}
        self.assertLess(ev[("start", "logger")], ev[("start", "load")])
        self.assertGreaterEqual(ev[("terminate", "logger")] - ev[("load-done", "load")], 60)

    def test_a_shortened_smoke_keeps_the_rc1_gate_and_fails_on_duration(self):
        rc, out = self.go(self.argv("smoke", "300"))
        tar, d = self.bundle()
        m = self.manifest(d)
        self.assertEqual(m["verdict_min_hours"], 1.0)
        with open(os.path.join(d, "verdict.json"), encoding="utf-8") as f:
            failed = {c["name"] for c in json.load(f)["checks"] if not c["ok"]}
        self.assertIn("duration", failed)
        own = subprocess.run(["python3", VERDICT, os.path.join(d, "status.jsonl"), "--min-hours", "1.0",
                              "--warmup-s", "900"], capture_output=True, text=True)
        self.assertNotEqual(own.returncode, 0)
        # FAIL today; INVALID (3) once soak_verdict.py grows a three-way verdict (#401 item 0.4)
        self.assertEqual(rc, {1: 1}.get(own.returncode, 3), out)
        self.assertNotEqual(self.world.released(), ["PASS"])
        self.assertTrue(any("never opens serial" in w for w in m["waivers"]))

    def test_an_injected_reboot_yields_a_fail_bundle(self):
        self.world.clock.listeners.append(
            lambda: self.world.board.reboot("PANIC")
            if self.world.procs.get("load") and int(self.world.clock.wall() - self.world.procs["load"].start) == 200
            else None)
        rc, out = self.go(self.argv("post-ota", "300"))
        self.assertEqual(rc, 1, out)
        tar, d = self.bundle()
        m = self.manifest(d)
        self.assertEqual(m["verdict"], "FAIL")
        self.assertIn("uptime went", m["reason"])
        with open(os.path.join(d, "abort-status.json"), encoding="utf-8") as f:
            self.assertTrue(json.load(f)["coredump"]["present"])
        self.assertEqual(m["coredump_after_abort"]["status"]["size"], 47264)
        self.assertIn("unavailable", m["coredump_after_abort"]["raw"])
        order = [(k, n) for k, n, _ in self.world.events if k in ("terminate", "run")]
        self.assertEqual(order[:2], [("terminate", "load"), ("terminate", "logger")], "the load stops first")
        self.assertEqual(self.world.touched_serial(), [], "the abort path never opens serial")
        self.assertEqual(self.world.released(), ["FAIL"])

    def test_a_sigterm_mid_run_still_checks_in(self):
        if not hasattr(signal, "SIGTERM") or os.name != "posix":
            self.skipTest("POSIX signals")
        sent = []

        def term():
            load = self.world.procs.get("load")
            if load and not sent and self.world.clock.wall() - load.start >= 100:
                sent.append(1)
                os.kill(os.getpid(), signal.SIGTERM)
                time.sleep(0.05)
        self.world.clock.listeners.append(term)
        before = signal.getsignal(signal.SIGTERM)
        rc, out = self.go(self.argv())
        self.assertEqual(rc, 4, out)
        self.assertEqual(self.world.released(), ["ABORTED"])
        self.assertTrue(self.bundle())
        self.assertIn(("terminate", "load"), [(k, n) for k, n, _ in self.world.events])
        self.assertIs(signal.getsignal(signal.SIGTERM), before)

    def test_a_sighup_mid_run_is_handled_like_sigterm(self):
        # A run started over `rig_checkout.sh ssh` gets SIGHUP when the connection drops.
        if not hasattr(signal, "SIGHUP") or os.name != "posix":
            self.skipTest("POSIX signals")
        unhandled = []
        sent = []

        def hup():
            load = self.world.procs.get("load")
            if load and not sent and self.world.clock.wall() - load.start >= 100:
                sent.append(1)
                os.kill(os.getpid(), signal.SIGHUP)
                time.sleep(0.05)
        self.world.clock.listeners.append(hup)
        # A sentinel, so an unhandled SIGHUP fails this test instead of killing the runner.
        outer = signal.signal(signal.SIGHUP, lambda *a: unhandled.append(1))
        try:
            rc, out = self.go(self.argv())
            self.assertEqual(unhandled, [], "run_soak left SIGHUP to its default (the run dies unchecked-in)")
            self.assertEqual(rc, 4, out)
            self.assertEqual(self.world.released(), ["ABORTED"])
            tar, d = self.bundle()
            self.assertEqual(self.manifest(d)["verdict"], "ABORTED")
            events = [(k, n) for k, n, _ in self.world.events]
            self.assertLess(events.index(("terminate", "load")), events.index(("terminate", "logger")),
                            "the load stops first")
            self.assertIsNot(signal.getsignal(signal.SIGHUP), signal.SIG_DFL)
        finally:
            signal.signal(signal.SIGHUP, outer)

    def test_a_setsid_nohup_start_keeps_ignoring_sighup(self):
        if not hasattr(signal, "SIGHUP") or os.name != "posix":
            self.skipTest("POSIX signals")
        sent = []

        def hup():
            load = self.world.procs.get("load")
            if load and not sent and self.world.clock.wall() - load.start >= 100:
                sent.append(1)
                os.kill(os.getpid(), signal.SIGHUP)
                time.sleep(0.05)
        self.world.clock.listeners.append(hup)
        outer = signal.signal(signal.SIGHUP, signal.SIG_IGN)      # what nohup hands over
        try:
            rc, out = self.go(self.argv())
            self.assertEqual(sent, [1])
            self.assertEqual(rc, 0, out)
            self.assertEqual(self.world.released(), ["PASS"])
            self.assertIs(signal.getsignal(signal.SIGHUP), signal.SIG_IGN, "left as nohup set it")
        finally:
            signal.signal(signal.SIGHUP, outer)

    # ---- the abort path ----------------------------------------------------
    def board_down(self, after_s, for_s):
        def arm():
            load = self.world.procs.get("load")
            if load and not self.world.board.down:
                a = load.start + after_s
                self.world.board.down.append((a, a + for_s))
        self.world.clock.listeners.insert(0, arm)

    def test_an_unreachable_board_gets_one_pinned_cycle_then_needs_a_human(self):
        self.board_down(150, 10 ** 6)
        rc, out = self.go(self.argv("post-ota", "300", "--uhubctl-loc", "1-1", "--uhubctl-port", "2"))
        self.assertEqual(rc, 5, out)
        self.assertEqual(self.world.names().count("uhubctl"), 1)
        self.assertIn(["/fake/uhubctl", "-l", "1-1", "-p", "2", "-a", "cycle"], self.world.calls)
        tar, d = self.bundle()
        self.assertEqual(len(self.manifest(d)["uhubctl_cycles"]), 1)
        self.assertEqual(self.world.released(), ["NEEDS-HUMAN"])

    def test_a_failed_uhubctl_cycle_by_full_path_still_needs_a_human(self):
        os.environ.pop("PD_SOAK_UHUBCTL", None)
        self.world.uhubctl_rc = 1               # no root: the cycle fails
        self.board_down(150, 10 ** 6)
        rc, out = self.go(self.argv("post-ota", "300", "--uhubctl-loc", "1-1", "--uhubctl-port", "2"))
        self.assertEqual(rc, 5, out)
        (cycle,) = [c for c in self.world.calls if os.path.basename(c[0]) == "uhubctl"]
        self.assertEqual(cycle[0], "/usr/sbin/uhubctl")
        tar, d = self.bundle()
        self.assertIn("uhubctl cycle failed (rc 1", self.manifest(d)["reason"])
        self.assertEqual(self.world.released(), ["NEEDS-HUMAN"])

    def test_a_board_silent_for_30_s_that_comes_back_fails_without_a_cycle(self):
        self.board_down(150, 45)
        rc, out = self.go(self.argv("post-ota", "300", "--uhubctl-loc", "1-1", "--uhubctl-port", "2"))
        self.assertEqual(rc, 1, out)
        self.assertNotIn("uhubctl", self.world.names())
        self.assertEqual(self.world.released(), ["FAIL"])

    def test_a_dead_logger_is_invalid_not_a_board_failure(self):
        self.world.logger_dies_at = int(self.world.clock.wall()) + 100
        rc, out = self.go(self.argv())
        self.assertEqual(rc, 3, out)
        self.assertEqual(self.world.released(), ["INVALID"])

    # ---- preflight ---------------------------------------------------------
    def test_preflight_failures_are_invalid_and_block_the_ota(self):
        cases = [
            ("coredump", lambda w: w.board.coredump.update(present=True, size=4096), "coredump is already present"),
            ("pending", lambda w: setattr(w.board, "pending", True), "pendingVerify"),
            ("reset", lambda w: setattr(w.board, "reason", "TASK_WDT"), "not benign"),
        ]
        for name, breaker, want in cases:
            with self.subTest(name):
                shutil.rmtree(self.out, ignore_errors=True)
                self.world = World("v0.0.1-old")
                breaker(self.world)
                rc, out = self.go(self.argv("smoke", "300", "--ota"))
                self.assertEqual(rc, 3, out)
                self.assertIn(want, out)
                self.assertNotIn("remote_ota.sh", self.world.names(), "the OTA was blocked")
                self.assertNotIn("status_logger.sh", self.world.names())
                self.assertEqual(self.world.touched_serial(), [])
                self.assertEqual(self.world.released(), ["INVALID"])

    def test_the_ota_profiles_never_open_serial(self):
        for profile in ("post-ota", "smoke", "soak"):
            with self.subTest(profile):
                shutil.rmtree(self.out, ignore_errors=True)
                self.world = World("v0.0.1-old")
                self.go(self.argv(profile, "300", "--ota"))
                self.assertEqual(self.world.touched_serial(), [])
                tar, d = self.bundle()
                self.assertTrue(any("never opens serial" in w for w in self.manifest(d)["waivers"]))
                shutil.rmtree(os.path.join(self.tmp, "x"), ignore_errors=True)

    def test_the_full_flash_path_keeps_the_backup_on_the_by_id_port(self):
        rc, out = self.go(self.argv("smoke", "300", "--full-flash"))
        esp = [c for c in self.world.calls if os.path.basename(c[0]).startswith("esptool")]
        reads, boot = esp[:4], esp[4]
        for c in reads:
            self.assertEqual(c[c.index("--after") + 1], "no_reset")
            self.assertEqual(c[c.index("--port") + 1], rs.RIG_SERIAL)
        self.assertEqual(boot, ["/fake/esptool.py", "--port", rs.RIG_SERIAL, "--after", "hard_reset", "chip_id"],
                         "a harmless op with --after hard_reset leaves the ROM loader")
        self.assertEqual(len(esp), 5, "and nothing else opens serial")
        tar, d = self.bundle()
        self.assertEqual(set(self.manifest(d)["flash_backup"]), {"nvs", "coredump"})

    def test_backup_reads_that_differ_are_invalid(self):
        self.world.differ_second_nvs_read = True
        rc, out = self.go(self.argv("smoke", "300", "--full-flash"))
        self.assertEqual(rc, 3, out)
        self.assertIn("two reads of nvs differ", out)
        self.assertNotIn("status_logger.sh", self.world.names())
        self.assertEqual(self.world.released(), ["INVALID"])

    def test_ota_installs_the_candidate_and_no_credential_reaches_an_argv(self):
        os.environ["PD_OTA_PASS"] = FAKE_SECRET
        self.world = World("v0.0.1-old")
        rc, out = self.go(self.argv("post-ota", "300", "--ota"))
        self.assertEqual(rc, 0, out)
        (ota,) = [c for c in self.world.calls if c[0].endswith("remote_ota.sh")]
        self.assertEqual(ota[ota.index("--expect-version") + 1], self.stamp)
        self.assertNotIn(FAKE_SECRET, json.dumps(self.world.calls))
        tar, d = self.bundle()
        for name in os.listdir(d):
            with open(os.path.join(d, name), "rb") as f:
                self.assertNotIn(FAKE_SECRET.encode(), f.read(), name)

    # ---- refusals: nothing runs ---------------------------------------------
    def assertRefused(self, argv, want):
        rc, out = self.go(argv)
        self.assertEqual(rc, 2, out)
        self.assertIn(want, out)
        ran = [n for n in self.world.names() if n not in ("git", "rig_checkout.sh")]
        self.assertEqual(ran, [], "a refusal runs nothing on the rig")
        self.assertEqual(self.world.released(), [], "and leaves the lease alone")
        self.assertFalse(os.path.exists(self.out))

    def test_a_dirty_checkout_is_refused(self):
        with open(os.path.join(self.repo, "f.txt"), "a") as f:
            f.write("uncommitted\n")
        self.assertRefused(self.argv(), "is dirty")

    def test_an_image_that_is_not_the_build_artifact_is_refused(self):
        a = self.argv()
        a[a.index("--image-sha256") + 1] = "0" * 64
        self.assertRefused(a, "is not --image-sha256")

    def test_an_image_of_another_commit_is_refused(self):
        make_image(self.image, "v9.9.9")
        with open(self.image, "rb") as f:
            sha = hashlib.sha256(f.read()).hexdigest()
        a = self.argv()
        a[a.index("--image-sha256") + 1] = sha
        self.assertRefused(a, "does not carry this checkout's stamp")

    def test_a_board_on_another_version_is_refused_without_ota(self):
        self.world.board.version = "v0.0.1-old"
        self.assertRefused(self.argv(), "pass --ota")

    def test_no_lease_no_run(self):
        self.world.lease_holder = "Stray"
        self.assertRefused(self.argv(), "not held by BigDog")

    def test_the_checkout_must_cover_the_run(self):
        a = self.argv("soak", "16200", "--skip-flash-backup")
        a[a.index("--checkout-expiry") + 1] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + 3600))
        self.assertRefused(a, "expires before this run would end")
        a = self.argv()
        a[a.index("--checkout-url") + 1] = "https://github.com/GlomarGadaffi/pocket-dial/discussions/294"
        self.assertRefused(a, "#428 CHECK-OUT comment link")

    def test_serial_is_the_stable_by_id_path_only(self):
        self.assertEqual(rs.RIG_SERIAL,
                         "/dev/serial/by-id/usb-Espressif_USB_JTAG_serial_debug_unit_28:84:85:4A:24:68-if00")
        self.assertRefused(self.argv("smoke", "300", "--full-flash", "--serial-port", "/dev/ttyACM0"),
                           "never /dev/ttyACM*")
        self.assertRefused(self.argv("smoke", "300", "--full-flash", "--serial-port",
                                     "/dev/serial/by-id/usb-Espressif_USB_JTAG_serial_debug_unit_"
                                     "E0:72:A1:CC:1C:04-if00"), "LilyGO DNS board")
        self.assertRefused(self.argv("smoke", "300", "--full-flash", "--ota"), "pick one")

    # ---- dry run --------------------------------------------------------------
    def test_dry_run_prints_every_command_and_executes_none(self):
        os.environ.pop("PD_SOAK_UHUBCTL", None)
        rc, out = self.go(self.argv("smoke", "3600", "--ota", "--uhubctl-loc", "1-1", "--uhubctl-port", "2",
                                    "--dry-run"))
        self.assertEqual(rc, 0, out)
        self.assertEqual(self.world.calls, [])
        self.assertEqual(self.world.board.hits, 0)
        self.assertFalse(os.path.exists(self.out))
        for want in ("describe --tags --always --dirty", "remote_ota.sh --host 192.0.2.10 --stage 3",
                     "status_logger.sh 192.0.2.10", "sip_stress.py --profile rc1",
                     "soak_verdict.py", "--min-hours 1.0", "/usr/sbin/uhubctl -l 1-1 -p 2 -a cycle",
                     "rig_checkout.sh release --holder BigDog", "no serial: flash backup waived"):
            self.assertIn(want, out)
        self.assertNotIn("read_flash", out)
        self.assertNotIn("/dev/", out, "the OTA path names no serial port at all")

    def test_dry_run_of_the_full_flash_path_shows_the_backup(self):
        rc, out = self.go(self.argv("smoke", "3600", "--full-flash", "--dry-run"))
        self.assertEqual(rc, 0, out)
        self.assertEqual(self.world.calls, [])
        self.assertEqual(out.count("read_flash"), 4)
        self.assertIn("read_flash 0x9000 0x6000", out)
        self.assertIn("read_flash 0xc20000 0x20000", out)
        self.assertIn("--port %s --after hard_reset chip_id" % rs.RIG_SERIAL, out)


class HttpTest(unittest.TestCase):
    def test_http_json_reads_a_loopback_status_server(self):
        class H(BaseHTTPRequestHandler):
            def do_GET(self):
                body = json.dumps({"uptime": 7, "version": "v1"}).encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass
        srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            port = srv.server_address[1]
            self.assertEqual(rs.http_json("http://127.0.0.1:%d/api/status" % port)["uptime"], 7)
        finally:
            srv.shutdown()
            srv.server_close()
        self.assertIsNone(rs.http_json("http://127.0.0.1:%d/api/status" % port, timeout=0.5))


if __name__ == "__main__":
    unittest.main()
