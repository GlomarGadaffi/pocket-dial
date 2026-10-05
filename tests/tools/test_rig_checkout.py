#!/usr/bin/env python3
"""Self-test for tools/soak/rig_checkout.sh and rig_policy.py (#401 item 0.3). Runs in CI:

    python3 -m unittest discover -s tests/tools -p 'test_rig_checkout.py'

Every case runs the real script against a temporary lock directory with a fake
"now" (PD_RIG_NOW). `ssh`, `gh`, `esptool` and `uhubctl` are stubs on PATH that
only record their argv, so nothing ever leaves the machine; most tests assert
that the stub was never called at all.
"""
import datetime
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SOAK = os.path.join(HERE, "..", "..", "tools", "soak")
SCRIPT = os.path.join(SOAK, "rig_checkout.sh")
sys.path.insert(0, SOAK)
import rig_policy as rp  # noqa: E402

POSIX = os.name == "posix" and shutil.which("bash") and shutil.which("flock")
try:
    rp._zone("Etc/GMT+5")
    ZONES = True
except Exception:  # noqa: BLE001 -- no tz database on this host
    ZONES = False


def at(text):
    """'2026-10-02T01:00' (UTC) -> epoch seconds."""
    return int(datetime.datetime.fromisoformat(text + "+00:00").timestamp())


# Built at run time so the repository never holds anything token-shaped.
FAKE_GH_TOKEN = "gh" + "p_" + "A1b2C3d4" * 5
FAKE_KEY_HEADER = "-----BEGIN " + "OPENSSH PRIVATE KEY-----"
FAKE_SECRET = "correct-horse-battery"


@unittest.skipUnless(POSIX, "needs bash and flock (Linux CI, WSL)")
class RigCheckoutTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.lock = os.path.join(self.tmp, "lock")
        self.posts = os.path.join(self.tmp, "posts")
        self.bin = os.path.join(self.tmp, "bin")
        self.calls = os.path.join(self.tmp, "calls.log")
        os.makedirs(self.lock)
        os.makedirs(self.bin)
        for tool in ("ssh", "gh", "esptool", "esptool.py", "uhubctl"):
            path = os.path.join(self.bin, tool)
            with open(path, "w") as f:
                f.write('#!/bin/sh\necho "%s $*" >> "%s"\n' % (tool, self.calls))
                if tool == "ssh":    # answers `cat /proc/uptime` when a test sets it
                    f.write('[ -n "${STUB_SSH_OUT:-}" ] && echo "$STUB_SSH_OUT"\n')
                f.write("exit 0\n")
            os.chmod(path, 0o755)
        self.uptime = os.path.join(self.tmp, "uptime")
        self.set_uptime(864000)        # glolab booted 10 days before any test's "now"
        self.key = os.path.join(self.tmp, "id_test")
        with open(self.key, "w") as f:
            f.write("not a key\n")
        self.secrets = os.path.join(self.tmp, "secrets")
        with open(self.secrets, "w") as f:
            f.write(FAKE_SECRET + "\n")
        self.env = dict(os.environ, PATH=self.bin + os.pathsep + os.environ.get("PATH", ""),
                        HOME=self.tmp, PD_RIG_LOCK_DIR=self.lock, PD_RIG_POST_DIR=self.posts,
                        PD_GLOLAB_TZ="UTC", PD_GLOLAB_KEY=self.key, PD_SECRETS_FILE=self.secrets,
                        PD_RIG_NOW=str(at("2026-10-02T12:00")), PD_RIG_PROC_UPTIME=self.uptime)
        for k in ("PD_GLOLAB", "PD_RIG_BOOT_VIA_SSH", "STUB_SSH_OUT"):
            self.env.pop(k, None)

    def set_uptime(self, seconds):
        with open(self.uptime, "w") as f:
            f.write("%.2f 12345.67\n" % seconds)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def rig(self, *args, now=None, **env):
        e = dict(self.env, **env)
        if now:
            e["PD_RIG_NOW"] = str(at(now))
        p = subprocess.run(["bash", SCRIPT] + list(args), env=e, capture_output=True, text=True,
                           timeout=60)
        return p.returncode, p.stdout + p.stderr

    def calls_made(self):
        if not os.path.exists(self.calls):
            return []
        with open(self.calls) as f:
            return f.read().splitlines()

    def claim(self, holder="BigDog", minutes="90", *extra, now=None):
        return self.rig("claim", "--holder", holder, "--purpose", "rc.1 smoke", "--minutes", minutes,
                        *extra, now=now)

    def read_post(self, prefix):
        names = sorted(n for n in os.listdir(self.posts) if n.startswith(prefix))
        self.assertTrue(names, "no %s post written" % prefix)
        with open(os.path.join(self.posts, names[-1])) as f:
            return f.read()

    # ---- claim / release ------------------------------------------------
    def test_a_second_claim_fails_naming_the_holder(self):
        rc, out = self.claim("BigDog")
        self.assertEqual(rc, 0, out)
        rc, out = self.claim("Stray")
        self.assertEqual(rc, 1)
        self.assertIn("checked out by BigDog", out)

    def test_release_frees_it_and_always_writes_the_checkin_with_the_verdict(self):
        self.assertEqual(self.claim("BigDog")[0], 0)
        rc, out = self.rig("release", "--holder", "BigDog", "--verdict", "FAIL",
                           "--evidence", "soak-20261002.tar.gz")
        self.assertEqual(rc, 0, out)
        post = self.read_post("checkin-")
        self.assertIn("verdict: **FAIL**", post)
        self.assertIn("soak-20261002.tar.gz", post)
        self.assertIn("2026-10-02T12:00Z", post)
        rc, out = self.claim("Stray")
        self.assertEqual(rc, 0, out)
        self.assertEqual(self.calls_made(), [], "nothing reached gh or ssh")

    def test_release_with_nothing_left_still_writes_the_checkin(self):
        rc, out = self.rig("release", "--holder", "BigDog", "--verdict", "ABORTED")
        self.assertEqual(rc, 0, out)
        self.assertIn("no check-out on record", self.read_post("checkin-"))

    def test_another_holder_cannot_release(self):
        self.assertEqual(self.claim("BigDog")[0], 0)
        rc, out = self.rig("release", "--holder", "Stray", "--verdict", "PASS")
        self.assertEqual(rc, 1)
        self.assertIn("checked out by BigDog, not by Stray", out)
        self.assertEqual(self.claim("Stray")[0], 1, "the lease survived")

    def test_a_human_hold_is_never_overridden(self):
        open(os.path.join(self.lock, "pd195.hold"), "w").close()
        rc, out = self.claim("BigDog", "30", "--break-expired")
        self.assertEqual(rc, 1)
        self.assertIn("human hold", out)

    def test_a_running_flock_user_blocks_the_claim(self):
        path = os.path.join(self.lock, "glolab.lock")
        # -o: flock itself holds the lock, so killing it frees the lock at once.
        held = subprocess.Popen(["flock", "-o", path, "sleep", "30"], start_new_session=True)
        try:
            deadline = time.monotonic() + 20
            while subprocess.run(["flock", "-n", path, "true"]).returncode == 0:
                self.assertLess(time.monotonic(), deadline, "the holder never took the lock")
                time.sleep(0.05)
            rc, out = self.claim("BigDog")
        finally:
            os.killpg(held.pid, 9)
            held.wait()
        self.assertEqual(rc, 1)
        self.assertIn("glolab is busy", out)
        self.assertFalse(os.path.exists(os.path.join(self.lock, "pd195.lease")), "both or neither")

    def test_an_expired_lease_needs_break_expired(self):
        self.assertEqual(self.claim("BigDog", "30", now="2026-10-02T08:00")[0], 0)
        rc, out = self.claim("Stray", "30", now="2026-10-02T12:00")
        self.assertEqual(rc, 1)
        self.assertIn("EXPIRED check-out by BigDog", out)
        rc, out = self.claim("Stray", "30", "--break-expired", now="2026-10-02T12:00")
        self.assertEqual(rc, 0, out)

    # ---- glolab's reboot: tmpfs leases vanish, persistent ones go stale ----
    def test_a_lease_wiped_by_a_reboot_lets_the_claim_through_and_says_so(self):
        self.assertEqual(self.claim("BigDog", "600")[0], 0)
        for name in os.listdir(self.lock):            # /run/lock is tmpfs: the reboot empties it
            os.remove(os.path.join(self.lock, name))
        rc, out = self.claim("Stray", "60", now="2026-10-02T14:00")
        self.assertEqual(rc, 0, out)
        self.assertIn("no lease on record", out)
        self.assertIn("#428 post is the social lock", out)

    def test_a_lease_from_before_the_last_boot_is_stale_not_live(self):
        self.assertEqual(self.claim("BigDog", "600")[0], 0)          # 12:00, until 22:00
        self.set_uptime(3600)                                         # rebooted at 13:00
        rc, out = self.claim("Stray", "60", now="2026-10-02T14:00")
        self.assertEqual(rc, 0, out)
        self.assertIn("STALE lease of BigDog", out)
        self.assertIn("2026-10-02T13:00Z", out)
        rc, out = self.rig("status", now="2026-10-02T14:00")
        self.assertIn("checked out by Stray", out)

    def test_a_lease_taken_after_the_last_boot_is_still_live(self):
        self.set_uptime(3600)                                         # booted 13:00 (now 14:00)
        self.assertEqual(self.claim("BigDog", "600", now="2026-10-02T13:30")[0], 0)
        rc, out = self.claim("Stray", "60", now="2026-10-02T14:00")
        self.assertEqual(rc, 1)
        self.assertIn("checked out by BigDog", out)

    def test_glolabs_boot_time_can_come_over_the_ssh_wrapper(self):
        self.assertEqual(self.claim("BigDog", "600")[0], 0)          # 12:00
        rc, out = self.rig("claim", "--holder", "Stray", "--purpose", "x", "--minutes", "30",
                           now="2026-10-02T12:10", PD_RIG_BOOT_VIA_SSH="1",
                           STUB_SSH_OUT="60.50 10.00", PD_RIG_PROC_UPTIME="/nonexistent")
        self.assertEqual(rc, 0, out)
        self.assertIn("STALE lease of BigDog", out)
        (call,) = self.calls_made()
        self.assertIn("claude-agent@192.168.12.110 -- cat /proc/uptime", call)

    def test_an_unknown_boot_time_fails_closed(self):
        self.assertEqual(self.claim("BigDog", "600")[0], 0)
        rc, out = self.rig("claim", "--holder", "Stray", "--purpose", "x", "--minutes", "30",
                           now="2026-10-02T14:00", PD_RIG_PROC_UPTIME="/nonexistent")
        self.assertEqual(rc, 1)
        self.assertIn("boot time is unknown", out)

    @unittest.skipUnless(ZONES, "needs the tz database")
    def test_glolab_time_is_new_york_by_default(self):
        env = {k: v for k, v in self.env.items() if k != "PD_GLOLAB_TZ"}
        def claim_at(now, minutes):
            e = dict(env, PD_RIG_NOW=str(at(now)))
            p = subprocess.run(["bash", SCRIPT, "claim", "--holder", "BigDog", "--purpose", "x",
                                "--minutes", minutes], env=e, capture_output=True, text=True,
                               timeout=60)
            return p.returncode, p.stdout + p.stderr
        rc, out = claim_at("2026-10-02T07:00", "60")      # 03:00-04:00 EDT
        self.assertEqual(rc, 1)
        self.assertIn("03:30 auto-reboot", out)
        rc, out = claim_at("2026-10-02T03:00", "60")      # 23:00-00:00 EDT: clear
        self.assertEqual(rc, 0, out)

    def test_a_checkout_always_has_an_expiry(self):
        rc, out = self.rig("claim", "--holder", "BigDog", "--purpose", "x")
        self.assertEqual(rc, 1)
        self.assertIn("always has an expiry", out)

    def test_the_0330_reboot_window_is_refused(self):
        rc, out = self.claim("BigDog", "150", now="2026-10-02T01:00")     # ends 03:30
        self.assertEqual(rc, 1)
        self.assertIn("03:30 auto-reboot", out)
        rc, out = self.claim("BigDog", "30", now="2026-10-02T03:40")      # starts inside it
        self.assertEqual(rc, 1)
        rc, out = self.claim("BigDog", "140", now="2026-10-02T01:00")     # ends 03:20
        self.assertEqual(rc, 0, out)
        self.rig("release", "--holder", "BigDog", "--verdict", "PASS")
        rc, out = self.claim("BigDog", "300", now="2026-10-02T03:50")     # after it
        self.assertEqual(rc, 0, out)

    def test_the_checkout_post_carries_the_expiry_and_nothing_is_sent(self):
        rc, out = self.claim("BigDog", "90")
        self.assertEqual(rc, 0, out)
        post = self.read_post("checkout-")
        self.assertIn("until **2026-10-02T13:30Z**", post)
        self.assertIn("`pd195`, `glolab`", post)
        rc, out = self.rig("post", "--file", os.path.join(self.posts, os.listdir(self.posts)[0]))
        self.assertEqual(rc, 0, out)
        self.assertIn("nothing sent", out)
        self.assertEqual(self.calls_made(), [])

    def test_a_post_holding_a_secret_is_refused_even_with_confirm(self):
        path = os.path.join(self.tmp, "post.md")
        with open(path, "w") as f:
            f.write("CHECK-IN\nlogin used %s\n" % FAKE_SECRET)
        rc, out = self.rig("post", "--file", path, "--confirm")
        self.assertEqual(rc, 1)
        self.assertIn("holds a secret", out)
        self.assertNotIn(FAKE_SECRET, out, "the refusal never echoes the secret")
        self.assertEqual(self.calls_made(), [], "gh was never called")

    # ---- the ssh wrapper -------------------------------------------------
    def ssh(self, *argv, flags=(), **env):
        return self.rig("ssh", *flags, "--", *argv, **env)

    def test_an_allowlisted_command_goes_to_glolab_by_ip_with_the_key(self):
        rc, out = self.ssh("tools/soak/status_logger.sh", "192.168.12.195", "soak.jsonl")
        self.assertEqual(rc, 0, out)
        (call,) = self.calls_made()
        self.assertIn("-i %s -o IdentitiesOnly=yes" % self.key, call)
        self.assertIn("claude-agent@192.168.12.110", call)

    def test_refusals_never_reach_ssh(self):
        cases = [
            ((), ("rm", "-rf", "/tmp/x"), "not on the glolab allowlist"),
            ((), ("cat", "/dev/ttyACM0"), "serial port"),
            ((), ("esptool", "--port", "/dev/ttyACM0", "read_flash"), "flash step"),
            (("--flash-step",), ("esptool", "--port", "/dev/ttyACM0", "write_flash"), "--after no_reset"),
            ((), ("uhubctl", "-a", "cycle"), "abort path"),
            ((), ("curl", "-X", "POST", "http://192.168.12.195/api/ota/reboot"), "read-only"),
            ((), ("python3", "tests/load/sip_stress.py", "--target", "sip:911@192.168.12.195"),
             "emergency number"),
            ((), ("python3", "tests/load/sip_stress.py", "--exts", "6101,9933"), "emergency number"),
            ((), ("python3", "tests/load/fake_pbx.py"), "not on the allowlist"),
            ((), ("curl", "-s", "http://admin:%s@192.168.12.195/" % FAKE_SECRET), "holds a secret"),
        ]
        for flags, argv, want in cases:
            rc, out = self.ssh(*argv, flags=flags)
            self.assertEqual(rc, 1, argv)
            self.assertIn(want, out, argv)
        self.assertEqual(self.calls_made(), [])

    def test_ssh_by_name_is_refused(self):
        rc, out = self.ssh("true", PD_GLOLAB="claude-agent@glolab")
        self.assertEqual(rc, 1)
        self.assertIn("never ssh by name", out)
        self.assertEqual(self.calls_made(), [])

    def test_the_flash_step_and_the_abort_path_are_the_only_ways_in(self):
        rc, out = self.ssh("esptool", "--port", "/dev/ttyACM0", "--after", "no_reset", "read_flash",
                           "0x9000", "0x6000", "nvs.bin", flags=("--flash-step",))
        self.assertEqual(rc, 0, out)
        rc, out = self.ssh("uhubctl", "-l", "1-1", "-p", "2", "-a", "cycle", flags=("--abort-path",))
        self.assertEqual(rc, 0, out)
        self.assertEqual(len(self.calls_made()), 2)

    def test_an_lan_address_ending_112_is_not_an_emergency_number(self):
        rc, out = self.ssh("curl", "-s", "http://192.168.12.112/api/status")
        self.assertEqual(rc, 0, out)

    def test_wrapped_commands_are_logged(self):
        log = os.path.join(self.tmp, "rig.log")
        rc, out = self.ssh("tools/soak/status_logger.sh", "192.168.12.195", "x.jsonl", PD_RIG_LOG=log)
        self.assertEqual(rc, 0, out)
        with open(log) as f:
            self.assertIn("status_logger.sh", f.read())

    def test_run_soak_can_be_started_through_the_wrapper(self):
        rc, out = self.ssh(*RUN_SOAK)
        self.assertEqual(rc, 0, out)
        (call,) = self.calls_made()
        self.assertIn("claude-agent@192.168.12.110 -- bash stray-smoke/pd/tools/soak/run_soak.sh --profile smoke",
                      call)

    def test_url_credentials_on_an_argv_are_refused_without_a_secrets_file(self):
        rc, out = self.ssh("curl", "-s", "http://admin:pw123@192.168.12.195/api/status",
                           PD_SECRETS_FILE="")
        self.assertEqual(rc, 1)
        self.assertIn("holds a secret", out)
        self.assertNotIn("pw123", out)
        self.assertEqual(self.calls_made(), [])

    def test_an_injected_run_soak_argument_never_reaches_ssh(self):
        rc, out = self.ssh(*with_arg(RUN_SOAK, "--holder", "BigDog; reboot"))
        self.assertEqual(rc, 1)
        self.assertIn("run_soak.sh --holder", out)
        self.assertNotIn("reboot", out, "the refusal does not echo the value")
        self.assertEqual(self.calls_made(), [])

    # ---- redaction and the secret grep ----------------------------------
    def test_redact_masks_every_kind(self):
        dirty = "\n".join([
            "login with %s" % FAKE_SECRET,
            "Authorization: Digest username=\"admin\", response=\"abc\"",
            "Cookie: pdsid=0123456789abcdef",
            "X-CSRF: 0123456789",
            "password=hunter22&next=1",
            '{"csrf":"tok123","ok":true}',
            "token " + FAKE_GH_TOKEN,
            "http://admin:pw123@192.168.12.195/api/status",
            "INVITE sip:+10000000000@trunk.invalid SIP/2.0",
            FAKE_KEY_HEADER,
        ])
        p = subprocess.run(["bash", SCRIPT, "redact"], input=dirty, env=self.env,
                           capture_output=True, text=True, timeout=30)
        self.assertEqual(p.returncode, 0, p.stderr)
        clean = p.stdout
        for leaked in (FAKE_SECRET, "response=", "0123456789abcdef", "hunter22", "tok123",
                       FAKE_GH_TOKEN, "pw123", "10000000000", "OPENSSH PRIVATE KEY"):
            self.assertNotIn(leaked, clean)
        self.assertIn("192.168.12.195/api/status", clean, "the useful part survives")
        path = os.path.join(self.tmp, "clean.txt")
        with open(path, "w") as f:
            f.write(clean)
        rc, out = self.rig("scan", path)
        self.assertEqual(rc, 0, out)

    def test_scan_fails_closed(self):
        path = os.path.join(self.tmp, "evidence.log")
        with open(path, "w") as f:
            f.write("ok line\nGET /api/ota/upload token=%s\n" % FAKE_GH_TOKEN)
        rc, out = self.rig("scan", path)
        self.assertEqual(rc, 1)
        self.assertIn("evidence.log:2", out)
        self.assertNotIn(FAKE_GH_TOKEN, out)
        rc, out = self.rig("scan", path, PD_SECRETS_FILE=os.path.join(self.tmp, "missing"))
        self.assertEqual(rc, 2, "an unreadable secrets file is a failure, not 'no secrets'")
        rc, out = self.rig("scan", os.path.join(self.tmp, "no-such-file"))
        self.assertEqual(rc, 2)


RUN_SOAK = ("bash", "stray-smoke/pd/tools/soak/run_soak.sh", "--profile", "smoke",
            "--host", "192.168.12.195", "--holder", "BigDog", "--repo", "stray-smoke/pd",
            "--image", "ota/pocket-dial-eth.bin", "--image-sha256", "ab" * 32, "--ota",
            "--checkout-url", "https://github.com/GlomarGadaffi/pocket-dial/discussions/428#discussioncomment-1",
            "--checkout-expiry", "2026-10-02T06:00Z", "--exts", "6101,6102,6103,6104",
            "--owner-ext", "4242", "--out", "stray-smoke/evidence", "--duration", "3600",
            "--uhubctl-loc", "1-1", "--uhubctl-port", "2", "--sip-port", "5060",
            "--allow-no-coredump", "--skip-flash-backup", "--dry-run")


def with_arg(argv, flag, value=None):
    """argv with FLAG's value replaced (or FLAG [VALUE] appended)."""
    argv = list(argv)
    if flag in argv and value is not None:
        argv[argv.index(flag) + 1] = value
    else:
        argv += [flag] + ([value] if value is not None else [])
    return argv


class RunSoakAllowlistTest(unittest.TestCase):
    """`bash <checkout>/tools/soak/run_soak.sh ...` over the ssh wrapper: every
    argument is a known flag or the value of one, checked against its shape."""

    def refused(self, argv, want):
        problems = " | ".join(rp.ssh_problems(list(argv)))
        self.assertIn(want, problems, argv)

    def test_the_real_shapes_are_accepted(self):
        self.assertEqual(rp.ssh_problems(list(RUN_SOAK)), [])
        post = ["bash", "tools/soak/run_soak.sh", "--profile", "post-ota", "--host", "192.168.12.195:80",
                "--holder", "Stray", "--image", "ota/a.bin", "--image-sha256", "0f" * 32,
                "--checkout-url", RUN_SOAK[RUN_SOAK.index("--checkout-url") + 1],
                "--checkout-expiry", "2026-10-02T06:00:00+00:00", "--exts", "6101,6102,6103,6104",
                "--owner-ext", "none"]
        self.assertEqual(rp.ssh_problems(post), [])

    def test_a_digest_is_not_read_as_a_dial_target(self):
        sha = "a911b" + "c" * 59                     # "911" between letters: a hash, not a number
        self.assertEqual(rp.ssh_problems(with_arg(RUN_SOAK, "--image-sha256", sha)), [])
        self.refused(with_arg(RUN_SOAK, "--exts", "6101,6102,6103,6911"), "emergency number")

    def test_injected_or_malformed_arguments_are_refused(self):
        cases = [
            (with_arg(RUN_SOAK, "--holder", "BigDog; reboot"), "run_soak.sh --holder"),
            (with_arg(RUN_SOAK, "--out", "$(reboot)"), "run_soak.sh --out"),
            (with_arg(RUN_SOAK, "--image", "../../etc/passwd"), "run_soak.sh --image"),
            (with_arg(RUN_SOAK, "--image", "/home/claude-agent/ota/a.bin"), "run_soak.sh --image"),
            (with_arg(RUN_SOAK, "--repo", "~/pd"), "run_soak.sh --repo"),
            (with_arg(RUN_SOAK, "--host", "glolab"), "run_soak.sh --host"),
            (with_arg(RUN_SOAK, "--profile", "smoke --ota"), "run_soak.sh --profile"),
            (with_arg(RUN_SOAK, "--image-sha256", "0" * 63), "run_soak.sh --image-sha256"),
            (with_arg(RUN_SOAK, "--checkout-url", "https://example.invalid/428"), "run_soak.sh --checkout-url"),
            (with_arg(RUN_SOAK, "--checkout-expiry", "tomorrow"), "run_soak.sh --checkout-expiry"),
            (with_arg(RUN_SOAK, "--exts", "6101,sip:x@y"), "run_soak.sh --exts"),
            (with_arg(RUN_SOAK, "--duration", "-1"), "run_soak.sh --duration"),
            (with_arg(RUN_SOAK, "--evil"), "'--evil' is not on the allowlist"),
            (with_arg(RUN_SOAK, "--profile=soak"), "'--profile=soak' is not on the allowlist"),
            (list(RUN_SOAK) + ["--holder"], "--holder needs a value"),
            (with_arg(RUN_SOAK, "--boot-cmd", "true"), "--boot-cmd"),
            (with_arg(RUN_SOAK, "--full-flash"), "--full-flash"),
            (with_arg(RUN_SOAK, "--serial-port",
                      "/dev/serial/by-id/usb-Espressif_USB_JTAG_serial_debug_unit_28:84:85:4A:24:68-if00"),
             "serial port"),
        ]
        for argv, want in cases:
            with self.subTest(want):
                self.refused(argv, want)

    def test_only_the_checkout_layout_runs_under_bash(self):
        for script in ("/tmp/tools/soak/run_soak.sh", "evil/run_soak.sh", "../pd/tools/soak/run_soak.sh",
                       "tools/soak/status_logger.sh", "-c"):
            with self.subTest(script):
                self.refused(["bash", script] + list(RUN_SOAK[2:]), "bash runs only")
        self.refused(["/tmp/bash"] + list(RUN_SOAK[1:]), "not on the glolab allowlist")

    def test_no_secret_rides_on_a_run_soak_argv(self):
        url = "https://admin:pw123@github.com/GlomarGadaffi/pocket-dial/discussions/428#discussioncomment-1"
        self.assertNotEqual(rp.ssh_problems(with_arg(RUN_SOAK, "--checkout-url", url)), [])
        self.assertTrue(rp.find_secrets("\n".join(with_arg(RUN_SOAK, "--checkout-url", url))))


class RigPolicyTest(unittest.TestCase):
    @unittest.skipUnless(ZONES, "needs the tz database")
    def test_reboot_window_edges(self):
        self.assertIsNone(rp.reboot_conflict(at("2026-10-02T01:00"), at("2026-10-02T03:25"), "UTC"))
        self.assertIsNotNone(rp.reboot_conflict(at("2026-10-02T01:00"), at("2026-10-02T03:26"), "UTC"))
        self.assertIsNone(rp.reboot_conflict(at("2026-10-02T03:45"), at("2026-10-02T09:00"), "UTC"))
        self.assertIsNotNone(rp.reboot_conflict(at("2026-10-01T20:00"), at("2026-10-02T09:00"), "UTC"),
                             "a run through the night crosses it")

    @unittest.skipUnless(ZONES, "needs the tz database")
    def test_the_window_follows_glolab_time_not_utc(self):
        # 03:30 in UTC-5 is 08:30Z: a 07:00Z-09:00Z run crosses it there.
        self.assertIsNotNone(rp.reboot_conflict(at("2026-10-02T07:00"), at("2026-10-02T09:00"),
                                                "Etc/GMT+5"))
        self.assertIsNone(rp.reboot_conflict(at("2026-10-02T07:00"), at("2026-10-02T09:00"), "UTC"))

    def test_emergency_runs(self):
        for arg in ("911", "sip:933@x", "tel:9911", "--dial=1933"):
            self.assertTrue(rp._emergency_in(arg), arg)
        for arg in ("192.168.12.112", "9110", "3600", "2026-10-02T09:11Z", "6101"):
            self.assertFalse(rp._emergency_in(arg), arg)


if __name__ == "__main__":
    unittest.main()
