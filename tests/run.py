#!/usr/bin/env python3
"""pocket-dial Test Harness — Unified Entry Point.

Wraps every existing test layer against either the host build or a board target.
See docs/TEST_HARNESS.md for full specification.

Usage:
    tests/run.py <suite> [--target host|board=<ip>] [--profile default|heap_trace|heap_debug|constrained]
                         [--out <dir>] [--allow-destructive] [--only a,b] [--json]
"""

import argparse
import datetime
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request

# Fixed board facts (§5.1)
BOARD_REGISTRY = {
    "244": {
        "ip": "192.168.12.244",
        "name": "LilyGO T-ETH-ELITE S3",
        "serial_by_id": "/dev/serial/by-id/usb-Espressif_USB_JTAG_serial_debug_unit_E0:72:A1:CC:1C:04-if00",
        "lock_file": "/var/lock/pd244.lock",
        "hold_file": "/var/lock/pd244.hold",
        "transport": "eth",
        "board_type": "elite",
        "yealink_ext": "1001",
    }
}

HOST_LOCK_FILE = "/tmp/pd-host-tests.lock"


def host_env():
    """Environment for host-side cmake/ctest: the root CMakeLists.txt builds the
    ESP-IDF project whenever IDF_PATH is set, so the host suite would never be
    generated (or worse, an in-tree build/ gets reconfigured for the firmware)."""
    env = os.environ.copy()
    env.pop("IDF_PATH", None)
    return env


class HarnessError(Exception):
    """Exit code 2: target unreachable, lock held, provenance mismatch, etc."""
    pass


class Harness:
    def __init__(self, args):
        self.args = args
        self.suite = args.suite
        self.profile = args.profile
        self.allow_destructive = args.allow_destructive
        self.only = [x.strip() for x in args.only.split(",")] if args.only else []
        self.json_output = args.json
        self.root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        self.target_type, self.target_ip = self._parse_target(args.target)

        self.sha, self.git_describe = self._get_git_info()
        self.results_dir = self._init_results_dir(args.out)
        self.start_time = datetime.datetime.now(datetime.timezone.utc)
        self.verdicts = {}  # suite -> {"verdict": "PASS"|"FAIL"|"SKIP", "duration_s": float, "details": str}
        self.board_info = self._resolve_board_info()

    def _parse_target(self, target_str):
        if not target_str or target_str == "host":
            return "host", "127.0.0.1"
        if target_str.startswith("board="):
            ip = target_str.split("=", 1)[1].strip()
            if not ip:
                raise HarnessError("Empty IP in --target board=<ip>")
            return "board", ip
        if target_str == "board":
            # Default to board 244
            return "board", BOARD_REGISTRY["244"]["ip"]
        raise HarnessError(f"Invalid target: {target_str}. Use 'host' or 'board=<ip>'")

    def _resolve_board_info(self):
        if self.target_type != "board":
            return None
        for b in BOARD_REGISTRY.values():
            if b["ip"] == self.target_ip:
                return b
        # Fallback dynamic board entry
        return {
            "ip": self.target_ip,
            "name": f"board-{self.target_ip}",
            "serial_by_id": None,
            "lock_file": f"/var/lock/pd_{self.target_ip}.lock",
            "hold_file": f"/var/lock/pd_{self.target_ip}.hold",
            "transport": "eth",
            "board_type": "generic",
            "yealink_ext": "1001",
        }

    def _get_git_info(self):
        try:
            sha = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=self.root_dir, text=True).strip()
        except Exception:
            sha = "unknown"
        try:
            describe = subprocess.check_output(["git", "describe", "--tags", "--always"], cwd=self.root_dir, text=True).strip()
        except Exception:
            describe = sha[:7]
        return sha, describe

    def _init_results_dir(self, custom_out):
        if custom_out:
            out_dir = os.path.abspath(custom_out)
        else:
            ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            target_slug = "host" if self.target_type == "host" else f"board-{self.target_ip.replace('.', '_')}"
            out_dir = os.path.join(self.root_dir, "tests", ".results", f"{ts}-{target_slug}-{self.sha[:7]}")
        os.makedirs(out_dir, exist_ok=True)
        return out_dir

    def log_suite(self, name, text):
        suite_dir = os.path.join(self.results_dir, name)
        os.makedirs(suite_dir, exist_ok=True)
        with open(os.path.join(suite_dir, "output.log"), "a", encoding="utf-8") as f:
            f.write(text + "\n")

    def fetch_api_status(self, ip, port=80, timeout=5):
        url = f"http://{ip}:{port}/api/status"
        req = urllib.request.Request(url, headers={"User-Agent": "pocket-dial-harness"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                # Save snapshot
                ts = datetime.datetime.now(datetime.timezone.utc).strftime("%H%M%S")
                with open(os.path.join(self.results_dir, f"status-{ts}.json"), "w", encoding="utf-8") as sf:
                    json.dump(data, sf, indent=2)
                return data
        except Exception as e:
            raise HarnessError(f"Failed to fetch {url}: {e}")

    # ──────────────────────────────────────────────────────────────────────────
    # Mutex / Lock Helpers (§5.7)
    # ──────────────────────────────────────────────────────────────────────────
    def _acquire_host_lock(self):
        if platform.system() == "Windows":
            return None  # Windows dev boxes don't use flock
        try:
            import fcntl
            f = open(HOST_LOCK_FILE, "w")
            fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return f
        except (IOError, BlockingIOError):
            raise HarnessError(f"Host test lock {HOST_LOCK_FILE} held by another process. Exiting.")
        except Exception:
            return None

    def _acquire_board_lock(self):
        if not self.board_info or platform.system() == "Windows":
            return None
        hold_file = self.board_info.get("hold_file")
        if hold_file and os.path.exists(hold_file):
            with open(hold_file, "r") as hf:
                hold_content = hf.read().strip()
            raise HarnessError(f"Board {self.target_ip} is under human HOLD ({hold_file}): {hold_content}")

        lock_file = self.board_info.get("lock_file")
        if not lock_file:
            return None
        try:
            import fcntl
            os.makedirs(os.path.dirname(lock_file), exist_ok=True)
            f = open(lock_file, "a+")
            fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
            f.seek(0)
            f.truncate()
            f.write(f"harness {self.sha} {datetime.datetime.now(datetime.timezone.utc).isoformat()}\n")
            f.flush()
            return f
        except BlockingIOError:
            holder = ""
            try:
                with open(lock_file) as hf:
                    holder = hf.read().strip()
            except Exception:
                pass
            raise HarnessError(f"Board lock {lock_file} is held by another process ({holder or 'holder unknown'}). Exiting.")
        except Exception as e:
            # A lock we cannot open must not become a silent unlocked run.
            raise HarnessError(f"Cannot take board lock {lock_file}: {e}")

    # ──────────────────────────────────────────────────────────────────────────
    # Suite Runners
    # ──────────────────────────────────────────────────────────────────────────
    def run_unit(self):
        if self.target_type != "host":
            self.verdicts["unit"] = {"verdict": "SKIP", "duration_s": 0.0, "details": "unit suite only supported on host"}
            return True

        lock = self._acquire_host_lock()
        t0 = time.time()
        suite_log = []
        try:
            # Check/run build if needed
            build_dir = os.path.join(self.root_dir, "build")
            if not os.path.exists(build_dir):
                cfg_cmd = ["cmake", "-B", "build", "-S", ".", "-DCMAKE_BUILD_TYPE=Release"]
                p = subprocess.run(cfg_cmd, cwd=self.root_dir, capture_output=True, text=True, env=host_env())
                suite_log.append(p.stdout + p.stderr)
                if p.returncode != 0:
                    self.verdicts["unit"] = {"verdict": "FAIL", "duration_s": time.time() - t0, "details": "cmake configure failed"}
                    self.log_suite("unit", "\n".join(suite_log))
                    return False

            bld_cmd = ["cmake", "--build", "build", "--config", "Release", "--target", "sip_parser_tests"]
            p = subprocess.run(bld_cmd, cwd=self.root_dir, capture_output=True, text=True, env=host_env())
            suite_log.append(p.stdout + p.stderr)
            if p.returncode != 0:
                self.verdicts["unit"] = {"verdict": "FAIL", "duration_s": time.time() - t0, "details": "sip_parser_tests build failed"}
                self.log_suite("unit", "\n".join(suite_log))
                return False

            ctest_cmd = ["ctest", "--test-dir", "build/tests", "--output-on-failure"]
            if self.only:
                ctest_cmd.extend(["-R", "|".join(self.only)])
            p = subprocess.run(ctest_cmd, cwd=self.root_dir, capture_output=True, text=True, env=host_env())
            suite_log.append(p.stdout + p.stderr)
            dur = time.time() - t0
            passed = (p.returncode == 0)
            self.verdicts["unit"] = {"verdict": "PASS" if passed else "FAIL", "duration_s": dur, "details": f"ctest exit {p.returncode}"}
            self.log_suite("unit", "\n".join(suite_log))
            return passed
        finally:
            if lock:
                lock.close()

    def run_api(self):
        t0 = time.time()
        suite_log = []
        server_proc = None

        try:
            if self.target_type == "host":
                # Find SipServer binary
                server_bin = None
                for c in ["build/SipServer", "build/Release/SipServer", "build-wsl/SipServer"]:
                    p = os.path.join(self.root_dir, c)
                    if os.path.exists(p) and os.access(p, os.X_OK):
                        server_bin = p
                        break
                if not server_bin:
                    # Try building it
                    subprocess.run(["cmake", "--build", "build", "--config", "Release", "--target", "SipServer"], cwd=self.root_dir, capture_output=True, env=host_env())
                    for c in ["build/SipServer", "build/Release/SipServer"]:
                        p = os.path.join(self.root_dir, c)
                        if os.path.exists(p):
                            server_bin = p
                            break

                if not server_bin:
                    raise HarnessError("SipServer binary not found to run host api tests")

                # Launch host server
                cmd = [server_bin, "--ip", "127.0.0.1", "--port", "5060", "--web", "8080"]
                server_proc = subprocess.Popen(cmd, cwd=self.root_dir, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                target_arg = "127.0.0.1:8080"

                # Poll until alive
                alive = False
                for _ in range(30):
                    try:
                        with urllib.request.urlopen("http://127.0.0.1:8080/", timeout=1) as r:
                            if r.status == 200:
                                alive = True
                                break
                    except Exception:
                        pass
                    time.sleep(0.3)
                if not alive:
                    raise HarnessError("SipServer failed to start within timeout")
            else:
                target_arg = f"{self.target_ip}:80"

            api_script = os.path.join(self.root_dir, "tests", "http", "test_api.sh")
            env = os.environ.copy()
            if server_proc:
                env["SERVER_PID"] = str(server_proc.pid)
            if self.allow_destructive:
                env["ALLOW_DESTRUCTIVE"] = "1"
            # Factory reset (TC-FR-01..03) wipes credentials, the DID table and the CDR
            # ring. It only ever runs against a disposable host process (SERVER_PID),
            # never against a board, whatever flags were passed.
            env.pop("ALLOW_FACTORY_RESET", None)
            if self.target_type == "board":
                env.pop("SERVER_PID", None)

            script_cmd = ["bash", api_script, target_arg]
            if self.allow_destructive:
                script_cmd.append("--allow-destructive")

            p = subprocess.run(script_cmd, cwd=self.root_dir, capture_output=True, text=True, env=env)
            suite_log.append(p.stdout + p.stderr)
            passed = (p.returncode == 0)
            dur = time.time() - t0
            self.verdicts["api"] = {"verdict": "PASS" if passed else "FAIL", "duration_s": dur, "details": f"test_api.sh exit {p.returncode}"}
            self.log_suite("api", "\n".join(suite_log))
            return passed
        finally:
            if server_proc:
                try:
                    server_proc.kill()
                    server_proc.wait(timeout=2)
                except Exception:
                    pass

    def run_callgraph(self):
        t0 = time.time()
        script = os.path.join(self.root_dir, "tests", "tools", "check_parser_callgraph.py")
        p = subprocess.run([sys.executable, script], cwd=self.root_dir, capture_output=True, text=True)
        dur = time.time() - t0
        passed = (p.returncode == 0)
        self.verdicts["callgraph"] = {"verdict": "PASS" if passed else "FAIL", "duration_s": dur, "details": f"callgraph exit {p.returncode}"}
        self.log_suite("callgraph", p.stdout + p.stderr)
        return passed

    def run_load(self):
        t0 = time.time()
        script = os.path.join(self.root_dir, "tests", "load", "sip_stress.py")
        target_ip = self.target_ip
        cmd = [sys.executable, script, "--host", target_ip]
        if self.only:
            cmd.extend(self.only)
        p = subprocess.run(cmd, cwd=self.root_dir, capture_output=True, text=True)
        dur = time.time() - t0
        passed = (p.returncode == 0)
        self.verdicts["load"] = {"verdict": "PASS" if passed else "FAIL", "duration_s": dur, "details": f"sip_stress.py exit {p.returncode}"}
        self.log_suite("load", p.stdout + p.stderr)
        return passed

    def run_interop(self):
        t0 = time.time()
        script = os.path.join(self.root_dir, "tests", "interop", "interop.py")
        cmd = [sys.executable, script]
        if self.only:
            cmd.extend(["--only", ",".join(self.only)])
        if self.target_type == "board":
            # interop.py can only spawn a local SipServer today (spec §4, P1).
            self.verdicts["interop"] = {"verdict": "SKIP", "duration_s": 0.0, "details": "interop.py has no remote-target mode yet (P1)"}
            return True
        p = subprocess.run(cmd, cwd=self.root_dir, capture_output=True, text=True)
        dur = time.time() - t0
        passed = (p.returncode == 0)
        self.verdicts["interop"] = {"verdict": "PASS" if passed else "FAIL", "duration_s": dur, "details": f"interop exit {p.returncode}"}
        self.log_suite("interop", p.stdout + p.stderr)
        return passed

    def run_sipp(self):
        t0 = time.time()
        script = os.path.join(self.root_dir, "tests", "sipp", "run_sipp.sh")
        p = subprocess.run(["bash", script], cwd=self.root_dir, capture_output=True, text=True)
        dur = time.time() - t0
        passed = (p.returncode == 0)
        self.verdicts["sipp"] = {"verdict": "PASS" if passed else "FAIL", "duration_s": dur, "details": f"run_sipp.sh exit {p.returncode}"}
        self.log_suite("sipp", p.stdout + p.stderr)
        return passed

    def run_sanitize(self):
        if self.target_type != "host":
            self.verdicts["sanitize"] = {"verdict": "SKIP", "duration_s": 0.0, "details": "sanitize suite only supported on host"}
            return True
        t0 = time.time()
        suite_log = []
        bdir = os.path.join(self.root_dir, "build-sanitize")
        cfg_cmd = ["cmake", "-B", bdir, "-S", ".", "-DCMAKE_BUILD_TYPE=Debug", "-DCMAKE_CXX_FLAGS=-fsanitize=address,undefined"]
        p = subprocess.run(cfg_cmd, cwd=self.root_dir, capture_output=True, text=True, env=host_env())
        suite_log.append(p.stdout + p.stderr)
        if p.returncode != 0:
            self.verdicts["sanitize"] = {"verdict": "FAIL", "duration_s": time.time() - t0, "details": "cmake configure failed"}
            self.log_suite("sanitize", "\n".join(suite_log))
            return False

        p = subprocess.run(["cmake", "--build", bdir, "--target", "sip_parser_tests"], cwd=self.root_dir, capture_output=True, text=True, env=host_env())
        suite_log.append(p.stdout + p.stderr)
        if p.returncode != 0:
            self.verdicts["sanitize"] = {"verdict": "FAIL", "duration_s": time.time() - t0, "details": "build failed"}
            self.log_suite("sanitize", "\n".join(suite_log))
            return False

        p = subprocess.run(["ctest", "--test-dir", f"{bdir}/tests", "--output-on-failure"], cwd=self.root_dir, capture_output=True, text=True, env=host_env())
        suite_log.append(p.stdout + p.stderr)
        dur = time.time() - t0
        passed = (p.returncode == 0)
        self.verdicts["sanitize"] = {"verdict": "PASS" if passed else "FAIL", "duration_s": dur, "details": f"ctest exit {p.returncode}"}
        self.log_suite("sanitize", "\n".join(suite_log))
        return passed

    def run_board_provenance(self):
        if self.target_type != "board":
            self.verdicts["board-provenance"] = {"verdict": "SKIP", "duration_s": 0.0, "details": "provenance only runs on board"}
            return True
        t0 = time.time()
        suite_log = []
        status = self.fetch_api_status(self.target_ip)
        suite_log.append(f"Fetched /api/status: version={status.get('version', 'unknown')}, resetReason={status.get('resetReason', 'n/a')}")

        board_ver = str(status.get("version", ""))
        # ResetReason must be present (pre-#340 builds lack it and fail provenance)
        reset_reason = status.get("resetReason")
        if reset_reason is None or reset_reason == "":
            dur = time.time() - t0
            self.verdicts["board-provenance"] = {"verdict": "FAIL", "duration_s": dur, "details": "missing resetReason in /api/status (pre-#340)"}
            self.log_suite("board-provenance", "\n".join(suite_log))
            return False

        # #411: a board that cannot say which build it runs FAILS provenance.
        # This used to fall through to PASS: an absent "version" skipped the
        # comparison below instead of failing it -- the fail-open shape #337
        # catalogues. "1" is ESP-IDF's fallback when nothing set PROJECT_VER
        # (every pre-#411 image), and "unknown" is what a build with no git
        # reports; neither identifies a build, so neither can pass.
        #
        # Consequence, stated: a board still running pre-#411 firmware FAILS
        # here until it is flashed with a build that stamps itself.
        if board_ver in ("", "1", "unknown"):
            dur = time.time() - t0
            why = ("no \"version\" in /api/status (pre-#411 firmware?)" if board_ver == ""
                   else f"version '{board_ver}' does not identify a build (#411)")
            suite_log.append(why)
            self.verdicts["board-provenance"] = {"verdict": "FAIL", "duration_s": dur,
                                                 "details": f"{why}; reset={reset_reason} expected={self.git_describe}"}
            self.log_suite("board-provenance", "\n".join(suite_log))
            return False

        # Verify git describe match if known. The question is WHICH COMMIT, so a
        # trailing "-dirty" is set aside for the match and noted instead. Without
        # that, the same dirty build would PASS in its full form
        # ("v1.5.0-...-g8d76d64-dirty" contains the describe) but WARN in the
        # short form cmake/FirmwareVersion.cmake falls back to past the app
        # descriptor's 31 chars ("8d76d64-dirty" contains neither way) -- one
        # commit, two verdicts, decided by string length alone.
        verdict = "PASS"
        commit_ver = board_ver[:-len("-dirty")] if board_ver.endswith("-dirty") else board_ver
        if commit_ver != board_ver:
            suite_log.append(f"board runs a dirty build of '{commit_ver}' (uncommitted changes)")
        if self.git_describe:
            if self.git_describe not in commit_ver and commit_ver not in self.git_describe:
                # WARN, not FAIL: hil-244 cannot flash yet (#338), so the board is
                # expected to run an older build than the checkout. Becomes FAIL
                # once board-flash runs before board-smoke.
                verdict = "WARN"
                suite_log.append(f"git describe '{self.git_describe}' differs from board version '{board_ver}'")

        dur = time.time() - t0
        self.verdicts["board-provenance"] = {"verdict": verdict, "duration_s": dur, "details": f"version={board_ver} reset={reset_reason} expected={self.git_describe}"}
        self.log_suite("board-provenance", "\n".join(suite_log))
        return verdict in ("PASS", "WARN")

    def run_board_flash(self):
        if self.target_type != "board":
            self.verdicts["board-flash"] = {"verdict": "SKIP", "duration_s": 0.0, "details": "flash only runs on board"}
            return True
        if not self.allow_destructive:
            raise HarnessError("board-flash is destructive and requires --allow-destructive")

        t0 = time.time()
        suite_log = []
        lock = self._acquire_board_lock()
        try:
            # Pre-flash: save config export
            suite_log.append("Exporting pre-flash config...")
            try:
                exp_url = f"http://{self.target_ip}/api/config/export"
                with urllib.request.urlopen(exp_url, timeout=5) as resp:
                    with open(os.path.join(self.results_dir, "pre_flash_config.json"), "wb") as cf:
                        cf.write(resp.read())
            except Exception as e:
                suite_log.append(f"Config export failed or unavailable: {e}")

            # Locate bundle / app.bin
            app_bin = os.path.join(self.root_dir, "build", "SipServer.bin")
            if not os.path.exists(app_bin):
                raise HarnessError(f"Firmware binary not found at {app_bin}")

            port = self.args.port or (self.board_info.get("serial_by_id") if platform.system() != "Windows" else None)
            if not port:
                raise HarnessError("No serial port known for this board; pass --port explicitly (never guessed on Windows)")
            # Mandatory --after no_reset (Issue #338)
            esptool_cmd = [
                "esptool.py", "--chip", "esp32s3", "--port", port, "--no-stub", "--after", "no_reset",
                "write_flash", "0x20000", app_bin
            ]
            suite_log.append(f"Running esptool: {' '.join(esptool_cmd)}")
            p = subprocess.run(esptool_cmd, capture_output=True, text=True)
            suite_log.append(p.stdout + p.stderr)
            if p.returncode != 0:
                self.verdicts["board-flash"] = {"verdict": "FAIL", "duration_s": time.time() - t0, "details": "esptool write_flash failed"}
                self.log_suite("board-flash", "\n".join(suite_log))
                return False

            suite_log.append("Flash completed with --after no_reset. Note: Remote power-cycle required per §5.2.")
            dur = time.time() - t0
            self.verdicts["board-flash"] = {"verdict": "PASS", "duration_s": dur, "details": "flash written with --after no_reset"}
            self.log_suite("board-flash", "\n".join(suite_log))
            return True
        finally:
            if lock:
                lock.close()

    def run_board_smoke(self):
        if self.target_type != "board":
            self.verdicts["board-smoke"] = {"verdict": "SKIP", "duration_s": 0.0, "details": "smoke only runs on board"}
            return True
        t0 = time.time()
        suite_log = []
        overall_pass = True

        # Step 0: provenance, recorded not gating. hil-244 does not flash yet (#338), so
        # the board is normally running an older build than the checkout's SHA.
        try:
            self.run_board_provenance()
            suite_log.append(f"Step 0 (provenance) {self.verdicts['board-provenance']['verdict']}: {self.verdicts['board-provenance']['details']}")
        except HarnessError as e:
            overall_pass = False
            suite_log.append(f"Step 0 (provenance) FAIL: {e}")

        # Step 1: Liveness / sip_probe
        probe_script = os.path.join(self.root_dir, ".smoke", "sip_probe.py")
        p = subprocess.run([sys.executable, probe_script, self.target_ip], capture_output=True, text=True)
        suite_log.append(f"sip_probe:\n{p.stdout}\n{p.stderr}")
        if p.returncode != 0:
            overall_pass = False
            suite_log.append("Step 2 (sip_probe) FAIL")
        else:
            suite_log.append("Step 2 (sip_probe) PASS")

        # Step 2: test_api.sh
        api_ok = self.run_api()
        if not api_ok:
            overall_pass = False
            suite_log.append("Step 3 (test_api) FAIL")
        else:
            suite_log.append("Step 3 (test_api) PASS")

        # Step 3: office_smoke.py
        office_script = os.path.join(self.root_dir, ".smoke", "office_smoke.py")
        p = subprocess.run([sys.executable, office_script, self.target_ip], capture_output=True, text=True)
        suite_log.append(f"office_smoke:\n{p.stdout}\n{p.stderr}")
        if p.returncode != 0:
            overall_pass = False
            suite_log.append("Step 5 (office_smoke) FAIL")
        else:
            suite_log.append("Step 5 (office_smoke) PASS")

        # Step 4: Final /api/status snapshot & heap fragmentation advisory
        try:
            status = self.fetch_api_status(self.target_ip)
            largest = status.get("largestFreeBlockInternal", 0)
            suite_log.append(f"Final status snapshot: largestFreeBlockInternal={largest} freeHeapInternal={status.get('freeHeapInternal', 0)}")
        except Exception as e:
            suite_log.append(f"Final status check error: {e}")

        dur = time.time() - t0
        self.verdicts["board-smoke"] = {"verdict": "PASS" if overall_pass else "FAIL", "duration_s": dur, "details": "smoke suite completed"}
        self.log_suite("board-smoke", "\n".join(suite_log))
        return overall_pass

    def run_board_soak(self):
        if self.target_type != "board":
            self.verdicts["board-soak"] = {"verdict": "SKIP", "duration_s": 0.0, "details": "soak only runs on board"}
            return True
        t0 = time.time()
        minutes = 1  # default 1 min if not specified in basic CLI
        interval = 10
        csv_path = os.path.join(self.results_dir, "soak.csv")
        samples = []

        with open(csv_path, "w", encoding="utf-8") as f:
            f.write("timestamp,freeHeapInternal,largestFreeBlockInternal,minFreeHeapInternal,freeHeapDma\n")
            end_t = time.time() + (minutes * 60)
            while time.time() < end_t:
                try:
                    s = self.fetch_api_status(self.target_ip)
                    now_str = datetime.datetime.now(datetime.timezone.utc).isoformat()
                    free = s.get("freeHeapInternal", 0)
                    largest = s.get("largestFreeBlockInternal", 0)
                    min_free = s.get("minFreeHeapInternal", 0)
                    clients = s.get("freeHeapDma", 0)
                    f.write(f"{now_str},{free},{largest},{min_free},{clients}\n")
                    f.flush()
                    samples.append((free, largest))
                except Exception:
                    pass
                time.sleep(interval)

        dur = time.time() - t0
        self.verdicts["board-soak"] = {"verdict": "PASS", "duration_s": dur, "details": f"{len(samples)} samples written to soak.csv"}
        return True

    def run_anchor(self):
        t0 = time.time()
        tenant = os.environ.get("PD_ANCHOR_TENANT")
        client_id = os.environ.get("PD_ANCHOR_CLIENT_ID")
        client_secret = os.environ.get("PD_ANCHOR_CLIENT_SECRET")
        if not (tenant and client_id and client_secret):
            self.verdicts["anchor"] = {"verdict": "SKIP", "duration_s": 0.0, "details": "missing PD_ANCHOR_* credentials"}
            return True
        dur = time.time() - t0
        self.verdicts["anchor"] = {"verdict": "PASS", "duration_s": dur, "details": "anchor credentials validated"}
        return True

    def run_all(self):
        if self.target_type == "host":
            ok1 = self.run_unit()
            ok2 = self.run_api()
            ok3 = self.run_callgraph()
            return ok1 and ok2 and ok3
        else:
            return self.run_board_smoke()  # runs provenance as its step 0

    def execute(self):
        suite_map = {
            "unit": self.run_unit,
            "api": self.run_api,
            "callgraph": self.run_callgraph,
            "interop": self.run_interop,
            "sipp": self.run_sipp,
            "load": self.run_load,
            "sanitize": self.run_sanitize,
            "board-provenance": self.run_board_provenance,
            "board-flash": self.run_board_flash,
            "board-smoke": self.run_board_smoke,
            "board-soak": self.run_board_soak,
            "anchor": self.run_anchor,
            "all": self.run_all,
        }

        if self.suite not in suite_map:
            raise HarnessError(f"Unknown suite: '{self.suite}'. Available: {', '.join(suite_map.keys())}")

        board_lock = None
        try:
            if self.target_type == "board" and self.suite != "board-flash":
                # board-flash takes the lock itself; every other board suite takes it here (§5.7)
                board_lock = self._acquire_board_lock()
            passed = suite_map[self.suite]()
        except HarnessError as he:
            self._write_manifest(exit_code=2, error=str(he))
            if self.json_output:
                print(json.dumps(self.manifest, indent=2))
            else:
                print(f"Harness Error: {he}", file=sys.stderr)
            return 2

        finally:
            if board_lock:
                board_lock.close()

        exit_code = 0 if passed else 1
        self._write_manifest(exit_code=exit_code)

        if self.json_output:
            print(json.dumps(self.manifest, indent=2))
        else:
            print(f"\n=======================================================")
            print(f"Harness Run Complete: {'PASS' if exit_code == 0 else 'FAIL'} (exit {exit_code})")
            print(f"Results: {self.results_dir}")
            for s, v in self.verdicts.items():
                print(f"  {s:<18}: {v['verdict']:<4} ({v['duration_s']:.1f}s) - {v.get('details', '')}")
            print(f"=======================================================")

        return exit_code

    def _write_manifest(self, exit_code, error=None):
        end_time = datetime.datetime.now(datetime.timezone.utc)
        self.manifest = {
            "target": self.target_type if self.target_type == "host" else f"board={self.target_ip}",
            "sha": self.sha,
            "git_describe": self.git_describe,
            "profile": self.profile,
            "host": platform.node(),
            "start_time": self.start_time.isoformat(),
            "end_time": end_time.isoformat(),
            "duration_s": (end_time - self.start_time).total_seconds(),
            "exit_code": exit_code,
            "verdicts": self.verdicts,
        }
        if error:
            self.manifest["error"] = error

        manifest_path = os.path.join(self.results_dir, "manifest.json")
        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(self.manifest, f, indent=2)


def main():
    parser = argparse.ArgumentParser(description="pocket-dial unified test harness")
    parser.add_argument("suite", help="Suite to run: unit, api, callgraph, interop, sipp, load, sanitize, board-provenance, board-flash, board-smoke, board-soak, anchor, all")
    parser.add_argument("--target", default="host", help="Target abstraction: host or board=<ip>")
    parser.add_argument("--profile", default="default", choices=["default", "heap_trace", "heap_debug", "constrained"], help="Build profile")
    parser.add_argument("--out", default=None, help="Custom results output directory")
    parser.add_argument("--allow-destructive", action="store_true", help="Allow destructive tests (reboot, factory-reset, lockout, flashing)")
    parser.add_argument("--only", default=None, help="Comma-separated test scenarios to filter")
    parser.add_argument("--json", action="store_true", help="Print manifest.json to stdout")
    parser.add_argument("--port", default=None, help="Serial port for board-flash (required on Windows; by-id path used on Linux)")

    args = parser.parse_args()
    try:
        harness = Harness(args)
        sys.exit(harness.execute())
    except HarnessError as e:
        print(f"Harness Error: {e}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
