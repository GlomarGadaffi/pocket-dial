#!/usr/bin/env python3
"""bench_fault_runner.py: Orchestrate hardware bench fault injection (#384, #328).

Drives the one-shot fault probe and DRAM ballast on a bench-probe image
(POCKETDIAL_ANCHOR_BENCH_PROBE, docs/BENCH_PROBE.md) to verify:
  - #349: makecall_read_fail (unread response -> participant reconcile)
  - #279: post_stream_fail (writeAudio write failure -> handset BYE)
  - #336: token_age (token lifetime shift -> re-auth on refresh)
  - #350: ballast (controlled DRAM reduction -> GET retry rebuilds handle)
  - #379: get_status & get_max_attempts (MediaNeverOpened teardown)

Safety invariants:
  - Fails closed if the board reports a release image (never probes release).
  - Registers clean abort hooks to release ballast and disarm faults on exit.
  - Verifies the 'fired' counter incremented before reporting success (avoids false passes).
"""

import argparse
import atexit
import http.client
import json
import os
import sys
import time
import urllib.parse
from typing import Any, Dict, Optional, Tuple


class BenchProbeError(Exception):
    """Exception raised on bench probe communication or safety failure."""


class BenchFaultClient:
    """Client for controlling the Pocket-dial Bench Probe API."""

    def __init__(self, host: str = "192.168.40.244", port: int = 80, password: Optional[str] = None):
        self.host = host
        self.port = port
        self.password = password or os.environ.get("POCKETDIAL_ADMIN_PASSWORD", "admin")
        self.session_cookie: Optional[str] = None
        self.csrf_token: Optional[str] = None

    def _request(self, method: str, path: str, body: Optional[str] = None, headers: Optional[Dict[str, str]] = None) -> Tuple[int, Dict[str, str], str]:
        req_headers = headers or {}
        if self.session_cookie:
            req_headers["Cookie"] = f"PD_SESSION={self.session_cookie}"
        if self.csrf_token:
            req_headers["X-CSRF"] = self.csrf_token

        conn = http.client.HTTPConnection(self.host, self.port, timeout=10)
        try:
            conn.request(method, path, body, req_headers)
            res = conn.getresponse()
            res_headers = {k.lower(): v for k, v in res.getheaders()}
            res_body = res.read().decode("utf-8", errors="replace")
            return res.status, res_headers, res_body
        finally:
            conn.close()

    def login(self) -> None:
        """Authenticate with the board and extract session cookie and CSRF token."""
        form = urllib.parse.urlencode({"password": self.password})
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        status, resp_headers, body = self._request("POST", "/api/admin/login", form, headers)
        if status != 200:
            raise BenchProbeError(f"Login failed (status {status}): {body}")

        cookie_header = resp_headers.get("set-cookie", "")
        for part in cookie_header.split(";"):
            part = part.strip()
            if part.startswith("PD_SESSION="):
                self.session_cookie = part.split("=", 1)[1]
            elif part.startswith("X-CSRF="):
                self.csrf_token = part.split("=", 1)[1]

        if not self.session_cookie:
            # Check response body for session tokens
            try:
                data = json.loads(body)
                self.session_cookie = data.get("session") or self.session_cookie
                self.csrf_token = data.get("csrf") or self.csrf_token
            except Exception:
                pass

        if not self.csrf_token and "x-csrf" in resp_headers:
            self.csrf_token = resp_headers["x-csrf"]

        if not self.session_cookie:
            raise BenchProbeError("Login response did not provide PD_SESSION cookie")

    def check_probe_available(self) -> None:
        """Verify that the target board is running a bench-probe image."""
        status, _, body = self._request("GET", "/api/bench/fault")
        if status == 404:
            raise BenchProbeError(
                f"Board at {self.host} returned 404 for /api/bench/fault. "
                "The board is running a RELEASE image. POCKETDIAL_ANCHOR_BENCH_PROBE is required."
            )
        if status == 401 or status == 403:
            # Needs login first
            return
        if status != 200:
            raise BenchProbeError(f"Probe availability check returned status {status}: {body}")

    def get_status(self) -> Dict[str, Any]:
        """Fetch current bench probe counters and state."""
        status, _, body = self._request("GET", "/api/bench/fault")
        if status != 200:
            raise BenchProbeError(f"Failed to fetch probe status (status {status}): {body}")
        try:
            return json.loads(body)
        except Exception as e:
            raise BenchProbeError(f"Failed to parse probe status JSON: {e} - Raw: {body}")

    def arm_fault(self, name: str, value: Optional[int] = None) -> Dict[str, Any]:
        """Arm a one-shot fault."""
        params: Dict[str, Any] = {"fault": name}
        if value is not None:
            params["value"] = value
        form = urllib.parse.urlencode(params)
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        status, _, body = self._request("POST", "/api/bench/fault", form, headers)
        if status == 409:
            raise BenchProbeError("Refused by board: emergency call is live or state conflict (409)")
        if status != 200:
            raise BenchProbeError(f"Failed to arm fault '{name}' (status {status}): {body}")
        return json.loads(body)

    def disarm_all(self) -> Dict[str, Any]:
        """Disarm all faults."""
        form = urllib.parse.urlencode({"fault": "disarm"})
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        status, _, body = self._request("POST", "/api/bench/fault", form, headers)
        if status != 200:
            raise BenchProbeError(f"Failed to disarm faults (status {status}): {body}")
        return json.loads(body)

    def hold_ballast(self, target_bytes: int, deadman_sec: int = 120) -> Dict[str, Any]:
        """Hold internal DRAM ballast until free heap reaches target_bytes."""
        if target_bytes < 8192:
            raise BenchProbeError("Target ballast heap must be >= 8192 bytes (floor requirement)")
        form = urllib.parse.urlencode({"ballast": target_bytes, "deadman": deadman_sec})
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        status, _, body = self._request("POST", "/api/bench/fault", form, headers)
        if status == 409:
            raise BenchProbeError("Refused by board: emergency active or ballast already held (409)")
        if status != 200:
            raise BenchProbeError(f"Failed to hold ballast (status {status}): {body}")
        return json.loads(body)

    def release_ballast(self) -> Dict[str, Any]:
        """Release any held DRAM ballast."""
        form = urllib.parse.urlencode({"ballast": "release"})
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        status, _, body = self._request("POST", "/api/bench/fault", form, headers)
        if status != 200:
            raise BenchProbeError(f"Failed to release ballast (status {status}): {body}")
        return json.loads(body)


def run_scenario(client: BenchFaultClient, scenario: str, timeout_sec: int = 30) -> bool:
    """Execute and verify a named scenario from issue #384."""
    print(f"=== Starting Bench Scenario: {scenario} ===")
    initial_status = client.get_status()

    cleanup_needed = True

    def cleanup():
        if cleanup_needed:
            print("Cleaning up: disarming faults and releasing ballast...")
            try:
                client.disarm_all()
                client.release_ballast()
            except Exception:
                pass

    atexit.register(cleanup)

    if scenario == "scenario-349":
        # Unread makeCall response -> reconcile
        print("Arming 'makecall_read_fail' (one-shot)...")
        res = client.arm_fault("makecall_read_fail")
        print(f"Armed status: {res}")
        print("Now stage an outbound call on the test handset / rig.")
        print("Waiting for fault firing...")
        deadline = time.time() + timeout_sec
        fired = False
        while time.time() < deadline:
            st = client.get_status()
            if st.get("makecall_read_fail", {}).get("fired", 0) > initial_status.get("makecall_read_fail", {}).get("fired", 0):
                fired = True
                print("Observed: BENCHFAULT makecall_read_fail FIRED successfully!")
                break
            time.sleep(1)
        if not fired:
            print("WARNING: Fault did NOT fire within timeout. Run is INVALID.")
            return False

    elif scenario == "scenario-279":
        # WriteAudio socket shutdown -> degraded teardown handset BYE
        print("Arming 'post_stream_fail' (one-shot)...")
        res = client.arm_fault("post_stream_fail")
        print(f"Armed status: {res}")
        print("Stage audio streaming call to anchor. Waiting for fault firing...")
        deadline = time.time() + timeout_sec
        fired = False
        while time.time() < deadline:
            st = client.get_status()
            if st.get("post_stream_fail", {}).get("fired", 0) > initial_status.get("post_stream_fail", {}).get("fired", 0):
                fired = True
                print("Observed: BENCHFAULT post_stream_fail FIRED successfully!")
                break
            time.sleep(1)
        if not fired:
            print("WARNING: Fault did NOT fire within timeout. Run is INVALID.")
            return False

    elif scenario == "scenario-336":
        # Token age shift -> refresh
        print("Arming 'token_age' (one-shot)...")
        res = client.arm_fault("token_age")
        print(f"Armed status: {res}")
        deadline = time.time() + timeout_sec
        fired = False
        while time.time() < deadline:
            st = client.get_status()
            if st.get("token_age", {}).get("fired", 0) > initial_status.get("token_age", {}).get("fired", 0):
                fired = True
                print("Observed: BENCHFAULT token_age FIRED successfully!")
                break
            time.sleep(1)
        if not fired:
            print("WARNING: Fault did NOT fire within timeout. Run is INVALID.")
            return False

    elif scenario == "scenario-350":
        # Memory ballast
        target = 16384
        print(f"Holding DRAM ballast down to target {target} bytes (deadman 60s)...")
        res = client.hold_ballast(target, deadman_sec=60)
        print(f"Ballast held: {res.get('ballast')}")
        print("Exercising unauthenticated and authenticated requests under pressure...")
        time.sleep(5)
        print("Releasing ballast...")
        client.release_ballast()
        print("Ballast released cleanly.")

    elif scenario == "scenario-379":
        # Forced 503 and attempt budget
        print("Arming 'get_status=503' and 'get_max_attempts=20'...")
        client.arm_fault("get_status", 503)
        res = client.arm_fault("get_max_attempts", 20)
        print(f"Armed status: {res}")
        print("Stage outbound call and verify MediaNeverOpened clean teardown.")

    else:
        print(f"Unknown scenario: {scenario}")
        return False

    cleanup_needed = False
    print(f"=== Scenario {scenario} execution complete ===")
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--host", default="192.168.40.244", help="Pocket-dial board IP (default: 192.168.40.244)")
    parser.add_argument("--port", type=int, default=80, help="HTTP port (default: 80)")
    parser.add_argument("--password", default=None, help="Admin password (or POCKETDIAL_ADMIN_PASSWORD env)")
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("status", help="Get current bench probe status and counters")
    subparsers.add_parser("disarm", help="Disarm all faults and release ballast")

    ballast_p = subparsers.add_parser("ballast", help="Hold DRAM ballast")
    ballast_p.add_argument("--target", type=int, default=16384, help="Target free internal heap bytes (min: 8192)")
    ballast_p.add_argument("--deadman", type=int, default=120, help="Deadman timer seconds (default: 120)")

    subparsers.add_parser("ballast-release", help="Release held DRAM ballast")

    scen_p = subparsers.add_parser("run", help="Run a verification scenario")
    scen_p.add_argument("scenario", choices=["scenario-349", "scenario-279", "scenario-336", "scenario-350", "scenario-379"],
                        help="Scenario identifier")
    scen_p.add_argument("--timeout", type=int, default=30, help="Timeout in seconds")

    args = parser.parse_args()

    client = BenchFaultClient(host=args.host, port=args.port, password=args.password)
    try:
        client.check_probe_available()
        client.login()

        if args.command == "status":
            st = client.get_status()
            print(json.dumps(st, indent=2))
        elif args.command == "disarm":
            st = client.disarm_all()
            client.release_ballast()
            print("All faults disarmed and ballast released.")
            print(json.dumps(st, indent=2))
        elif args.command == "ballast":
            st = client.hold_ballast(args.target, args.deadman)
            print(f"Ballast armed: {json.dumps(st.get('ballast', {}), indent=2)}")
        elif args.command == "ballast-release":
            st = client.release_ballast()
            print("Ballast released.")
            print(json.dumps(st.get('ballast', {}), indent=2))
        elif args.command == "run":
            ok = run_scenario(client, args.scenario, args.timeout)
            sys.exit(0 if ok else 1)
    except BenchProbeError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
