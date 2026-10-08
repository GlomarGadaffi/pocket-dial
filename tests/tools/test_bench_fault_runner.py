"""Unit tests for tools/bench/bench_fault_runner.py (#384, #328)."""

import os
import sys
import unittest
from unittest.mock import MagicMock, patch

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "tools", "bench"))
import bench_fault_runner as bfr  # noqa: E402


class BenchFaultRunnerTest(unittest.TestCase):
    def setUp(self):
        self.client = bfr.BenchFaultClient("127.0.0.1", 80, "testpass")

    @patch.object(bfr.BenchFaultClient, "_request")
    def test_login_extracts_cookie_and_csrf(self, mock_req):
        mock_req.return_value = (
            200,
            {"set-cookie": "PD_SESSION=abc123session; Path=/", "x-csrf": "csrf-tok-456"},
            '{"status":"ok"}',
        )
        self.client.login()
        self.assertEqual(self.client.session_cookie, "abc123session")
        self.assertEqual(self.client.csrf_token, "csrf-tok-456")

    @patch.object(bfr.BenchFaultClient, "_request")
    def test_check_probe_404_raises_release_image_error(self, mock_req):
        mock_req.return_value = (404, {}, "Not Found")
        with self.assertRaises(bfr.BenchProbeError) as ctx:
            self.client.check_probe_available()
        self.assertIn("RELEASE image", str(ctx.exception))

    def test_ballast_floor_enforced(self):
        with self.assertRaises(bfr.BenchProbeError) as ctx:
            self.client.hold_ballast(4096)  # Below 8192 B floor
        self.assertIn(">= 8192 bytes", str(ctx.exception))

    @patch.object(bfr.BenchFaultClient, "_request")
    def test_arm_fault_success(self, mock_req):
        mock_req.return_value = (
            200,
            {},
            '{"makecall_read_fail":{"armed":true,"fired":0}}',
        )
        res = self.client.arm_fault("makecall_read_fail")
        self.assertTrue(res["makecall_read_fail"]["armed"])

    @patch.object(bfr.BenchFaultClient, "_request")
    def test_arm_fault_emergency_conflict(self, mock_req):
        mock_req.return_value = (409, {}, "Emergency call live")
        with self.assertRaises(bfr.BenchProbeError) as ctx:
            self.client.arm_fault("makecall_read_fail")
        self.assertIn("emergency call is live", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
