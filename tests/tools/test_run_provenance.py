"""Tests for tests/run.py's board-provenance verdicts (issue #411).

Run: python3 -m unittest discover -s tests/tools -p "test_*.py"

The point of #411 on the harness side: a board that cannot say which build it
runs must FAIL provenance, never pass by default. Before #411, an absent
"version" skipped the comparison and the suite reported PASS.

The Harness is built without __init__ (which parses CLI args and runs git),
and /api/status is supplied directly, so only the verdict logic is under test.
"""

import os
import sys
import types
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.normpath(os.path.join(HERE, "..")))
import run  # noqa: E402  (tests/run.py)

DESCRIBE = "v1.5.0-beta.2-104-g8d76d64"


def harness(status, describe=DESCRIBE):
    h = run.Harness.__new__(run.Harness)
    h.target_type = "board"
    h.target_ip = "192.0.2.10"
    h.git_describe = describe
    h.verdicts = {}
    h.log_suite = lambda name, text: None
    h.fetch_api_status = types.MethodType(lambda self, ip, *a, **k: dict(status), h)
    return h


class ProvenanceTest(unittest.TestCase):
    def verdict(self, status, **kw):
        h = harness(status, **kw)
        ok = h.run_board_provenance()
        return h.verdicts["board-provenance"]["verdict"], ok, h.verdicts["board-provenance"]["details"]

    def test_a_missing_version_fails_instead_of_passing(self):
        v, ok, details = self.verdict({"resetReason": "POWERON"})
        self.assertEqual(v, "FAIL")
        self.assertFalse(ok)
        self.assertIn("pre-#411", details)

    def test_the_idf_fallback_and_unknown_fail(self):
        for ver in ("1", "unknown"):
            with self.subTest(version=ver):
                v, ok, _ = self.verdict({"version": ver, "resetReason": "POWERON"})
                self.assertEqual(v, "FAIL")
                self.assertFalse(ok)

    def test_a_matching_stamp_passes(self):
        for ver in (DESCRIBE, DESCRIBE + "-dirty", "8d76d64", "8d76d64-dirty"):
            with self.subTest(version=ver):
                v, ok, _ = self.verdict({"version": ver, "resetReason": "POWERON"})
                self.assertIn(v, ("PASS",), ver)
                self.assertTrue(ok)

    def test_a_different_build_is_still_warn_until_board_flash_lands(self):
        # Unchanged policy (TEST_HARNESS.md: mismatch is WARN until #338).
        v, ok, _ = self.verdict({"version": "v1.5.0-beta.2-93-g98cc830", "resetReason": "POWERON"})
        self.assertEqual(v, "WARN")
        self.assertTrue(ok)

    def test_missing_reset_reason_still_fails_first(self):
        v, ok, details = self.verdict({"version": DESCRIBE})
        self.assertEqual(v, "FAIL")
        self.assertIn("resetReason", details)


if __name__ == "__main__":
    unittest.main()
