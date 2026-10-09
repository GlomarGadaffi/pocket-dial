"""#731 source gate: the constrained build names exactly one outside-line path.

SIP_OUTSIDE_LINE=anchor is required with SIP_CONSTRAINED=1 and reaches the source as
POCKETDIAL_HAS_ANCHOR=1 / POCKETDIAL_HAS_TRUNK=0 (ADR-002). SIP_OUTSIDE_LINE=trunk is
refused there: the SIP trunk is shelved and cannot carry 911 or 933. CMake and the CI YAML
never run on the host, so this reads them as text, like the other tests/tools gates.
"""
import os
import re
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))


def read(path):
    with open(os.path.join(ROOT, path), encoding="utf-8") as f:
        return f.read()


class OutsideLineSelector(unittest.TestCase):
    def test_cmake_requires_the_anchor_when_constrained(self):
        cm = read("main/CMakeLists.txt")
        sel = cm[cm.index("set(_pd_has_anchor 1)"):]
        sel = sel[:sel.index("message(STATUS \"SipServer outside line")]
        self.assertRegex(sel, r"if\(SIP_CONSTRAINED\)\s+if\(NOT SIP_OUTSIDE_LINE\)\s+message\(FATAL_ERROR")
        self.assertRegex(sel, r'elseif\(SIP_OUTSIDE_LINE STREQUAL "anchor"\)\s+set\(_pd_has_trunk 0\)')
        # The trunk is refused on the constrained build, not selected: no branch takes it.
        self.assertNotIn('STREQUAL "trunk"', sel)
        self.assertRegex(sel, r"else\(\)\s+message\(FATAL_ERROR \"SIP_OUTSIDE_LINE must be 'anchor'")
        # A choice on a non-constrained build is refused, not ignored.
        self.assertRegex(sel, r"elseif\(SIP_OUTSIDE_LINE\)\s+message\(FATAL_ERROR")
        self.assertRegex(cm, r"POCKETDIAL_HAS_ANCHOR=\$\{_pd_has_anchor\}\s+POCKETDIAL_HAS_TRUNK=\$\{_pd_has_trunk\}")

    def test_non_constrained_and_host_builds_keep_both_paths(self):
        cm = read("main/CMakeLists.txt")
        self.assertRegex(cm, r"set\(_pd_has_anchor 1\)\s+set\(_pd_has_trunk 1\)\s+if\(SIP_CONSTRAINED\)")
        cfg = read("src/SIP/PoolConfig.hpp")
        self.assertRegex(cfg, r"#ifndef POCKETDIAL_HAS_ANCHOR\s+#define POCKETDIAL_HAS_ANCHOR 1\s+#endif")
        self.assertRegex(cfg, r"#ifndef POCKETDIAL_HAS_TRUNK\s+#define POCKETDIAL_HAS_TRUNK 1\s+#endif")
        self.assertRegex(cfg, r"static_assert\(POCKETDIAL_HAS_ANCHOR \|\| POCKETDIAL_HAS_TRUNK")

    def test_ci_builds_only_the_anchor_constrained_variant(self):
        ci = read(".github/workflows/ci.yml")
        builds = re.findall(r"idf\.py[^\n]*SIP_CONSTRAINED=1[^\n]*", ci)
        self.assertEqual(len(builds), 1, "one constrained build: the anchor (ADR-002)")
        self.assertIn("SIP_OUTSIDE_LINE=anchor", builds[0])
        self.assertNotIn("SIP_OUTSIDE_LINE=trunk", ci)
        self.assertNotIn("build-constrained-trunk", ci)
        # The build is checked against the #489 app-slot margin.
        jobs = ci[ci.index("  build-constrained:"):ci.index("  # Job 3: Security")]
        self.assertEqual(jobs.count("python3 tools/ci/app_slot_margin.py build"), 1)


if __name__ == "__main__":
    unittest.main()
