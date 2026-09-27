#!/usr/bin/env python3
"""Self-test for check_test_count.py (#467). Runs in CI before the real check:

    python3 -m unittest discover -s tests/tools -p 'test_check_test_count.py'

Every case builds its own base file, contribution directory and fake gtest
JSON reports in a temp dir, so it needs no build and touches nothing real.
"""

import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import check_test_count as ctc  # noqa: E402


def write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)


def report(ran, skipped=0, notrun=0):
    cases = [{"name": f"t{i}", "status": "RUN", "result": "COMPLETED"} for i in range(ran)]
    cases += [{"name": f"s{i}", "status": "RUN", "result": "SKIPPED"} for i in range(skipped)]
    cases += [{"name": f"n{i}", "status": "NOTRUN"} for i in range(notrun)]
    return json.dumps({"testsuites": [{"name": "Suite", "testsuite": cases}]})


class Rig:
    def __init__(self, base=100, contribs=None, ran=100, **kw):
        self.tmp = tempfile.TemporaryDirectory()
        d = self.tmp.name
        self.base = os.path.join(d, "EXPECTED_MIN_TESTS")
        self.contrib = os.path.join(d, "min_tests.d")
        self.reports = os.path.join(d, "reports")
        write(self.base, f"# header\n{base}\n")
        os.makedirs(self.contrib)
        for name, text in (contribs or {}).items():
            write(os.path.join(self.contrib, name), text)
        write(os.path.join(self.reports, "sip_parser_tests.json"), report(ran, **kw))

    def run(self):
        out = io.StringIO()
        with redirect_stdout(out):
            rc = ctc.main(["check_test_count.py", self.reports, self.base, self.contrib])
        return rc, out.getvalue()


class FloorIsBasePlusContributions(unittest.TestCase):
    def test_base_alone_passes_at_the_count(self):
        rc, out = Rig(base=100, ran=100).run()
        self.assertEqual(rc, 0, out)
        self.assertIn("floor: 100 = base 100", out)

    def test_contributions_sum_and_are_each_printed(self):
        rc, out = Rig(base=100, contribs={"459-server-cseq.txt": "4\n", "471-lookups.txt": "# c\n+4\n"},
                      ran=108).run()
        self.assertEqual(rc, 0, out)
        self.assertIn("+4  ", out)
        self.assertIn("459-server-cseq.txt", out)
        self.assertIn("471-lookups.txt", out)
        self.assertIn("floor: 108 = base 100 + 2 contribution(s) (+8)", out)

    def test_below_the_sum_fails(self):
        rc, out = Rig(base=100, contribs={"1-a.txt": "4"}, ran=103).run()
        self.assertEqual(rc, 1, out)
        self.assertIn("1 missing", out)

    def test_a_deliberate_removal_is_a_negative_contribution(self):
        rc, out = Rig(base=100, contribs={"2-drop-dead-tests.txt": "-3"}, ran=97).run()
        self.assertEqual(rc, 0, out)

    def test_an_undeclared_removal_goes_red(self):
        # The positive control #467 asks for: tests disappear, nobody says so.
        rc, out = Rig(base=100, contribs={"3-adds.txt": "2"}, ran=100).run()
        self.assertEqual(rc, 1, out)

    def test_skipped_and_notrun_cases_do_not_count(self):
        rc, out = Rig(base=100, ran=99, skipped=5, notrun=5).run()
        self.assertEqual(rc, 1, out)

    def test_headroom_is_a_note_not_a_failure(self):
        rc, out = Rig(base=100, ran=104).run()
        self.assertEqual(rc, 0, out)
        self.assertIn("4 above the floor", out)


class FailsClosed(unittest.TestCase):
    def test_misnamed_contribution(self):
        rc, out = Rig(contribs={"MyChange.txt": "4"}).run()
        self.assertEqual(rc, 2, out)

    def test_non_integer_contribution(self):
        rc, out = Rig(contribs={"4-x.txt": "four"}).run()
        self.assertEqual(rc, 2, out)

    def test_empty_contribution(self):
        rc, out = Rig(contribs={"5-x.txt": "# nothing\n"}).run()
        self.assertEqual(rc, 2, out)

    def test_signed_base_is_rejected(self):
        r = Rig()
        write(r.base, "+100\n")
        rc, out = r.run()
        self.assertEqual(rc, 2, out)

    def test_no_reports(self):
        r = Rig()
        os.remove(os.path.join(r.reports, "sip_parser_tests.json"))
        rc, out = r.run()
        self.assertEqual(rc, 2, out)

    def test_readme_in_the_directory_is_ignored(self):
        rc, out = Rig(contribs={"README.md": "how to"}, ran=100).run()
        self.assertEqual(rc, 0, out)


class Compact(unittest.TestCase):
    def test_folds_contributions_into_the_base_and_removes_them(self):
        r = Rig(base=100, contribs={"1-a.txt": "4", "2-b.txt": "-1", "README.md": "keep"})
        out = io.StringIO()
        with redirect_stdout(out):
            rc = ctc.main(["check_test_count.py", "--compact", r.base, r.contrib])
        self.assertEqual(rc, 0, out.getvalue())
        with open(r.base, encoding="utf-8") as f:
            text = f.read()
        self.assertIn("# header", text)
        self.assertEqual(ctc.read_number(r.base), 103)
        self.assertEqual(sorted(os.listdir(r.contrib)), ["README.md"])


if __name__ == "__main__":
    unittest.main()
