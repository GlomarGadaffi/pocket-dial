#!/usr/bin/env python3
"""Test-count floor for the host suite (#390).

ctest runs the whole gtest suite as ONE ctest test, so the only count CI ever
printed was "0 tests failed out of 1". That cannot tell 1235 passing tests from
12: a source dropped from the CMake target, an #if that compiles a file empty,
or a stray filter all go green with identical output.

This reads the JSON reports gtest writes when GTEST_OUTPUT=json:<dir>/ is set
on the ctest step (one file per test binary), prints how many tests actually
RAN, and fails if that is below the checked-in floor in tests/EXPECTED_MIN_TESTS.

A floor, not an exact match: two PRs that each add tests must not conflict
over one number. A PR that adds tests raises the floor to its new count; a PR
that removes tests on purpose lowers it, visibly, in the diff.

Fails CLOSED. No report directory, no reports in it, or a report that does not
parse is a failure, not a pass -- a check that goes green when its input is
missing is the #262 failure mode (a green that only says the step ran).

    python3 tests/tools/check_test_count.py <report-dir> [<floor-file>]

Exit status 0 = at or above the floor, 1 = below it, 2 = no usable report or
floor.
"""

import glob
import json
import os
import sys

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
DEFAULT_FLOOR = os.path.join(REPO, "tests", "EXPECTED_MIN_TESTS")


def read_floor(path):
    """The first non-blank, non-# line, as an int."""
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                return int(line)
    raise ValueError("no number in " + path)


def count_report(path):
    """(ran, skipped, suites) for one gtest JSON report.

    Counted per test case, not from the header's "tests" total: a test that
    was filtered out or GTEST_SKIP()ed is listed there too, and neither ran.
    """
    with open(path, encoding="utf-8") as f:
        doc = json.load(f)
    ran = skipped = 0
    suites = doc.get("testsuites", [])
    for suite in suites:
        for case in suite.get("testsuite", []):
            if case.get("status") != "RUN":
                continue            # NOTRUN: disabled or filtered out
            if case.get("result") == "SKIPPED":
                skipped += 1
            else:
                ran += 1
    return ran, skipped, len(suites)


def main(argv):
    if len(argv) not in (2, 3):
        print(__doc__)
        return 2
    report_dir = argv[1]
    floor_path = argv[2] if len(argv) == 3 else DEFAULT_FLOOR

    try:
        floor = read_floor(floor_path)
    except (OSError, ValueError) as e:
        print(f"::error::test-count floor unreadable: {e}")
        return 2

    reports = sorted(glob.glob(os.path.join(report_dir, "*.json")))
    if not reports:
        print(f"::error::no gtest JSON reports in {report_dir} -- was GTEST_OUTPUT set on the "
              "test step? Failing closed: no report is not a pass.")
        return 2

    total_ran = total_skipped = 0
    for path in reports:
        try:
            ran, skipped, suites = count_report(path)
        except (OSError, ValueError) as e:
            print(f"::error::unreadable gtest report {path}: {e}")
            return 2
        print(f"{os.path.basename(path)}: {ran} tests ran from {suites} test suites"
              + (f", {skipped} skipped" if skipped else ""))
        total_ran += ran
        total_skipped += skipped

    print(f"host suite: {total_ran} tests ran; floor {floor} ({os.path.relpath(floor_path, REPO)})")
    if total_ran < floor:
        print(f"::error::only {total_ran} tests ran, below the floor of {floor} -- "
              f"{floor - total_ran} missing. A test source dropped from the build, an #if "
              "compiling a file empty, or a filter would all do this. If tests were removed "
              "on purpose, lower tests/EXPECTED_MIN_TESTS in the same PR.")
        return 1
    if total_ran > floor:
        print(f"note: {total_ran - floor} above the floor. A PR that adds tests should raise "
              "tests/EXPECTED_MIN_TESTS to its new count, or the headroom lets a later drop "
              "of that size through unnoticed.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
