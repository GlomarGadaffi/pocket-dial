#!/usr/bin/env python3
"""Test-count floor for the host suite (#390, made mergeable by #467).

ctest runs the whole gtest suite as ONE ctest test, so the only count CI ever
printed was "0 tests failed out of 1". That cannot tell 1235 passing tests from
12: a source dropped from the CMake target, an #if that compiles a file empty,
or a stray filter all go green with identical output.

This reads the JSON reports gtest writes when GTEST_OUTPUT=json:<dir>/ is set
on the ctest step (one file per test binary), prints how many tests actually
RAN, and fails if that is below the floor.

THE FLOOR (#467) is a sum, so that concurrent PRs never edit the same line:

    tests/EXPECTED_MIN_TESTS            the BASE: an audited count on main
  + tests/min_tests.d/<issue>-<slug>.txt   one small file per PR, holding the
                                        signed number of tests that PR adds
                                        (or removes, as a negative number)

Before #467 every PR that added tests rewrote the single number in
EXPECTED_MIN_TESTS, so any two such PRs conflicted and whichever merged second
had to be rebased just to re-add a count. Separate files merge in any order.

A contribution file's first non-blank, non-# line is its signed integer
("4", "+4" or "-2"). Its name must look like 1234-short-slug.txt, so each file
says which issue it belongs to. Removing tests on purpose is a NEGATIVE
contribution: the reduction still shows in the diff instead of passing
silently.

Fails CLOSED. No report directory, no reports in it, a report that does not
parse, an unreadable base, or a malformed or misnamed contribution is a
failure, not a pass. A check that goes green when its input is missing is the
#262 failure mode (a green that only says the step ran).

    python3 tests/tools/check_test_count.py <report-dir> [<base-file> [<contrib-dir>]]
    python3 tests/tools/check_test_count.py --compact [<base-file> [<contrib-dir>]]

--compact folds every contribution into the base and deletes the files (run
it on main now and then, in its own PR, once the directory gets long). It
does not need reports.

Exit status 0 = at or above the floor, 1 = below it, 2 = no usable input.
"""

import glob
import json
import os
import re
import sys

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
DEFAULT_BASE = os.path.join(REPO, "tests", "EXPECTED_MIN_TESTS")
DEFAULT_CONTRIB_DIR = os.path.join(REPO, "tests", "min_tests.d")

# <issue number>-<slug>.txt, e.g. 470-cdr-nvs-blob.txt
CONTRIB_NAME = re.compile(r"^[0-9]+-[a-z0-9][a-z0-9-]*\.txt$")


def read_number(path, signed=False):
    """The first non-blank, non-# line of `path`, as an int."""
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if not re.fullmatch(r"[+-]?[0-9]+" if signed else r"[0-9]+", line):
                raise ValueError(f"{path}: expected {'a signed ' if signed else 'an '}integer, got {line!r}")
            return int(line)
    raise ValueError("no number in " + path)


def read_contributions(contrib_dir):
    """[(filename, n)] sorted by name. A missing directory means none."""
    if not os.path.isdir(contrib_dir):
        return []
    out = []
    for name in sorted(os.listdir(contrib_dir)):
        path = os.path.join(contrib_dir, name)
        if name.startswith(".") or name.lower() == "readme.md":
            continue
        if not os.path.isfile(path):
            raise ValueError(f"{path}: not a file")
        if not CONTRIB_NAME.match(name):
            raise ValueError(f"{name}: contribution files are named <issue>-<slug>.txt "
                             "(lowercase), e.g. 470-cdr-nvs-blob.txt")
        out.append((name, read_number(path, signed=True)))
    return out


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


def compute_floor(base_path, contrib_dir):
    """(floor, lines-to-print). Raises OSError/ValueError on bad input."""
    base = read_number(base_path)
    contribs = read_contributions(contrib_dir)
    lines = [f"floor base: {base} ({os.path.relpath(base_path, REPO)})"]
    for name, n in contribs:
        lines.append(f"  {n:+d}  {os.path.relpath(os.path.join(contrib_dir, name), REPO)}")
    floor = base + sum(n for _, n in contribs)
    lines.append(f"floor: {floor} = base {base}"
                 + (f" + {len(contribs)} contribution(s) ({sum(n for _, n in contribs):+d})" if contribs else ""))
    return floor, lines


def compact(base_path, contrib_dir):
    floor, lines = compute_floor(base_path, contrib_dir)
    for line in lines:
        print(line)
    with open(base_path, encoding="utf-8") as f:
        text = f.read()
    # Replace the number line only; keep the header comments.
    new, n = re.subn(r"(?m)^[0-9]+[ \t]*$", str(floor), text, count=1)
    if n != 1:
        raise ValueError(f"{base_path}: no bare number line to replace")
    with open(base_path, "w", encoding="utf-8") as f:
        f.write(new)
    for name, _ in read_contributions(contrib_dir):
        os.remove(os.path.join(contrib_dir, name))
    print(f"compacted: base is now {floor}; contribution files removed")
    return 0


def main(argv):
    args = argv[1:]
    if args and args[0] == "--compact":
        base_path = args[1] if len(args) > 1 else DEFAULT_BASE
        contrib_dir = args[2] if len(args) > 2 else DEFAULT_CONTRIB_DIR
        try:
            return compact(base_path, contrib_dir)
        except (OSError, ValueError) as e:
            print(f"::error::cannot compact the test-count floor: {e}")
            return 2

    if len(args) not in (1, 2, 3):
        print(__doc__)
        return 2
    report_dir = args[0]
    base_path = args[1] if len(args) > 1 else DEFAULT_BASE
    contrib_dir = args[2] if len(args) > 2 else DEFAULT_CONTRIB_DIR

    try:
        floor, lines = compute_floor(base_path, contrib_dir)
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

    for line in lines:
        print(line)
    print(f"host suite: {total_ran} tests ran; floor {floor}")
    if total_ran < floor:
        print(f"::error::only {total_ran} tests ran, below the floor of {floor} -- "
              f"{floor - total_ran} missing. A test source dropped from the build, an #if "
              "compiling a file empty, or a filter would all do this. If tests were removed "
              "on purpose, add a NEGATIVE contribution in tests/min_tests.d/ in the same PR.")
        return 1
    if total_ran > floor:
        print(f"note: {total_ran - floor} above the floor. A PR that adds tests should add "
              "tests/min_tests.d/<issue>-<slug>.txt with that number, or the headroom lets a "
              "later drop of that size through unnoticed.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
