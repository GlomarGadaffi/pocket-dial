#!/usr/bin/env python3
"""Fail if a built tree carries the #384 bench probe (POCKETDIAL_ANCHOR_BENCH_PROBE).

The probe image (docs/BENCH_PROBE.md) arms one-shot anchor faults and DRAM
ballast over POST /api/bench/fault. It is bench-only: every byte of it sits
under `#if defined(POCKETDIAL_ANCHOR_BENCH_PROBE)`, so a release image costs
0 B. This checks the result on a built ESP-IDF tree, not the intent:

  1. the app image holds neither the probe's log tag nor its route;
  2. CMakeCache.txt does not have the option on;
  3. the stamp CMake chose (pocketdial_fw_version.txt) does not carry -probe.

    python3 tools/ci/check_no_bench_probe.py <build-dir>

Exit 0 = no probe, 1 = the probe is in this build, 2 = the build dir is unusable.
tests/tools/test_bench_probe_release.py pins the scanner and the source-level
guards (every probe line under the macro, the CMake refusals) on a host-only run.
"""

import os
import sys

OPTION = "POCKETDIAL_ANCHOR_BENCH_PROBE"
# The fixed log tag every fault prints ("BENCHFAULT <name> fired") and the route.
MARKERS = (b"BENCHFAULT", b"/api/bench/fault")
PROBE_SUFFIX = "-probe"
CMAKE_TRUE = {"1", "ON", "YES", "TRUE", "Y"}


class Unusable(Exception):
    pass


def image_markers(data):
    """The probe markers present in an app image, in MARKERS order."""
    return [m.decode() for m in MARKERS if m in data]


def cmake_true(value):
    v = value.strip().upper()
    if v in CMAKE_TRUE:
        return True
    try:
        return float(v) != 0
    except ValueError:
        return False


def cache_has_probe(text):
    """True if CMakeCache.txt sets the option to a CMake-true value."""
    for line in text.splitlines():
        if line.startswith(OPTION + ":") or line.startswith(OPTION + "="):
            return cmake_true(line.split("=", 1)[1] if "=" in line else "")
    return False


def stamp_is_probe(stamp):
    s = stamp.strip()
    return s.endswith(PROBE_SUFFIX) or s.endswith(PROBE_SUFFIX + "-dirty")


def check(build_dir):
    """The list of problems in `build_dir` (empty = no probe). Raises Unusable."""
    image = os.path.join(build_dir, "SipServer.bin")
    if not os.path.isfile(image):
        raise Unusable(f"no app image at {image}")
    problems = []
    with open(image, "rb") as f:
        found = image_markers(f.read())
    if found:
        problems.append(f"{image} contains the bench probe: {', '.join(found)}")
    cache = os.path.join(build_dir, "CMakeCache.txt")
    if os.path.isfile(cache):
        with open(cache, encoding="utf-8", errors="replace") as f:
            if cache_has_probe(f.read()):
                problems.append(f"{cache} has {OPTION} on")
    stamp_file = os.path.join(build_dir, "pocketdial_fw_version.txt")
    if os.path.isfile(stamp_file):
        with open(stamp_file, encoding="utf-8") as f:
            stamp = f.read().strip()
        if stamp_is_probe(stamp):
            problems.append(f"the build is stamped '{stamp}', a bench probe stamp")
    return problems


def main(argv):
    if len(argv) != 2:
        print(__doc__.strip().splitlines()[0])
        print("usage: check_no_bench_probe.py <build-dir>", file=sys.stderr)
        return 2
    try:
        problems = check(argv[1])
    except Unusable as e:
        print(f"FAIL: {e}", file=sys.stderr)
        return 2
    for p in problems:
        print(f"::error title=bench probe in a release build (#384)::{p}")
    if problems:
        return 1
    print("PASS: no bench probe in this build (#384)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
