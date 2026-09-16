#!/usr/bin/env python3
"""Measure MSVC's real string-literal caps (issue #270).

`tools/check_string_literal_caps.py` hard-fails a build on three constants.
Constants like that rot into folklore unless the measurement that produced
them can be repeated, so this is that measurement, as a script.

It is WINDOWS-ONLY and is NOT part of CI -- CI runs the byte check, which
needs no compiler. Run this by hand when bumping the toolchain, when a
constant looks wrong, or when someone asks where the numbers came from:

    # from a Developer Command Prompt, or after vcvars64.bat
    python tools\\msvc_literal_cap_probe.py

Each probe is a complete translation unit compiled with `cl /std:c++17 /c`.
A probe "passes" if cl exits 0 and "fails" if it emits C2026.

WHAT THIS FOUND (cl 19.44.35228, VS 2022 BuildTools, 2026-09-16)
----------------------------------------------------------------
  raw literal, 16384 bytes of content ........... OK
  raw literal, 16385 ............................ C2026
  raw literal, 16510 (cap + 126) ................ C2026
  ordinary literal, 16383 chars of result ....... OK
  ordinary literal, 16384 ....................... C2026
  ordinary literal, 16383 escapes (32766 source
    bytes) ...................................... OK   <- counted by RESULT
  ordinary literal, 16384 escapes ............... C2026
  4 adjacent raw literals, 65535 bytes total .... OK
  4 adjacent raw literals, 65536 total .......... OK   <- docs say 65535
  40 adjacent raw literals, 655360 total ........ OK
  64 adjacent ordinary literals, 1048512 total .. OK

It then CROSS-CHECKS the byte checker against the compiler: it compiles a TU
including src/Helpers/index_html.h and compares every sizeof(PD_HTML_N)-1
against what tools/check_string_literal_caps.py reports for the same part.
That comparison is the point of this script as much as the caps are -- it is
what caught the checker measuring a CRLF working tree and over-reporting
every part by roughly its line count, which the caps alone would never have
revealed.

Two of the findings above contradict what was previously believed, which is
why the script exists:

  1. The raw and ordinary caps differ BY ONE (16384 vs 16383). A checker
     that applies one number to both is wrong for half its inputs.
  2. The 65535 concatenated-literal cap that MSVC documents, and that
     src/Helpers/index_html.h's header states as fact, is NOT ENFORCED by
     this compiler -- not at 10x it, not at 16x it. index_html.h's split is
     still required, but by the per-token cap alone.
"""

import os
import shutil
import subprocess
import sys
import tempfile

Q = chr(34)
BS = chr(92)


def raw_tu(sizes):
    """One declaration whose initializer is `sizes` adjacent RAW literals."""
    parts = ["R" + Q + "p" + str(n) + "(" + ("x" * sz) + ")p" + str(n) + Q
             for n, sz in enumerate(sizes)]
    return ("static const char S[] =\n" + "\n".join(parts) + ";\n"
            "int main(){ return (int)sizeof S; }\n")


def ordinary_tu(bodies):
    """One declaration whose initializer is `bodies` adjacent ORDINARY literals."""
    parts = [Q + b + Q for b in bodies]
    return ("static const char S[] =\n" + "\n".join(parts) + ";\n"
            "int main(){ return (int)sizeof S; }\n")


PROBES = [
    # (name, source, what a PASS would mean)
    ("raw_at_cap",        raw_tu([16384]),            "raw cap is at least 16384"),
    ("raw_over_cap",      raw_tu([16385]),            "raw cap is above 16384"),
    ("raw_cap_plus_126",  raw_tu([16510]),            "raw cap is above 16510"),
    ("ord_at_cap",        ordinary_tu(["x" * 16383]), "ordinary cap is at least 16383"),
    ("ord_over_cap",      ordinary_tu(["x" * 16384]), "ordinary cap is above 16383"),
    ("ord_escapes_at",    ordinary_tu([(BS + "n") * 16383]),
     "escapes are counted by RESULT, not by source bytes"),
    ("ord_escapes_over",  ordinary_tu([(BS + "n") * 16384]),
     "escapes are counted by source bytes, or not at all"),
    ("run_raw_65535",     raw_tu([16384, 16384, 16384, 16383]),
     "a 65535-byte concatenated run is allowed"),
    ("run_raw_65536",     raw_tu([16384, 16384, 16384, 16384]),
     "the documented 65535 concatenation cap is NOT enforced"),
    ("run_raw_655360",    raw_tu([16384] * 40),
     "no concatenation cap at 10x the documented one"),
    ("run_ord_1048512",   ordinary_tu(["x" * 16383] * 64),
     "no concatenation cap at 16x the documented one"),
]


HEADER = os.path.join("src", "Helpers", "index_html.h")

CROSSCHECK_TU = r"""#include "index_html.h"
#include <cstdio>
int main() {
    for (size_t i = 0; i < CGA_INDEX_HTML_PART_COUNT; ++i)
        std::printf("%zu\n", CGA_INDEX_HTML_PARTS[i].size);
    return 0;
}
"""


def crosscheck(cl):
    """Compare the byte checker's numbers against the compiler's own.

    This is the verification that matters most, and the one that caught a
    real bug: the checker read the working tree's CRLF bytes and reported
    every part ~2000 bytes larger than the compiler sees, because
    translation phase 1 turns CRLF into a single newline. Sizes that agree
    with sizeof(PD_HTML_N)-1, exactly, are the only proof that the byte
    count and the compiler are measuring the same thing.
    """
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    header = os.path.join(root, HEADER)
    if not os.path.isfile(header):
        print("  cross-check skipped: %s not found" % HEADER)
        return 0

    sys.path.insert(0, os.path.join(root, "tools"))
    from check_string_literal_caps import scan_literals, read_source, label_for

    text = read_source(header)
    lits = [l for l in scan_literals(text) if l.kind == "raw"]
    mine = [(label_for(text, l), l.counted) for l in lits]
    mine = [(n, c) for n, c in mine if n and n.startswith("PD_HTML_")]

    workdir = tempfile.mkdtemp(prefix="pd_literal_xcheck_")
    try:
        tu = os.path.join(workdir, "xcheck.cpp")
        with open(tu, "w", encoding="utf-8", newline=chr(10)) as f:
            f.write(CROSSCHECK_TU)
        exe = os.path.join(workdir, "xcheck.exe")
        r = subprocess.run([cl, "/nologo", "/std:c++17", "/EHsc",
                            "/I", os.path.join(root, "src", "Helpers"),
                            tu, "/Fe:" + exe, "/Fo:" + workdir + os.sep],
                           cwd=workdir, capture_output=True, text=True)
        if r.returncode != 0:
            print("  cross-check FAILED to compile index_html.h:")
            print((r.stdout or "") + (r.stderr or ""))
            return 1
        run = subprocess.run([exe], capture_output=True, text=True)
        theirs = [int(x) for x in run.stdout.split()]
    finally:
        shutil.rmtree(workdir, ignore_errors=True)

    print("CROSS-CHECK against the compiler (sizeof(PD_HTML_N) - 1)")
    bad = 0
    for i, size in enumerate(theirs):
        name, counted = mine[i] if i < len(mine) else ("<missing>", -1)
        ok = counted == size
        bad += 0 if ok else 1
        print("  %-12s checker %6d   cl %6d   %s"
              % (name, counted, size, "ok" if ok else "*** MISMATCH ***"))
    extra = [n for n, _ in mine[len(theirs):]]
    if extra:
        print("  (not in CGA_INDEX_HTML_PARTS, so not cross-checked: %s)"
              % ", ".join(extra))
    print("  %s" % ("all parts agree" if not bad
                    else "%d PART(S) DISAGREE -- the checker is wrong" % bad))
    return 1 if bad else 0


def main():
    cl = shutil.which("cl")
    if not cl:
        print("cl.exe is not on PATH. Run this from a Developer Command "
              "Prompt, or call vcvars64.bat first.", file=sys.stderr)
        return 2

    ver = subprocess.run([cl], capture_output=True, text=True)
    banner = (ver.stderr or ver.stdout).splitlines()
    print(banner[0].strip() if banner else "cl (version unknown)")
    print()

    workdir = tempfile.mkdtemp(prefix="pd_literal_cap_")
    width = max(len(n) for n, _, _ in PROBES)
    try:
        for name, src, meaning in PROBES:
            path = os.path.join(workdir, name + ".cpp")
            with open(path, "w", encoding="utf-8", newline="\n") as f:
                f.write(src)
            r = subprocess.run([cl, "/nologo", "/std:c++17", "/EHsc", "/c", path],
                               cwd=workdir, capture_output=True, text=True)
            out = (r.stdout or "") + (r.stderr or "")
            verdict = "OK   " if r.returncode == 0 else "C2026" if "C2026" in out \
                else "exit %d" % r.returncode
            print("  %-*s  %s   (pass would mean: %s)" % (width, name, verdict, meaning))
    finally:
        shutil.rmtree(workdir, ignore_errors=True)

    print()
    rc = crosscheck(cl)
    print()
    print("Update RAW_CAP / ORDINARY_CAP / RUN_CAP in "
          "tools/check_string_literal_caps.py only from a run of this script,")
    print("and record the compiler version alongside them.")
    return rc


if __name__ == "__main__":
    sys.exit(main())
