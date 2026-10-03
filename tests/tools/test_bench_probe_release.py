"""#384 (H1): the bench probe image costs a release build nothing.

POCKETDIAL_ANCHOR_BENCH_PROBE (docs/BENCH_PROBE.md) is a bench-only image. Two
layers keep it out of a release:

  * tools/ci/check_no_bench_probe.py scans a BUILT tree (the app image, the
    CMake cache, the chosen stamp). CI runs it after every ESP build; its
    scanner is pinned here with synthetic input.
  * This file reads the SOURCE: every probe line in src/ and main/ sits under
    `#if defined(POCKETDIAL_ANCHOR_BENCH_PROBE)`, the CMake option refuses the
    builds it must never reach, and no workflow turns it on. A host-only run
    cannot build an image, so this is the check that runs everywhere.

Run: python3 -m unittest discover -s tests/tools -p "test_*.py"
"""
import os
import re
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "tools", "ci"))
import check_no_bench_probe as gate  # noqa: E402

OPTION = "POCKETDIAL_ANCHOR_BENCH_PROBE"
# The guard every probe block uses (the RESET_INTERRUPT_PROBE precedent's form).
GUARD = re.compile(r"^\s*#\s*if\s+defined\s*\(\s*" + OPTION + r"\s*\)\s*&&\s*defined\s*\(\s*ESP_PLATFORM\s*\)\s*$")
DIRECTIVE = re.compile(r"^\s*#\s*(if|ifdef|ifndef|elif|else|endif)\b")
# Text that only probe code may contain.
TOKENS = ("BENCHFAULT", "/api/bench/", "BenchProbe.hpp", "BenchProbeLogic.hpp",
          "benchprobe::", "sendApiBenchFault", OPTION)
PURE = os.path.join("src", "SIP", "BenchProbeLogic.hpp")
GLUE = (os.path.join("src", "SIP", "BenchProbe.hpp"), os.path.join("src", "SIP", "BenchProbe.cpp"))


def read(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8", errors="replace") as f:
        return f.read()


def probe_lines(text):
    """[(lineno, line, guarded)] for every line; guarded = inside an active probe-on branch."""
    stack = []   # one bool per open conditional: is its current branch the probe-on one?
    out = []
    for n, line in enumerate(text.splitlines(), 1):
        m = DIRECTIVE.match(line)
        if m:
            kw = m.group(1)
            if kw in ("if", "ifdef", "ifndef"):
                stack.append(bool(GUARD.match(line)))
            elif kw == "elif" and stack:
                stack[-1] = False
            elif kw == "else" and stack:
                stack[-1] = False
            elif kw == "endif" and stack:
                stack.pop()
            out.append((n, line, None))
            continue
        out.append((n, line, any(stack)))
    return out


def sources():
    for top in ("src", "main"):
        for root, dirs, files in os.walk(os.path.join(ROOT, top)):
            dirs[:] = [d for d in dirs if not d.startswith(".")]
            for f in files:
                if f.endswith((".cpp", ".hpp", ".h", ".c")):
                    yield os.path.relpath(os.path.join(root, f), ROOT)


class Scanner(unittest.TestCase):
    def test_image_markers(self):
        self.assertEqual(gate.image_markers(b"\x00release image\x00/api/status\x00"), [])
        self.assertEqual(gate.image_markers(b"..BENCHFAULT %s fired..."), ["BENCHFAULT"])
        self.assertEqual(gate.image_markers(b"/api/bench/fault\x00BENCHFAULT"),
                         ["BENCHFAULT", "/api/bench/fault"])

    def test_cache_option(self):
        self.assertFalse(gate.cache_has_probe("SIP_TRANSPORT:UNINITIALIZED=eth\n"))
        self.assertTrue(gate.cache_has_probe(OPTION + ":UNINITIALIZED=1\n"))
        self.assertTrue(gate.cache_has_probe(OPTION + ":BOOL=ON\n"))
        self.assertFalse(gate.cache_has_probe(OPTION + ":BOOL=OFF\n"))
        self.assertFalse(gate.cache_has_probe(OPTION + ":UNINITIALIZED=0\n"))
        self.assertFalse(gate.cache_has_probe("OTHER_" + OPTION + ":BOOL=ON\n"))

    def test_stamp(self):
        self.assertFalse(gate.stamp_is_probe("v1.5.0-12-g7026dcb"))
        self.assertFalse(gate.stamp_is_probe("7026dcb-dirty"))
        self.assertTrue(gate.stamp_is_probe("v1.5.0-12-g7026dcb-probe"))
        self.assertTrue(gate.stamp_is_probe("7026dcb-probe-dirty"))

    def test_check_on_a_build_dir(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(gate.Unusable):
                gate.check(d)
            with open(os.path.join(d, "SipServer.bin"), "wb") as f:
                f.write(b"\xe9release image")
            with open(os.path.join(d, "pocketdial_fw_version.txt"), "w") as f:
                f.write("v1.5.0-12-g7026dcb\n")
            self.assertEqual(gate.check(d), [])
            self.assertEqual(gate.main(["x", d]), 0)
            with open(os.path.join(d, "SipServer.bin"), "ab") as f:
                f.write(b"BENCHFAULT %s fired")
            with open(os.path.join(d, "CMakeCache.txt"), "w") as f:
                f.write(OPTION + ":UNINITIALIZED=1\n")
            with open(os.path.join(d, "pocketdial_fw_version.txt"), "w") as f:
                f.write("v1.5.0-12-g7026dcb-probe\n")
            self.assertEqual(len(gate.check(d)), 3)
            self.assertEqual(gate.main(["x", d]), 1)


class GuardScanner(unittest.TestCase):
    def test_the_scanner_itself(self):
        text = "\n".join([
            "a();",
            "#if defined(" + OPTION + ") && defined(ESP_PLATFORM)",
            "b();",
            "#if X",
            "c();",
            "#endif",
            "#else",
            "d();",
            "#endif",
            "#ifdef " + OPTION,
            "e();",
            "#endif",
        ])
        got = {line: g for _, line, g in probe_lines(text) if g is not None}
        self.assertEqual(got, {"a();": False, "b();": True, "c();": True, "d();": False, "e();": False})


class SourceGuards(unittest.TestCase):
    def test_every_probe_line_is_under_the_macro(self):
        stray = []
        for rel in sources():
            if rel == PURE:
                continue
            for n, line, guarded in probe_lines(read(rel)):
                if guarded is None or guarded:
                    continue
                if any(t in line for t in TOKENS):
                    stray.append(f"{rel}:{n}: {line.strip()}")
        self.assertEqual(stray, [], "probe code outside #if defined(" + OPTION + ") && defined(ESP_PLATFORM)")

    def test_the_glue_files_are_entirely_guarded(self):
        for rel in GLUE:
            with self.subTest(rel=rel):
                text = read(rel)
                self.assertTrue(any(GUARD.match(l) for l in text.splitlines()), "no probe guard")
                loose = []
                for n, line, guarded in probe_lines(text):
                    s = line.strip()
                    if guarded is None or guarded or not s or s.startswith("//"):
                        continue
                    if re.match(r"#\s*define\s+\w+_HPP$", s):
                        continue   # the include guard
                    loose.append(f"{n}: {s}")
                self.assertEqual(loose, [], "code outside the probe guard compiles into release images")

    def test_the_pure_header_is_only_included_by_the_glue(self):
        users = [rel for rel in sources() if "BenchProbeLogic.hpp" in read(rel) and rel != PURE]
        self.assertEqual(users, [GLUE[0]])

    def test_the_route_exists_only_in_the_probe(self):
        hs = read(os.path.join("src", "Helpers", "HttpServer.cpp"))
        lines = [(n, g) for n, line, g in probe_lines(hs) if "/api/bench/fault" in line]
        self.assertTrue(lines, "the route is missing")
        self.assertTrue(all(g for _, g in lines), lines)


class CmakeRefusals(unittest.TestCase):
    def block(self, text, start):
        i = text.index(start)
        depth, j = 0, i
        for m in re.finditer(r"\b(if|endif)\(", text[i:]):
            depth += 1 if m.group(1) == "if" else -1
            if depth == 0:
                j = i + m.end()
                break
        return text[i:j]

    def test_the_option_refuses_every_build_but_eth_unconstrained(self):
        cm = read(os.path.join("main", "CMakeLists.txt"))
        blk = self.block(cm, "if(" + OPTION + ")")
        self.assertRegex(blk, r'if\(NOT SIP_TRANSPORT STREQUAL "eth" OR SIP_CONSTRAINED\)\s+message\(FATAL_ERROR')
        self.assertRegex(blk, r"target_compile_definitions\(\$\{COMPONENT_LIB\} PRIVATE " + OPTION + r"=1\)")
        self.assertIn("message(WARNING", blk)
        self.assertEqual(cm.count(OPTION + "=1"), 1, "the define is set in exactly one place")

    def test_the_probe_stamp_carries_its_suffix(self):
        top = read("CMakeLists.txt")
        blk = self.block(top, "if(" + OPTION + ")")
        self.assertIn('pocketdial_firmware_version(POCKETDIAL_RESOLVED_FW_VERSION "-probe")', blk)
        self.assertEqual(top.count('"-probe"'), 1)

    def test_no_workflow_builds_the_probe_and_ci_checks_for_it(self):
        wf = os.path.join(ROOT, ".github", "workflows")
        for f in sorted(os.listdir(wf)):
            with self.subTest(workflow=f):
                with open(os.path.join(wf, f), encoding="utf-8") as fh:
                    text = fh.read()
                self.assertNotRegex(text, r"-D\s*" + OPTION)
        for f in ("ci.yml", "release.yml"):
            with self.subTest(checked_in=f):
                self.assertIn("python3 tools/ci/check_no_bench_probe.py build",
                              read(os.path.join(".github", "workflows", f)))


if __name__ == "__main__":
    unittest.main()
