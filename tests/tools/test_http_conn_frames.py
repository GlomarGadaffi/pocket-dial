"""Source pins for the http_conn frame rule (#1044).

The config export and import handlers run on an http_conn thread whose stack is
kHttpConnStackBytes. Their frames were 1392 B and 1040 B because they held
std::ostringstream objects (each several hundred bytes) next to one another.
These pins read the two function bodies and fail if a local that large comes
back; the real frame size is measured by tools/ci/task_stack_gate.py.
"""
import os
import re
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
CPP = os.environ.get("PD_HTTP_CPP") or os.path.join(ROOT, "src", "Helpers", "HttpServer.cpp")
HPP = os.path.join(ROOT, "src", "Helpers", "HttpServer.hpp")

LIMIT = 256

# Library objects known to exceed the limit (libstdc++ on the target).
LARGE_TYPES = ("ostringstream", "stringstream", "istringstream", "ostream", "ofstream", "ifstream")


def _strip(src):
    """Blank comments and string/char literals, keeping length and newlines."""
    out = []
    i, n = 0, len(src)
    while i < n:
        c = src[i]
        nxt = src[i + 1] if i + 1 < n else ""
        if c == "/" and nxt == "/":
            while i < n and src[i] != "\n":
                out.append(" ")
                i += 1
        elif c == "/" and nxt == "*":
            while i < n and not (src[i] == "*" and i + 1 < n and src[i + 1] == "/"):
                out.append("\n" if src[i] == "\n" else " ")
                i += 1
            out.append("  ")
            i += 2
        elif c in "\"'":
            q = c
            out.append(q)
            i += 1
            while i < n and src[i] != q:
                if src[i] == "\\":
                    out.append(" ")
                    i += 1
                out.append(" ")
                i += 1
            out.append(q)
            i += 1
        else:
            out.append(c)
            i += 1
    return "".join(out)


def _body(name):
    with open(CPP, encoding="utf-8") as f:
        src = _strip(f.read())
    m = re.search(r"\bvoid\s+HttpServer::" + name + r"\s*\(", src)
    assert m, name + " not found"
    start = src.index("{", m.end())
    depth = 0
    for i in range(start, len(src)):
        if src[i] == "{":
            depth += 1
        elif src[i] == "}":
            depth -= 1
            if depth == 0:
                return src[start:i + 1]
    raise AssertionError("unbalanced braces in " + name)


def _static_body(name):
    """Body of a file-scope `static void name(...)` helper, comments and literals blanked."""
    with open(CPP, encoding="utf-8") as f:
        src = _strip(f.read())
    m = re.search(r"static\s+void\s+" + name + r"\s*\(", src)
    assert m, name + " not found"
    start = src.index("{", m.end())
    depth = 0
    for i in range(start, len(src)):
        if src[i] == "{":
            depth += 1
        elif src[i] == "}":
            depth -= 1
            if depth == 0:
                return src[start:i + 1]
    raise AssertionError("unbalanced braces in " + name)


SECTION_HELPER = re.compile(r"^static\s+void\s+(export(?:Section\w+|Gated(?!Json\s*\()[A-Z]\w*))\s*\(", re.M)


def _section_helpers():
    """Names and bodies of the per-section export helpers, comments and literals blanked."""
    with open(CPP, encoding="utf-8") as f:
        raw = f.read()
    src = _strip(raw)
    out = []
    for m in SECTION_HELPER.finditer(src):
        start = src.index("{", m.end())
        depth = 0
        for i in range(start, len(src)):
            if src[i] == "{":
                depth += 1
            elif src[i] == "}":
                depth -= 1
                if depth == 0:
                    out.append((m.group(1), src[start:i + 1], raw[:m.start()].rstrip().splitlines()[-1].strip()))
                    break
    return out


def _large_locals(body):
    found = []
    for t in LARGE_TYPES:
        for m in re.finditer(r"\b(?:std::)?" + t + r"\s+\w+", body):
            found.append(m.group(0))
    for m in re.finditer(r"\b\w+\s+(\w+)\s*\[\s*(\d+)\s*\]", body):
        if int(m.group(2)) > LIMIT:
            found.append(m.group(0))
    return found


class HttpConnFrames(unittest.TestCase):
    def test_export_frame_holds_no_large_local(self):
        self.assertEqual(_large_locals(_body("sendApiConfigExport")), [])

    def test_import_frame_holds_no_large_local(self):
        self.assertEqual(_large_locals(_body("sendApiConfigImport")), [])

    def test_bodies_are_found_not_vacuous(self):
        exp = _body("sendApiConfigExport")
        imp = _body("sendApiConfigImport")
        self.assertIn("exportPlaintextJson(", exp)
        self.assertIn("exportGatedJson(", exp)
        self.assertIn("sendResponse(", exp)
        self.assertIn("importResultJson(", imp)
        self.assertIn("sendResponse(", imp)
        self.assertGreater(len(exp), 800)
        self.assertGreater(len(imp), 3000)

    def test_detector_flags_a_stream_and_a_big_array(self):
        self.assertTrue(_large_locals("{ std::ostringstream s; }"))
        self.assertTrue(_large_locals("{ char buf[512]; }"))
        self.assertEqual(_large_locals("{ char buf[16]; }"), [])

    def test_helpers_stay_noinline(self):
        with open(CPP, encoding="utf-8") as f:
            src = f.read()
        for name in ("exportPlaintextJson", "exportGatedJson", "importResultJson"):
            m = re.search(r"__attribute__\(\(noinline\)\)\s*#endif\s*static\s+[\w:<>& ,]+?"
                          + name + r"\s*\(", src)
            self.assertTrue(m, name + " must stay noinline")

    def test_export_path_builds_no_stream(self):
        # #1044: std::ostringstream formatting is the deepest thing the export calls.
        bodies = {
            "exportPlaintextJson": _static_body("exportPlaintextJson"),
            "exportGatedJson": _static_body("exportGatedJson"),
            "sendApiConfigExport": _body("sendApiConfigExport"),
        }
        for n, b, _ in _section_helpers():
            bodies[n] = b
        for name, body in bodies.items():
            self.assertNotRegex(body, r"stringstream|ostream|<<", name + " must not use a stream")

    def test_export_helper_bodies_are_found_not_vacuous(self):
        helpers = dict((n, b) for n, b, _ in _section_helpers())
        pt = "".join(b for n, b in helpers.items() if n.startswith("exportSection"))
        gated = "".join(b for n, b in helpers.items() if n.startswith("exportGated"))
        self.assertIn("jsonEscape", pt)
        self.assertGreater(len(pt), 2000)
        self.assertIn("getHa1", gated)
        self.assertGreater(len(gated), 800)
        send = _body("sendApiConfigExport")
        self.assertIn("exportPlaintextJson", send)
        self.assertIn("aesGcmSeal", send)
        self.assertGreater(len(send), 600)

    def test_append_integer_checks_the_conversion(self):
        # #1044: a to_chars that failed must not be written as a gap.
        body = _static_body("appendInteger")
        self.assertIn("to_chars", body)
        self.assertRegex(body, r"\.ec\s*==\s*std::errc\(\)")
        self.assertRegex(body, r"char\s+buf\[24\]")

    def test_leaf_helpers_and_sections_are_noinline(self):
        # #1044: a leaf helper inlined into a caller copies its buffer into that frame, and a
        # section helper inlined into exportPlaintextJson puts every getter's result back in
        # one frame (1072 B against the 1024 B ceiling).
        with open(CPP, encoding="utf-8") as f:
            src = f.read()
        self.assertRegex(src, r"#define\s+PD_EXPORT_NOINLINE\s+__attribute__\(\(noinline\)\)")
        self.assertRegex(src, r"#define\s+PD_EXPORT_NOINLINE\s+__declspec\(noinline\)")
        for pat in (r"PD_EXPORT_NOINLINE\s+static\s+void\s+jsonEscapeAppend\s*\(",
                    r"template\s*<typename T>\s+PD_EXPORT_NOINLINE\s+static\s+void\s+appendInteger\s*\("):
            self.assertRegex(src, pat)
        helpers = _section_helpers()
        # Positive control: the split exists. 14 plaintext sections and 5 gated ones.
        self.assertGreaterEqual(len(helpers), 19)
        for name, body, prev in helpers:
            self.assertEqual(prev, "PD_EXPORT_NOINLINE", name + " must be noinline")
            self.assertEqual(_large_locals(body), [], name)

    def test_top_level_export_is_a_short_sequence(self):
        body = _static_body("exportPlaintextJson")
        self.assertNotIn("for (", body)
        self.assertNotIn("jsonEscapeAppend", body)
        self.assertLess(len(body), 4000)

    def test_stack_constant_unchanged(self):
        with open(HPP, encoding="utf-8") as f:
            hpp = f.read()
        m = re.search(r"kHttpConnStackBytes\s*=\s*(\d+)\s*;", hpp)
        self.assertTrue(m)
        self.assertEqual(int(m.group(1)), 4096)


    def test_json_escape_hooks_share_the_declaration_guard(self):
        # #1044: the hooks are declared only on the host; a definition outside the same
        # guard fails every device build ("no declaration matches").
        guard = "#if !defined(ESP_PLATFORM) && !defined(ESP32) && !defined(ARDUINO)"
        found = 0
        for path, marker in ((HPP, "static std::string jsonEscapeForTest"),
                             (CPP, "std::string HttpServer::jsonEscapeForTest")):
            with open(path, encoding="utf-8") as f:
                lines = f.read().splitlines()
            idx = [i for i, l in enumerate(lines) if marker in l]
            self.assertEqual(len(idx), 1, marker)
            guards = []
            for l in lines[:idx[0]]:
                st = l.strip()
                if st.startswith("#if"):
                    guards.append(st)
                elif st.startswith("#endif") and guards:
                    guards.pop()
                elif st.startswith("#else") or st.startswith("#elif"):
                    if guards:
                        guards[-1] = st
            self.assertTrue(guards, path)
            self.assertEqual(guards[-1], guard, path)
            sib = [i for i, l in enumerate(lines) if "jsonEscapeAppendForTest" in l]
            self.assertTrue(sib)
            between = lines[min(idx[0], sib[0]):max(idx[0], sib[-1])]
            self.assertFalse([l for l in between if l.strip().startswith("#")], path)
            found += 1
        self.assertEqual(found, 2)


if __name__ == "__main__":
    unittest.main()
