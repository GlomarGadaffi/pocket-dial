#!/usr/bin/env python3
"""Self-test for tools/gen_index_html.py (the web/ -> src/Helpers/index_html.h generator).

Runs in CI:

    python3 -m unittest discover -s tests/tools -p 'test_gen_index_html.py'

Every fixture is a throwaway directory under tempfile; the real header is only READ (to prove the two
preserved regions survive byte for byte), never written, and the real web/ is not needed.
"""
import contextlib
import io
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.normpath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, os.path.join(REPO, "tools"))
import gen_index_html as gen  # noqa: E402

REAL_HEADER = os.path.join(REPO, "src", "Helpers", "index_html.h")
MARKER = b"__PD_CSRF__"
CAP = 16384                                   # MSVC raw-literal cap, measured

STANDALONE = (
    b"// Issue #159 (SMTP client): the standalone /setup/email admin page.\n"
    b"static const char PD_HTML_8[] =\n"
    b'R"html8(<!DOCTYPE html>\n<html><body>email \xc3\xa9 __PD_CSRF__</body></html>\n)html8";\n'
    b"// Issue #164 (ITSP SIP trunk): the standalone /setup/trunk admin page.\n"
    b"static const char PD_HTML_9[] =\n"
    b'R"html9(<!DOCTYPE html>\n<html><body>trunk __PD_CSRF__</body></html>\n)html9";\n'
)
HEAD = (
    b"#ifndef INDEX_HTML_H\n#define INDEX_HTML_H\n\n#include <cstddef>\n\n"
    b"// top comment, kept byte for byte\n"
    b"struct HtmlPart { const char* data; size_t size; };\n"
)
OLD_HEADER = (
    HEAD + b"\nstatic const char PD_HTML_0[] =\nR\"html0(old spa\n)html0\";\n\n"
    + STANDALONE + b"\n\nstatic const HtmlPart CGA_INDEX_HTML_PARTS[] = {\n\t{ PD_HTML_0, sizeof(PD_HTML_0) - 1 },\n};\n"
    b"static constexpr size_t CGA_INDEX_HTML_PART_COUNT = 1;\n\n#endif // INDEX_HTML_H\n"
)

SHELL = (
    b'<!DOCTYPE html>\n<html lang="en">\n<head>\n<meta charset="UTF-8">\n<title>t</title>\n'
    b'<link rel="stylesheet" href="app.css">\n</head>\n<body>\n<main>\n'
    b'<section id="sec-overview" hidden></section>\n'
    b'<section id="sec-trunks-numbers" hidden>\n</section>\n'
    b'</main>\n'
    b'<script src="app/00-core.js"></script>\n'
    b'<script src="app/10-overview.js"></script>\n'
    b'</body>\n</html>\n'
)
MANIFEST = (
    b"# comment\nindex.html\napp.css\n\napp/00-core.js\napp/10-overview.js\n\n"
    b"sections/10-overview.html\nsections/40-trunks-numbers.html\n"
)
CORE_JS = b'var PD_CSRF="__PD_CSRF__";\nfunction $(id){\nreturn document.getElementById(id);\n}\n'


def write(root, rel, data):
    path = os.path.join(root, *rel.split("/"))
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)


def make_web(root, shell=SHELL, manifest=MANIFEST, css=b"body{margin:0}\n", core=CORE_JS,
             overview_js=b"function a(){\n}\n", frag1=b'<h2>Overview \xc3\xa9</h2>\n', frag2=b"<p>trunks</p>\n"):
    write(root, "index.html", shell)
    write(root, "manifest.txt", manifest)
    write(root, "app.css", css)
    write(root, "app/00-core.js", core)
    write(root, "app/10-overview.js", overview_js)
    write(root, "sections/10-overview.html", frag1)
    write(root, "sections/40-trunks-numbers.html", frag2)


def spa_parts(out):
    """{id: content bytes} of the SPA parts (everything but 8 and 9) in a generated header."""
    found = {}
    for m in re.finditer(rb'static const char PD_HTML_(\d+)\[\] =\nR"html(\d+)\((.*?)\)html\2";\n', out, re.S):
        assert m.group(1) == m.group(2), "name/delimiter mismatch"
        found[int(m.group(1))] = m.group(3)
    return {k: v for k, v in found.items() if k not in (8, 9)}


def array_ids(out):
    body = re.search(rb"CGA_INDEX_HTML_PARTS\[\] = \{(.*?)\};", out, re.S).group(1)
    return [int(x) for x in re.findall(rb"\{ PD_HTML_(\d+), sizeof\(PD_HTML_\1\) - 1 \}", body)]


class Fixture(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.web = os.path.join(self._tmp.name, "web")
        os.makedirs(self.web)
        self.out = os.path.join(self._tmp.name, "index_html.h")
        with open(self.out, "wb") as f:
            f.write(OLD_HEADER)

    def gen(self, old=OLD_HEADER):
        return gen.generate(self.web, old)

    def big(self, n_lines, line=b".k" + b"x" * 88 + b"{margin:0}\n"):
        """A CSS file of about n_lines*len(line) bytes (rules, not comments: the minifier drops those)."""
        return b"body{margin:0}\n" + line * n_lines


class RoundTripTest(Fixture):
    def test_inlined_page_is_exactly_the_concatenated_parts(self):
        make_web(self.web)
        out = self.gen()
        parts = spa_parts(out)
        spa = b"".join(parts[k] for k in sorted(parts))
        self.assertTrue(spa.startswith(b"<!DOCTYPE html>"))
        self.assertIn(b"<style>\nbody{margin:0}\n</style>", spa)
        self.assertIn(b'<section id="sec-overview" hidden>\n<h2>Overview \xc3\xa9</h2>\n</section>', spa)
        self.assertIn(b'<section id="sec-trunks-numbers" hidden>\n<p>trunks</p>\n</section>', spa)
        self.assertIn(b"<script>\n" + CORE_JS + b"function a(){\n}\n</script>\n", spa)
        self.assertNotIn(b"<script src", spa)
        self.assertEqual(spa.count(b"<script>"), 1)
        self.assertEqual(spa.count(MARKER), 1)

    def test_split_pieces_rejoin_byte_for_byte(self):
        make_web(self.web, css=self.big(600))                      # ~57 KB -> several parts
        spa = gen.assemble_spa(self.web)
        out = self.gen()
        parts = spa_parts(out)
        self.assertGreater(len(parts), 3)
        self.assertEqual(b"".join(parts[k] for k in sorted(parts)), spa)

    def test_generation_is_idempotent(self):
        make_web(self.web, css=self.big(400))
        once = self.gen()
        self.assertEqual(self.gen(once), once)

    def test_crlf_sources_give_the_same_bytes_as_lf_sources(self):
        make_web(self.web)
        lf = self.gen()
        make_web(self.web, shell=SHELL.replace(b"\n", b"\r\n"), manifest=MANIFEST.replace(b"\n", b"\r\n"),
                 css=b"body{margin:0}\r\n", core=CORE_JS.replace(b"\n", b"\r\n"),
                 overview_js=b"function a(){\r\n}\r\n", frag1=b'<h2>Overview \xc3\xa9</h2>\r\n',
                 frag2=b"<p>trunks</p>\r\n")
        self.assertEqual(self.gen(OLD_HEADER.replace(b"\n", b"\r\n")), lf)
        self.assertNotIn(b"\r", lf)

    def test_bare_cr_is_an_error(self):
        make_web(self.web, frag1=b"<p>a\rb</p>\n")
        with self.assertRaisesRegex(gen.GenError, "bare CR"):
            self.gen()


class CapTest(Fixture):
    def test_every_part_is_at_most_16000_and_under_the_msvc_cap(self):
        make_web(self.web, css=self.big(1500))                      # ~140 KB
        parts = spa_parts(self.gen())
        self.assertGreater(len(parts), 8)
        for k, body in parts.items():
            self.assertLessEqual(len(body), gen.PART_CAP, "PD_HTML_%d" % k)
            self.assertLessEqual(len(body), CAP - 384, "PD_HTML_%d" % k)

    def test_parts_split_at_a_newline_when_there_is_one(self):
        make_web(self.web, css=self.big(400))
        parts = spa_parts(self.gen())
        ordered = [parts[k] for k in sorted(parts)]
        for body in ordered[:-1]:
            self.assertTrue(body.endswith(b"\n"))

    def test_a_single_line_longer_than_the_cap_still_splits_inside_utf8_boundaries(self):
        long_line = (b"\xc3\xa9" * 20000) + b"\n"                    # 40 KB, no newline until the end
        make_web(self.web, frag1=long_line)
        spa = gen.assemble_spa(self.web)
        out = self.gen()
        parts = spa_parts(out)
        self.assertGreater(len(parts), 2)
        for body in parts.values():
            body.decode("utf-8")                                    # each part is valid UTF-8 on its own
            self.assertLessEqual(len(body), gen.PART_CAP)
        self.assertEqual(b"".join(parts[k] for k in sorted(parts)), spa)

    def test_split_parts_respects_a_custom_cap(self):
        spa = b"aaaa\nbbbb\ncccc\n"
        self.assertEqual(gen.split_parts(spa, cap=10), [b"aaaa\nbbbb\n", b"cccc\n"])


class MarkerTest(Fixture):
    def test_marker_not_straddled_when_it_sits_on_the_cap_boundary(self):
        # No newline anywhere near the cut, so the split falls back to a byte offset; put the marker
        # across every offset around the boundary and prove it never lands in two parts.
        for off in range(gen.PART_CAP - len(MARKER) - 2, gen.PART_CAP + 2):
            with self.subTest(offset=off):
                filler = b"y" * off
                core = b'var s="' + filler + MARKER + b"z" * 30 + b'";\n'
                make_web(self.web, core=core)
                parts = spa_parts(self.gen())
                holders = [k for k, b in parts.items() if MARKER in b]
                self.assertEqual(len(holders), 1)
                self.assertEqual(parts[holders[0]].count(MARKER), 1)
                joined = b"".join(parts[k] for k in sorted(parts))
                self.assertEqual(joined.count(MARKER), 1)
                for k, body in parts.items():
                    self.assertFalse(body.endswith(MARKER[:-1]) and not MARKER in body)
                    self.assertLessEqual(len(body), gen.PART_CAP)

    def test_split_parts_moves_the_cut_in_front_of_the_marker(self):
        spa = b"A" * 6 + MARKER + b"B" * 30                       # a cap of 14 would cut inside the marker
        parts = gen.split_parts(spa, cap=14)
        self.assertEqual(b"".join(parts), spa)
        self.assertEqual(parts[0], b"A" * 6)
        self.assertEqual([p for p in parts if MARKER in p], [p for p in parts if p.count(MARKER) == 1])
        self.assertEqual(sum(p.count(MARKER) for p in parts), 1)

    def test_marker_must_appear_exactly_once(self):
        make_web(self.web, core=b"var PD_CSRF=\"\";\n")
        with self.assertRaisesRegex(gen.GenError, "exactly once.*found 0"):
            self.gen()
        make_web(self.web, core=CORE_JS + b'var again="__PD_CSRF__";\n')
        with self.assertRaisesRegex(gen.GenError, "exactly once.*found 2"):
            self.gen()


class DelimiterTest(Fixture):
    def test_delimiters_are_unique_and_never_collide_with_the_standalone_pages(self):
        make_web(self.web, css=self.big(1500))
        out = self.gen()
        ids = array_ids(out)
        self.assertGreater(len(ids), 8)
        self.assertEqual(len(set(ids)), len(ids))
        self.assertNotIn(8, ids)
        self.assertNotIn(9, ids)
        self.assertEqual(ids[:9], [0, 1, 2, 3, 4, 5, 6, 7, 10])
        for i in ids + [8, 9]:
            self.assertEqual(out.count(b'R"html%d(' % i), 1, "opening delimiter html%d" % i)
            self.assertEqual(out.count(b')html%d";' % i), 1, "closing delimiter html%d" % i)
            self.assertEqual(out.count(b"static const char PD_HTML_%d[] =" % i), 1)
        self.assertEqual(sorted(spa_parts(out)), sorted(ids))

    def test_array_lists_spa_parts_only_and_count_follows(self):
        make_web(self.web)
        out = self.gen()
        self.assertEqual(array_ids(out), [0])
        self.assertIn(b"CGA_INDEX_HTML_PART_COUNT =\n\tsizeof(CGA_INDEX_HTML_PARTS) / sizeof(CGA_INDEX_HTML_PARTS[0]);", out)
        self.assertTrue(out.endswith(b"\n#endif // INDEX_HTML_H\n"))

    def test_a_source_that_would_end_a_raw_literal_early_is_rejected(self):
        for bad in (b')html3"', b')html0"', b')html12"'):
            with self.subTest(bad=bad):
                make_web(self.web, frag1=b"<p>" + bad + b"</p>\n")
                with self.assertRaisesRegex(gen.GenError, r"\)html<digit>"):
                    self.gen()

    def test_close_but_harmless_text_is_accepted(self):
        make_web(self.web, frag1=b'<p>)html"</p> <p>html3"</p> <p>)htmlx"</p>\n')
        self.gen()


class PreservedRegionsTest(Fixture):
    def test_synthetic_head_and_standalone_pages_survive_byte_for_byte(self):
        make_web(self.web)
        out = self.gen()
        self.assertTrue(out.startswith(HEAD))
        self.assertIn(STANDALONE, out)
        self.assertEqual(out.count(b"Issue #159 (SMTP client)"), 1)
        # the standalone pages sit AFTER every SPA part and before the array
        self.assertLess(out.rindex(b'static const char PD_HTML_0[] ='), out.index(STANDALONE))
        self.assertLess(out.index(STANDALONE), out.index(b"CGA_INDEX_HTML_PARTS[] = {"))
        # the old SPA is gone
        self.assertNotIn(b"old spa", out)

    @unittest.skipUnless(os.path.isfile(REAL_HEADER), "real header not present")
    def test_real_header_regions_are_extracted_and_survive(self):
        with open(REAL_HEADER, "rb") as f:
            real = gen.normalize(f.read(), "real header")
        head, standalone = gen.extract_regions(real)
        self.assertTrue(real.startswith(head))
        self.assertTrue(head.startswith(b"#ifndef INDEX_HTML_H\n"))
        self.assertTrue(head.rstrip(b"\n").endswith(b"};"))
        self.assertIn(b"struct HtmlPart { const char* data; size_t size; };", head)
        self.assertNotIn(b"PD_HTML_0", head)
        self.assertTrue(standalone.startswith(b"// Issue #159 (SMTP client)"))
        self.assertTrue(standalone.endswith(b')html9";\n'))
        self.assertIn(b"static const char PD_HTML_8[] =", standalone)
        self.assertIn(b"static const char PD_HTML_9[] =", standalone)
        self.assertNotIn(b"static const char PD_HTML_7[]", standalone)
        make_web(self.web, css=self.big(300))
        out = gen.generate(self.web, real)
        self.assertTrue(out.startswith(head))
        self.assertEqual(out.count(standalone), 1)
        self.assertEqual(gen.generate(self.web, out), out)        # and a second pass changes nothing

    def test_missing_regions_fail_loudly(self):
        make_web(self.web)
        with self.assertRaisesRegex(gen.GenError, "struct HtmlPart"):
            self.gen(b"nothing here\n")
        with self.assertRaisesRegex(gen.GenError, "Issue #159"):
            self.gen(HEAD)
        with self.assertRaisesRegex(gen.GenError, "PD_HTML_9"):
            self.gen(HEAD + STANDALONE.split(b"// Issue #164")[0])


class ShellContractTest(Fixture):
    def test_script_order_in_shell_must_match_manifest(self):
        make_web(self.web, shell=SHELL.replace(b"00-core", b"XX").replace(b"10-overview", b"00-core")
                 .replace(b"XX", b"10-overview"))
        with self.assertRaisesRegex(gen.GenError, "do not match manifest"):
            self.gen()

    def test_section_without_fragment_and_fragment_without_section(self):
        make_web(self.web, shell=SHELL.replace(b"</main>", b'<section id="sec-extra" hidden></section>\n</main>'))
        with self.assertRaisesRegex(gen.GenError, "sec-extra"):
            self.gen()
        make_web(self.web, shell=SHELL.replace(b'<section id="sec-trunks-numbers" hidden>\n</section>\n', b""))
        with self.assertRaisesRegex(gen.GenError, "trunks-numbers"):
            self.gen()

    def test_shell_section_must_be_empty(self):
        make_web(self.web, shell=SHELL.replace(b'id="sec-overview" hidden>', b'id="sec-overview" hidden><p>x</p>'))
        with self.assertRaisesRegex(gen.GenError, "must be empty"):
            self.gen()

    def test_external_and_forbidden_content_is_rejected(self):
        make_web(self.web, shell=SHELL.replace(b'href="app.css"', b'href="https://cdn.example/x.css"'))
        with self.assertRaisesRegex(gen.GenError, "external stylesheet"):
            self.gen()
        make_web(self.web, css=b"@import url(x.css);\n")
        with self.assertRaisesRegex(gen.GenError, "@import"):
            self.gen()
        make_web(self.web, css=b"a{background:url(https://x/y.png)}\n")
        with self.assertRaisesRegex(gen.GenError, "external url"):
            self.gen()
        make_web(self.web, overview_js=b'var s="</script>";\n')
        with self.assertRaisesRegex(gen.GenError, "</script"):
            self.gen()

    def test_manifest_problems(self):
        make_web(self.web, manifest=MANIFEST + b"app/00-core.js\n")
        with self.assertRaisesRegex(gen.GenError, "duplicate"):
            self.gen()
        make_web(self.web, manifest=MANIFEST + b"app/99-missing.js\n")
        with self.assertRaisesRegex(gen.GenError, "does not exist"):
            self.gen()
        make_web(self.web, manifest=MANIFEST + b"../evil.js\n")
        with self.assertRaisesRegex(gen.GenError, "relative"):
            self.gen()

    def test_inlined_text_is_not_rescanned_for_tags(self):
        # A JS string that looks like a section or a stylesheet link must pass through untouched.
        js = b'var t=\'<section id="sec-overview"></section><link rel="stylesheet" href="nope.css">\';\n'
        make_web(self.web, overview_js=js)
        spa = b"".join(v for _, v in sorted(spa_parts(self.gen()).items()))
        self.assertIn(js, spa)


class CliTest(Fixture):
    def run_cli(self, *extra):
        buf_out, buf_err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(buf_out), contextlib.redirect_stderr(buf_err):
            rc = gen.main(["--web", self.web, "--out", self.out] + list(extra))
        return rc, buf_out.getvalue(), buf_err.getvalue()

    def test_check_flags_a_stale_file_then_write_fixes_it(self):
        make_web(self.web)
        rc, _, err = self.run_cli("--check")
        self.assertEqual(rc, 1)
        self.assertIn("stale", err)
        with open(self.out, "rb") as f:
            self.assertEqual(f.read(), OLD_HEADER)                   # --check never writes
        rc, _, _ = self.run_cli()
        self.assertEqual(rc, 0)
        rc, _, _ = self.run_cli("--check")
        self.assertEqual(rc, 0)
        with open(self.out, "rb") as f:
            written = f.read()
        self.assertNotIn(b"\r", written)
        self.assertTrue(written.startswith(HEAD))

    def test_check_treats_a_crlf_checkout_of_identical_content_as_up_to_date(self):
        make_web(self.web)
        self.run_cli()
        with open(self.out, "rb") as f:
            lf = f.read()
        with open(self.out, "wb") as f:
            f.write(lf.replace(b"\n", b"\r\n"))
        rc, _, _ = self.run_cli("--check")
        self.assertEqual(rc, 0)

    def test_check_flags_a_hand_edit(self):
        make_web(self.web)
        self.run_cli()
        with open(self.out, "ab") as f:
            f.write(b"// hand edit\n")
        rc, _, _ = self.run_cli("--check")
        self.assertEqual(rc, 1)

    def test_generator_errors_exit_2_and_leave_the_header_alone(self):
        make_web(self.web, core=b"no marker\n")
        rc, _, err = self.run_cli()
        self.assertEqual(rc, 2)
        self.assertIn("gen_index_html:", err)
        with open(self.out, "rb") as f:
            self.assertEqual(f.read(), OLD_HEADER)


class MinifyTest(unittest.TestCase):
    """The size squeeze. It must never change what the page does or what the C++ tests slice."""

    def test_js_drops_whole_line_comments_blank_lines_and_indentation(self):
        src = (b"/* header\n   spans lines */\nvar a=1;\n\n  // gone\n  function f(){\n    var s=\"// not a comment\";\n"
               b"    /* one line */\n    return s;\n  }\n")
        out = gen.min_js(src, "t.js")
        self.assertEqual(out, b'var a=1;\nfunction f(){\nvar s="// not a comment";\nreturn s;\n }\n')

    def test_js_nested_closer_is_never_a_bare_brace_line(self):
        # tests slice a page function from `function name(...){` to the next "\n}\n"
        src = b"function f(x){\n  if(x){\n    g();\n  }\n}\nfunction h(){\n}\n"
        out = gen.min_js(src, "t.js")
        self.assertEqual(out, b"function f(x){\nif(x){\ng();\n }\n}\nfunction h(){\n}\n")
        self.assertEqual(out.count(b"\n}\n"), 2)                      # one per top-level function

    def test_js_keeps_the_pinned_issue_167_comment_and_code_after_a_block_closer(self):
        out = gen.min_js(b"/* #167: radio */\n/* gone */ var x=1;\n", "t.js")
        self.assertEqual(out, b"/* #167: radio */\nvar x=1;\n")

    def test_js_refuses_what_line_squeezing_cannot_keep_intact(self):
        with self.assertRaisesRegex(gen.GenError, "backtick"):
            gen.min_js(b"var a=`x\n   y`;\n", "t.js")
        with self.assertRaisesRegex(gen.GenError, "backtick"):
            gen.min_js(b'var a="x\\\n   y";\n', "t.js")

    def test_css_squeezes_but_leaves_strings_and_calc_spaces_alone(self):
        src = (b"/* it's a comment */\n.a > .b ,\n.c {\n  margin: 0;\n  width: calc(100% - 4px);\n}\n"
               b".d::before{ content:\"\\25CF  \"; color:red; }\n")
        out = gen.min_css(src, "t.css")
        self.assertEqual(out, b'.a>.b,.c{margin:0;width:calc(100% - 4px)}\n.d::before{content:"\\25CF  ";color:red}\n')

    def test_css_keeps_the_descendant_combinator_before_a_pseudo_class(self):
        self.assertEqual(gen.min_css(b"#main :is(.a){x:1}\n", "t.css"), b"#main :is(.a){x:1}\n")

    def test_html_drops_comments_indentation_and_blank_lines(self):
        out = gen.min_html(b"<div>\n  <!-- gone -->\n\n  <p>a  b</p>\n</div>\n", "t.html")
        self.assertEqual(out, b"<div>\n<p>a  b</p>\n</div>\n")

    def test_html_refuses_a_textarea_with_content_but_allows_an_empty_one(self):
        gen.min_html(b'<textarea id="x" rows="3"></textarea>\n', "t.html")
        with self.assertRaisesRegex(gen.GenError, "textarea"):
            gen.min_html(b"<textarea>\n  keep\n</textarea>\n", "t.html")

    def test_the_real_sources_survive_the_squeeze(self):
        web = os.path.join(REPO, "web")
        if not os.path.isdir(os.path.join(web, "app")):
            self.skipTest("web/ not present")
        spa = gen.assemble_spa(web)
        pinned = (b"fetchStatus fetchAdminStatus fetchCdr fetchE911 applyE911 applyEmergencyRoute renderBoard "
                  b"updateRail renderRegistrar renderWifi setMsg factoryReset startApMode holdConfigMode otaReboot")
        for name in pinned.split():                  # the page functions the C++ tests slice by name
            m = re.search(rb"^function " + name + rb"\([^)]*\)\{", spa, re.M)
            self.assertIsNotNone(m, name.decode())
            end = spa.index(b"\n}\n", m.start())
            body = spa[m.end():end]
            self.assertNotIn(b"\nfunction ", body, name.decode())              # a body never swallows the next function
            self.assertGreater(len(body), 20, name.decode())
        self.assertEqual(spa.count(MARKER), 1)


class RealManifestTest(unittest.TestCase):
    def test_manifest_lists_the_brief_layout_in_order(self):
        path = os.path.join(REPO, "web", "manifest.txt")
        if not os.path.isfile(path):
            self.skipTest("web/manifest.txt not present")
        entries = gen.read_manifest(os.path.join(REPO, "web"))
        names = ["overview", "extensions", "devices", "trunks-numbers", "routing", "call-handling",
                 "audio", "security", "maintenance", "console"]
        nums = ["10", "20", "30", "40", "50", "60", "70", "80", "85", "90"]
        expect = (["index.html", "app.css", "app/00-core.js"]
                  + ["app/%s-%s.js" % (n, s) for n, s in zip(nums, names)]
                  + ["sections/%s-%s.html" % (n, s) for n, s in zip(nums, names)])
        # the feature files split out of 40-trunks-numbers, 60-call-handling and 85-maintenance, spliced in
        # right after them; the SBC profile copy (05-sbc) sits right after core / first among the fragments
        for kind, ext in (("app", "js"), ("sections", "html")):
            expect.insert(expect.index("%s/10-overview.%s" % (kind, ext)), "%s/05-sbc.%s" % (kind, ext))
            expect.insert(expect.index("%s/40-trunks-numbers.%s" % (kind, ext)) + 1, "%s/41-did.%s" % (kind, ext))
            expect.insert(expect.index("%s/60-call-handling.%s" % (kind, ext)) + 1, "%s/61-paging.%s" % (kind, ext))
            expect.insert(expect.index("%s/85-maintenance.%s" % (kind, ext)) + 1, "%s/86-wifi.%s" % (kind, ext))
        self.assertEqual(entries, expect)

    def test_the_guards_are_the_wifi_paging_and_sbc_profile_files_and_nothing_else(self):
        path = os.path.join(REPO, "web", "manifest.txt")
        if not os.path.isfile(path):
            self.skipTest("web/manifest.txt not present")
        guards = {e: g for e, g in gen.read_manifest_guards(os.path.join(REPO, "web")) if g}
        paging = ("POCKETDIAL_MULTICAST_PAGING", True, False)
        wifi = ("POCKETDIAL_HAS_WIFI", False, False)
        sbc = ("POCKETDIAL_PROFILE_SBC", False, gen.ONLY)                   # strict: no host fallback
        not_sbc = ("POCKETDIAL_PROFILE_SBC", False, True)
        expect = {"app/05-sbc.js": (sbc,), "sections/05-sbc.html": (sbc,),
                  "app/61-paging.js": (paging, not_sbc), "sections/61-paging.html": (paging, not_sbc),
                  "app/86-wifi.js": (wifi,), "sections/86-wifi.html": (wifi,)}
        for name in ("41-did", "50-routing", "60-call-handling", "70-audio"):       # 3CX owns these under SBC
            expect["app/%s.js" % name] = (not_sbc,)
            expect["sections/%s.html" % name] = (not_sbc,)
        self.assertEqual(guards, expect)


WIFI_JS = b"function wifiGo(){\nreturn 1;\n}\n"
PAGING_JS = b"function pageGo(){\nreturn 2;\n}\n"
LAST_JS = b"function last(){\nreturn 3;\n}\n"
GSHELL = SHELL.replace(b'<script src="app/10-overview.js"></script>\n',
                       b'<script src="app/10-overview.js"></script>\n<script src="app/20-last.js"></script>\n')
GMANIFEST = (
    b"index.html\napp.css\napp/00-core.js\napp/10-overview.js\n"
    b"@if HAS_WIFI\napp/15-wifi.js\n"
    b"@if PAGING!=0\napp/17-paging.js\n"
    b"app/20-last.js\n"
    b"sections/10-overview.html\n"
    b"@if HAS_WIFI\nsections/15-wifi.html\n"
    b"@if PAGING!=0\nsections/17-paging.html\n"
    b"sections/40-trunks-numbers.html\n"
)
SLOTS = b'<h2>Overview</h2>\n<div id="wifi-slot"></div>\n<div id="paging-slot"></div>\n'
IF_WIFI = b"#if defined(HAS_WIFI) || !defined(ESP_PLATFORM)\n"
IF_PAGING = b"#if (defined(PAGING) && (PAGING) != 0) || !defined(ESP_PLATFORM)\n"


def make_gweb(root, shell=GSHELL, manifest=GMANIFEST, wifi_js=WIFI_JS, paging_js=PAGING_JS,
              wifi_html=b"<p>wifi ui</p>\n", paging_html=b"<p>paging ui</p>\n", frag1=SLOTS, core=CORE_JS):
    make_web(root, shell=shell, manifest=manifest, frag1=frag1, core=core)
    write(root, "app/15-wifi.js", wifi_js)
    write(root, "app/17-paging.js", paging_js)
    write(root, "app/20-last.js", LAST_JS)
    write(root, "sections/15-wifi.html", wifi_html)
    write(root, "sections/17-paging.html", paging_html)


def part_of(out, needle):
    """(id, content) of the single SPA part holding `needle`."""
    hits = [(k, v) for k, v in spa_parts(out).items() if needle in v]
    assert len(hits) == 1, (needle, [k for k, _ in hits])
    return hits[0]


class GuardedPartsTest(Fixture):
    def test_the_whole_page_still_has_every_guarded_file_in_place(self):
        make_gweb(self.web)
        spa = gen.assemble_spa(self.web)
        self.assertIn(b'<div id="wifi-slot">\n<p>wifi ui</p>\n</div>', spa)
        self.assertIn(b'<div id="paging-slot">\n<p>paging ui</p>\n</div>', spa)
        order = [spa.index(x) for x in (b"function a(){", WIFI_JS, PAGING_JS, LAST_JS)]
        self.assertEqual(order, sorted(order))                        # spliced at the manifest position
        self.assertEqual(spa.count(b"<script>"), 1)
        self.assertEqual(spa.count(b"</script>"), 1)
        self.assertEqual(b"".join(b for _, b in gen.assemble_segments(self.web)), spa)
        self.assertEqual(spa.count(MARKER), 1)

    def test_a_guarded_file_is_its_own_part_and_never_shares_a_literal(self):
        make_gweb(self.web)
        out = self.gen()
        for needle, body in ((b"wifi ui", b"<p>wifi ui</p>"), (b"paging ui", b"<p>paging ui</p>"),
                             (b"wifiGo", WIFI_JS), (b"pageGo", PAGING_JS)):
            _, content = part_of(out, needle)
            self.assertEqual(content, body, needle)                   # exactly that file, nothing else
        for k, content in spa_parts(out).items():                     # and unguarded parts hold none of it
            if content not in (b"<p>wifi ui</p>", b"<p>paging ui</p>", WIFI_JS, PAGING_JS):
                for needle in (b"wifi ui", b"paging ui", b"wifiGo", b"pageGo"):
                    self.assertNotIn(needle, content, "PD_HTML_%d" % k)
        parts = spa_parts(out)
        self.assertEqual(b"".join(parts[k] for k in sorted(parts)), gen.assemble_spa(self.web))

    def test_definition_and_array_entry_are_both_wrapped_exactly(self):
        make_gweb(self.web)
        out = self.gen()
        for cond, needle in ((IF_WIFI, b"wifi ui"), (IF_WIFI, b"wifiGo"), (IF_PAGING, b"paging ui"), (IF_PAGING, b"pageGo")):
            i, content = part_of(out, needle)
            self.assertIn(cond + b"static const char PD_HTML_%d[] =\nR\"html%d(" % (i, i) + content
                          + b")html%d\";\n#endif\n" % i, out, needle)
            self.assertIn(cond + b"\t{ PD_HTML_%d, sizeof(PD_HTML_%d) - 1 },\n#endif\n" % (i, i), out, needle)
            self.assertEqual(array_ids(out).count(i), 1)
        unguarded = [k for k, v in spa_parts(out).items() if MARKER in v][0]
        self.assertNotIn(b"#if", out.split(b"static const char PD_HTML_%d[] =" % unguarded)[0].rsplit(b"\n", 2)[-2])
        self.assertIn(b"\t{ PD_HTML_%d, sizeof(PD_HTML_%d) - 1 },\n" % (unguarded, unguarded), out)
        self.assertNotIn(b"#if defined(HAS_WIFI) || !defined(ESP_PLATFORM)\n\t{ PD_HTML_%d," % unguarded, out)

    def test_the_value_form_adds_one_error_guard_and_the_flag_form_none(self):
        make_gweb(self.web)
        out = self.gen()
        belt = (b"#if defined(ESP_PLATFORM) && !defined(PAGING)\n#error \"PAGING must be defined (include its "
                b"header) before index_html.h\"\n#endif\n")
        self.assertEqual(out.count(belt), 1)
        self.assertLess(out.index(belt), out.index(IF_PAGING))
        self.assertEqual(out.count(b"#error"), 1)

    def test_the_marker_stays_in_an_unguarded_part(self):
        make_gweb(self.web)
        out = self.gen()
        self.assertEqual(out.count(MARKER), 3)                         # SPA once + the two standalone pages
        i, _ = part_of(out, MARKER)
        self.assertIn(b"\t{ PD_HTML_%d, sizeof(PD_HTML_%d) - 1 },\n" % (i, i), out)
        for cond in (IF_WIFI, IF_PAGING):                              # no guarded wrapper opens on the marker's part
            self.assertNotIn(cond + b"static const char PD_HTML_%d[] =" % i, out)
            self.assertNotIn(cond + b"\t{ PD_HTML_%d," % i, out)
        for bad in ("wifi_js", "paging_js", "wifi_html", "paging_html"):
            with self.subTest(guarded_file_with_marker=bad):
                make_gweb(self.web, **{bad: b"<p>x __PD_CSRF__ x</p>\n" if "html" in bad else b'var t="__PD_CSRF__";\n'})
                with self.assertRaisesRegex(gen.GenError, "in a guarded file.*unguarded part"):
                    self.gen()

    def test_the_value_form_adds_one_error_guard_and_the_flag_form_none(self):
        make_gweb(self.web)
        out = self.gen()
        belt = (b"#if defined(ESP_PLATFORM) && !defined(PAGING)\n#error \"PAGING must be defined (include its "
                b"header) before index_html.h\"\n#endif\n")
        self.assertEqual(out.count(belt), 1)
        self.assertLess(out.index(belt), out.index(IF_PAGING))
        self.assertEqual(out.count(b"#error"), 1)

    def test_an_oversized_guarded_file_splits_into_several_wrapped_parts_skipping_8_and_9(self):
        long_js = b"".join(b"var v%d=\"%s\";\n" % (i, b"q" * 80) for i in range(1100))      # ~100 KB
        make_gweb(self.web, wifi_js=long_js)
        out = self.gen()
        parts = spa_parts(out)
        wifi_ids = [k for k, v in parts.items() if v.startswith(b"var v") and v.endswith(b";\n")]
        self.assertGreater(len(wifi_ids), 5)
        self.assertEqual(b"".join(parts[k] for k in sorted(wifi_ids)), gen.min_js(long_js, "t.js"))
        ids = array_ids(out)
        self.assertNotIn(8, ids)
        self.assertNotIn(9, ids)
        self.assertTrue(any(i > 9 for i in wifi_ids))
        for i in wifi_ids:
            self.assertLessEqual(len(parts[i]), gen.PART_CAP)
            self.assertIn(IF_WIFI + b"static const char PD_HTML_%d[] =" % i, out)
            self.assertIn(IF_WIFI + b"\t{ PD_HTML_%d, sizeof(PD_HTML_%d) - 1 },\n#endif\n" % (i, i), out)
        self.assertEqual(b"".join(parts[k] for k in sorted(parts)), gen.assemble_spa(self.web))

    def test_adjacent_guarded_files_are_never_merged(self):
        man = GMANIFEST.replace(b"app/20-last.js\n", b"@if HAS_WIFI\napp/20-last.js\n").replace(
            b"@if PAGING!=0\napp/17-paging.js\n", b"@if HAS_WIFI\napp/17-paging.js\n")
        make_gweb(self.web, manifest=man, shell=SHELL)
        segs = gen.assemble_segments(self.web)
        js = [b for g, b in segs if g is not None and b.startswith(b"function ")]
        self.assertEqual(js, [WIFI_JS, PAGING_JS, LAST_JS])

    def test_generation_is_idempotent_and_check_agrees(self):
        make_gweb(self.web, wifi_js=WIFI_JS * 1000)
        once = self.gen()
        self.assertEqual(self.gen(once), once)
        self.assertNotIn(b"\r", once)

    def test_without_guards_the_output_has_no_preprocessor_lines(self):
        make_web(self.web)
        out = self.gen()
        self.assertNotIn(b"#error", out)
        self.assertEqual(out.count(b"\n#if"), 0)
        self.assertEqual(out.count(b"\n#endif"), 1)                    # the header's own include guard

    def test_the_shell_may_omit_guarded_scripts_or_list_them_in_manifest_order_only(self):
        make_gweb(self.web)                                            # GSHELL omits both guarded scripts
        self.gen()
        full = GSHELL.replace(b'<script src="app/20-last.js"></script>\n',
                              b'<script src="app/15-wifi.js"></script>\n<script src="app/17-paging.js"></script>\n'
                              b'<script src="app/20-last.js"></script>\n')
        make_gweb(self.web, shell=full)
        self.gen()
        swapped = full.replace(b"15-wifi", b"XX").replace(b"17-paging", b"15-wifi").replace(b"XX", b"17-paging")
        make_gweb(self.web, shell=swapped)
        with self.assertRaisesRegex(gen.GenError, "do not match manifest"):
            self.gen()
        make_gweb(self.web, shell=GSHELL.replace(b'<script src="app/20-last.js"></script>\n', b""))
        with self.assertRaisesRegex(gen.GenError, "do not match manifest"):    # an UNguarded script still must be there
            self.gen()


class GuardedManifestTest(Fixture):
    def parse(self, manifest):
        make_gweb(self.web, manifest=manifest)
        return gen.read_manifest_guards(self.web)

    def test_if_binds_to_the_next_path_only_and_read_manifest_still_lists_plain_paths(self):
        got = self.parse(b"# c\n@if A_B # trailing\n\n# more\napp/15-wifi.js\napp/17-paging.js\nindex.html\n")
        self.assertEqual(got, [("app/15-wifi.js", (("A_B", False, False),)), ("app/17-paging.js", None), ("index.html", None)])
        self.assertEqual(gen.read_manifest(self.web), ["app/15-wifi.js", "app/17-paging.js", "index.html"])
        self.assertEqual(self.parse(b"@if X!=0\nsections/15-wifi.html\n"), [("sections/15-wifi.html", (("X", True, False),))])

    def test_unless_parses_as_the_inverse_flag_clause_and_guard_lines_stack(self):
        self.assertEqual(self.parse(b"@unless SBC\napp/15-wifi.js\n"), [("app/15-wifi.js", (("SBC", False, True),))])
        self.assertEqual(self.parse(b"@if P!=0\n# c\n\n@unless SBC\napp/17-paging.js\n"),
                         [("app/17-paging.js", (("P", True, False), ("SBC", False, True)))])
        self.assertEqual(gen.guard_cond((("SBC", False, True),)), "!defined(SBC)")
        self.assertEqual(gen.guard_cond((("P", True, False), ("SBC", False, True))),
                         "((defined(P) && (P) != 0) && !defined(SBC))")
        with self.assertRaisesRegex(gen.GenError, "flag macro only"):
            self.parse(b"@unless SBC!=0\napp/15-wifi.js\n")
        with self.assertRaisesRegex(gen.GenError, "expected `@if NAME"):
            self.parse(b"@unless\napp/15-wifi.js\n")

    def test_dangling_doubled_and_malformed_ifs_are_errors(self):
        for text, rx in ((b"app/15-wifi.js\n@if A\n", "end with no path"),
                         (b"app/15-wifi.js\n@unless A\n", "`@unless A` at the end with no path"),
                         (b"@if A\n@if A\napp/15-wifi.js\n", "already in the guard"),
                         (b"@if A\n# only a comment\n\n@unless A\napp/15-wifi.js\n", "already in the guard"),
                         (b"@if\napp/15-wifi.js\n", "expected `@if NAME"),
                         (b"@if 1BAD\napp/15-wifi.js\n", "expected `@if NAME"),
                         (b"@if A B\napp/15-wifi.js\n", "expected `@if NAME"),
                         (b"@if A(1)\napp/15-wifi.js\n", "expected `@if NAME"),
                         (b"@if A!=1\napp/15-wifi.js\n", "expected `@if NAME"),
                         (b"@ifdef A\napp/15-wifi.js\n", "expected `@if NAME"),
                         (b"@if A;B\napp/15-wifi.js\n", "expected `@if NAME")):
            with self.subTest(text=text):
                make_gweb(self.web, manifest=text)
                with self.assertRaisesRegex(gen.GenError, rx):
                    gen.read_manifest_guards(self.web)

    def test_only_feature_js_and_fragments_may_be_guarded(self):
        for path in (b"index.html", b"app.css", b"app/00-core.js", b"manifest.txt"):
            with self.subTest(path=path):
                make_gweb(self.web, manifest=b"@if A\n" + path + b"\n")
                with self.assertRaisesRegex(gen.GenError, "may guard only"):
                    gen.read_manifest_guards(self.web)

    def test_a_guarded_path_listed_twice_is_still_a_duplicate(self):
        make_gweb(self.web, manifest=GMANIFEST + b"app/15-wifi.js\n")
        with self.assertRaisesRegex(gen.GenError, "duplicate"):
            self.gen()


class GuardedSlotTest(Fixture):
    def test_a_fragment_with_no_section_needs_exactly_one_slot(self):
        make_gweb(self.web, frag1=b"<h2>Overview</h2>\n<div id=\"paging-slot\"></div>\n")      # no wifi slot
        with self.assertRaisesRegex(gen.GenError, "15-wifi.html.*wifi-slot"):
            self.gen()
        make_gweb(self.web, frag1=SLOTS + b'<div id="wifi-slot"></div>\n')                    # two wifi slots
        with self.assertRaisesRegex(gen.GenError, "15-wifi.html.*wifi-slot"):
            self.gen()

    def test_the_slot_must_be_empty_and_exact(self):
        make_gweb(self.web, frag1=SLOTS.replace(b'<div id="wifi-slot"></div>', b'<div id="wifi-slot"> </div>'))
        with self.assertRaisesRegex(gen.GenError, "wifi-slot"):
            self.gen()

    def test_the_slot_cannot_live_in_a_fragment_that_owns_no_section(self):
        man = GMANIFEST.replace(b"@if HAS_WIFI\nsections/15-wifi.html\n",
                                b"@if HAS_WIFI\nsections/15-wifi.html\n@if HAS_WIFI\nsections/16-host.html\n")
        make_gweb(self.web, manifest=man, frag1=b"<h2>Overview</h2>\n<div id=\"paging-slot\"></div>\n")
        write(self.web, "sections/16-host.html", b'<div id="wifi-slot"></div>\n')
        with self.assertRaisesRegex(gen.GenError, "wifi-slot|sec-host"):
            self.gen()

    def test_a_guarded_host_takes_a_guest_only_when_the_guests_guard_implies_its_own(self):
        # the wifi fragment owns <section id="sec-wifi"> and hosts the paging slot
        shell = GSHELL.replace(b"</main>", b'<section id="sec-wifi" hidden></section>\n</main>')
        frag1 = b"<h2>Overview</h2>\n"
        wifi_html = b"<p>wifi ui</p>\n<div id=\"paging-slot\"></div>\n<p>wifi tail</p>\n"
        make_gweb(self.web, shell=shell, frag1=frag1, wifi_html=wifi_html)      # paging: PAGING!=0 only
        with self.assertRaisesRegex(gen.GenError, "17-paging.html.*paging-slot.*implies"):
            self.gen()
        man = GMANIFEST.replace(b"@if PAGING!=0\nsections/17-paging.html\n",
                                b"@if PAGING!=0\n@if HAS_WIFI\nsections/17-paging.html\n")
        make_gweb(self.web, shell=shell, manifest=man, frag1=frag1, wifi_html=wifi_html)
        out = self.gen()
        both = b"#if ((defined(PAGING) && (PAGING) != 0) && defined(HAS_WIFI)) || !defined(ESP_PLATFORM)\n"
        i, content = part_of(out, b"paging ui")
        self.assertEqual(content, b"<p>paging ui</p>")
        self.assertIn(both + b"static const char PD_HTML_%d[] =" % i, out)
        self.assertIn(both + b"\t{ PD_HTML_%d, sizeof(PD_HTML_%d) - 1 },\n#endif\n" % (i, i), out)
        head, _ = part_of(out, b"wifi ui")                                       # the host splits around the guest
        tail, _ = part_of(out, b"wifi tail")
        self.assertEqual([head, i, tail], sorted([head, i, tail]))
        for k in (head, tail):
            self.assertIn(IF_WIFI + b"static const char PD_HTML_%d[] =" % k, out)
        spa = gen.assemble_spa(self.web)
        self.assertIn(b'<section id="sec-wifi" hidden>\n<p>wifi ui</p>\n<div id="paging-slot">\n<p>paging ui</p>\n</div>\n'
                      b'<p>wifi tail</p>\n</section>', spa)
        parts = spa_parts(out)
        self.assertEqual(b"".join(parts[k] for k in sorted(parts)), spa)
        self.assertNotIn(b"\x00", out)

    def test_a_guarded_fragment_that_owns_a_section_takes_the_section_tags_into_its_part(self):
        shell = GSHELL.replace(b"</main>", b'<section id="sec-wifi" hidden></section>\n</main>')
        make_gweb(self.web, shell=shell, frag1=b'<h2>Overview</h2>\n<div id="paging-slot"></div>\n')
        out = self.gen()
        sec = b'<section id="sec-wifi" hidden>\n<p>wifi ui</p>\n</section>'
        i, content = part_of(out, b"wifi ui")
        self.assertEqual(content, sec)                                     # tags and body, nothing else
        self.assertIn(IF_WIFI + b"static const char PD_HTML_%d[] =" % i, out)
        self.assertIn(IF_WIFI + b"\t{ PD_HTML_%d, sizeof(PD_HTML_%d) - 1 },\n#endif\n" % (i, i), out)
        unguarded = b"".join(b for g, b in gen.assemble_segments(self.web) if g is None)
        self.assertNotIn(b"sec-wifi", unguarded)                            # a build without it has no #sec-wifi
        self.assertIn(sec, gen.assemble_spa(self.web))

    def test_an_unguarded_slot_fragment_is_inserted_in_place_without_wrapping(self):
        man = GMANIFEST.replace(b"@if HAS_WIFI\nsections/15-wifi.html\n", b"sections/15-wifi.html\n")
        make_gweb(self.web, manifest=man)
        out = self.gen()
        spa = gen.assemble_spa(self.web)
        self.assertIn(b'<div id="wifi-slot">\n<p>wifi ui</p>\n</div>', spa)
        self.assertEqual(out.count(IF_WIFI), 2)                            # only the JS (definition + entry) is wrapped
        i, content = part_of(out, b"wifiGo")
        self.assertEqual(content, WIFI_JS)
        self.assertNotIn(b"<p>wifi ui</p>", content)

    def test_nul_in_a_source_is_refused(self):
        make_gweb(self.web, wifi_html=b"<p>a\x00b</p>\n")
        with self.assertRaisesRegex(gen.GenError, "NUL"):
            self.gen()


UNLESS_SBC = b"#if !defined(SBC) || !defined(ESP_PLATFORM)\n"
ONLY_SBC = b"#if defined(SBC)\n"                                            # strict: no `|| !defined(ESP_PLATFORM)`
IF_PAGING_NOT_SBC = b"#if ((defined(PAGING) && (PAGING) != 0) && !defined(SBC)) || !defined(ESP_PLATFORM)\n"
UMANIFEST = (
    b"index.html\napp.css\napp/00-core.js\n"
    b"@only SBC\napp/05-sbc.js\n"
    b"app/10-overview.js\n"
    b"@unless SBC\napp/15-wifi.js\n"
    b"@if PAGING!=0\n@unless SBC\napp/17-paging.js\n"
    b"app/20-last.js\n"
    b"sections/10-overview.html\n"
    b"@only SBC\nsections/05-sbc.html\n"
    b"@unless SBC\nsections/15-wifi.html\n"
    b"@if PAGING!=0\n@unless SBC\nsections/17-paging.html\n"
    b"sections/40-trunks-numbers.html\n"
)
USHELL = GSHELL.replace(b"</main>", b'<section id="sec-wifi" hidden></section>\n</main>')
SBC_JS = b"PD_PROFILE.product=\"SBC\";\n"


def make_uweb(root, manifest=UMANIFEST, shell=USHELL):
    make_gweb(root, manifest=manifest, shell=shell, frag1=b'<h2>Overview</h2>\n<div id="paging-slot"></div>\n<div id="sbc-slot"></div>\n')
    write(root, "app/05-sbc.js", SBC_JS)
    write(root, "sections/05-sbc.html", b"<p>sbc ui</p>\n")


def preprocessed_spa(out, env):
    """The SPA an ESP/host build keeps: evaluate the `#if` line above each PD_HTML_N definition the way
    the preprocessor would, with `env` as the defined macros ({NAME: value}), and join the kept parts."""
    defs = re.findall(rb"(?:(#if [^\n]*)\n)?static const char PD_HTML_(\d+)\[\] =", out)
    assert defs

    def kept(cond):
        if not cond:
            return True
        expr = cond[len("#if "):].decode()
        expr = re.sub(r"!defined\((\w+)\)", lambda m: str(m.group(1) not in env), expr)
        expr = re.sub(r"defined\((\w+)\)", lambda m: str(m.group(1) in env), expr)
        expr = re.sub(r"\((\w+)\) != 0", lambda m: str(env.get(m.group(1), 0) != 0), expr)
        return eval(expr.replace("&&", " and ").replace("||", " or "))        # noqa: S307 - test-only

    parts = spa_parts(out)
    return b"".join(parts[int(i)] for c, i in defs if int(i) not in (8, 9) and kept(c))


def gxx_preprocess(header, defines):
    """`g++ -E -P` of a header file with `defines` (NAME or NAME=V), natively or through WSL on Windows.
    Returns the preprocessed bytes, or None when no g++ is reachable."""
    flags = ["-E", "-P", "-x", "c++"] + ["-D" + d for d in defines]
    if shutil.which("g++"):
        cmd = ["g++"] + flags + [header]
    elif sys.platform == "win32" and shutil.which("wsl"):
        try:
            probe = subprocess.run(["wsl", "-e", "sh", "-c", 'command -v g++ && wslpath -a "$1"', "_", header],
                                   capture_output=True, text=True, timeout=60)
        except (OSError, subprocess.TimeoutExpired):
            return None
        if probe.returncode:
            return None
        cmd = ["wsl", "-e", "g++"] + flags + [probe.stdout.split("\n")[1].strip()]
    else:
        return None
    p = subprocess.run(cmd, capture_output=True, timeout=120)
    if p.returncode:                                                       # a reachable g++ that fails IS a failure
        raise AssertionError("%s failed:\n%s" % (" ".join(cmd), p.stderr.decode(errors="replace")))
    return p.stdout


class UnlessTest(Fixture):
    """`@unless MACRO` is the inverse of `@if MACRO`: the part and its entry are wrapped in
    `#if !defined(MACRO) || !defined(ESP_PLATFORM)`; a guarded-and-unless file ANDs the two. The SBC copy
    in this fixture is `@only SBC`, the strict form (bare `#if defined(SBC)`, no host fallback)."""

    def test_unless_parts_are_wrapped_with_not_defined_and_the_only_parts_with_bare_defined(self):
        make_uweb(self.web)
        out = self.gen()
        for cond, needle, body in ((UNLESS_SBC, b"wifiGo", WIFI_JS),
                                   (UNLESS_SBC, b"wifi ui", b'<section id="sec-wifi" hidden>\n<p>wifi ui</p>\n</section>'),
                                   (IF_PAGING_NOT_SBC, b"pageGo", PAGING_JS),
                                   (IF_PAGING_NOT_SBC, b"paging ui", b"<p>paging ui</p>"),
                                   (ONLY_SBC, b"sbc ui", b"<p>sbc ui</p>"),
                                   (ONLY_SBC, b"PD_PROFILE", SBC_JS)):
            i, content = part_of(out, needle)
            self.assertEqual(content, body, needle)
            self.assertIn(cond + b"static const char PD_HTML_%d[] =\nR\"html%d(" % (i, i) + content
                          + b")html%d\";\n#endif\n" % i, out, needle)
            self.assertIn(cond + b"\t{ PD_HTML_%d, sizeof(PD_HTML_%d) - 1 },\n#endif\n" % (i, i), out, needle)
        self.assertEqual(out.count(b"#error"), 1)                          # the value form's belt, once
        self.assertEqual(out.count(UNLESS_SBC), 4)
        self.assertEqual(out.count(IF_PAGING_NOT_SBC), 4)
        self.assertEqual(out.count(ONLY_SBC), 4)                           # 2 definitions + 2 entries
        self.assertNotIn(b"#if defined(SBC) ||", out)                      # never with the host fallback

    def test_an_if_and_an_unless_never_share_a_part_and_the_whole_page_rejoins(self):
        make_uweb(self.web)
        segs = gen.assemble_segments(self.web)
        guarded = [(g, b) for g, b in segs if g is not None]
        # page order: the two slot fragments in overview, the wifi section, then the script's guarded files
        self.assertEqual([g for g, _ in guarded], [
            (("PAGING", True, False), ("SBC", False, True)), (("SBC", False, gen.ONLY),), (("SBC", False, True),),
            (("SBC", False, gen.ONLY),), (("SBC", False, True),), (("PAGING", True, False), ("SBC", False, True))])
        for _, b in guarded:
            self.assertEqual(b.count(b"<script>") + b.count(b"<section"), b.count(b"</script>") + b.count(b"</section>"))
        out = self.gen()
        parts = spa_parts(out)
        self.assertEqual(b"".join(parts[k] for k in sorted(parts)), gen.assemble_spa(self.web))
        self.assertEqual(self.gen(out), out)

    def test_the_preprocessor_keeps_exactly_the_right_parts_per_build(self):
        """Evaluate the emitted #if lines the way the compiler would, for every macro combination."""
        make_uweb(self.web)
        out = self.gen()
        self.assertGreaterEqual(len(spa_parts(out)), 6)
        # the `@only` copy is kept on SBC builds alone: the host build (no ESP_PLATFORM) loses it too
        for env, want_sbc, want_wifi, want_paging in (({"ESP_PLATFORM": 1, "PAGING": 1}, False, True, True),
                                                      ({"ESP_PLATFORM": 1, "PAGING": 0}, False, True, False),
                                                      ({"ESP_PLATFORM": 1, "PAGING": 1, "SBC": 1}, True, False, False),
                                                      ({"PAGING": 0}, False, True, True),
                                                      ({}, False, True, True),
                                                      ({"SBC": 1}, True, True, True)):
            spa = preprocessed_spa(out, env)
            self.assertEqual(b"sbc ui" in spa, want_sbc, env)
            self.assertEqual(SBC_JS in spa, want_sbc, env)
            self.assertEqual(b"wifi ui" in spa, want_wifi, env)
            self.assertEqual(b"sec-wifi" in spa, want_wifi, env)
            self.assertEqual(b"paging ui" in spa, want_paging, env)
            self.assertEqual(spa.count(MARKER), 1, env)


class OnlyTest(Fixture):
    """`@only MACRO` is the strict `@if`: the part and its entry are wrapped in a bare `#if defined(MACRO)`
    with no `|| !defined(ESP_PLATFORM)`, so the host build never carries product-profile copy either."""

    def test_only_parses_as_a_strict_clause_that_stands_alone(self):
        make_gweb(self.web, manifest=b"@only SBC\napp/15-wifi.js\n")
        self.assertEqual(gen.read_manifest_guards(self.web), [("app/15-wifi.js", (("SBC", False, gen.ONLY),))])
        self.assertEqual(gen.guard_cond((("SBC", False, gen.ONLY),)), "defined(SBC)")
        self.assertTrue(gen.is_strict((("SBC", False, gen.ONLY),)))
        self.assertFalse(gen.is_strict((("SBC", False, False),)))
        self.assertFalse(gen.is_strict((("P", True, False), ("SBC", False, True))))
        for text, rx in ((b"@only SBC!=0\napp/15-wifi.js\n", "flag macro only"),
                         (b"@only\napp/15-wifi.js\n", "expected `@if NAME"),
                         (b"@if P!=0\n@only SBC\napp/17-paging.js\n", "stands alone"),
                         (b"@unless X\n@only SBC\napp/17-paging.js\n", "stands alone"),
                         (b"@only SBC\n@if P!=0\napp/17-paging.js\n", "stands alone"),
                         (b"@only SBC\n@unless X\napp/17-paging.js\n", "stands alone"),
                         (b"@only SBC\n@only SBC\napp/17-paging.js\n", "stands alone"),
                         (b"app/15-wifi.js\n@only SBC\n", "`@only SBC` at the end with no path"),
                         (b"@only SBC\napp/00-core.js\n", "may guard only"),
                         (b"@only SBC\napp.css\n", "may guard only")):
            with self.subTest(text=text):
                make_gweb(self.web, manifest=text)
                with self.assertRaisesRegex(gen.GenError, rx):
                    gen.read_manifest_guards(self.web)

    def test_only_parts_are_wrapped_in_the_bare_defined_with_no_host_fallback(self):
        make_uweb(self.web)
        out = self.gen()
        for needle, body in ((b"sbc ui", b"<p>sbc ui</p>"), (b"PD_PROFILE", SBC_JS)):
            i, content = part_of(out, needle)
            self.assertEqual(content, body, needle)                        # its own part: exactly that file
            self.assertIn(ONLY_SBC + b"static const char PD_HTML_%d[] =\nR\"html%d(" % (i, i) + content
                          + b")html%d\";\n#endif\n" % i, out, needle)
            self.assertIn(ONLY_SBC + b"\t{ PD_HTML_%d, sizeof(PD_HTML_%d) - 1 },\n#endif\n" % (i, i), out, needle)
            self.assertEqual(array_ids(out).count(i), 1)
        self.assertEqual(out.count(ONLY_SBC), 4)
        self.assertNotIn(b"#if defined(SBC) ||", out)                      # never with the host fallback
        for k, content in spa_parts(out).items():                          # no other part holds a byte of it
            if content not in (b"<p>sbc ui</p>", SBC_JS):
                self.assertNotIn(b"sbc ui", content, k)
                self.assertNotIn(b"PD_PROFILE", content, k)
        self.assertEqual(gen.wrap((("SBC", False, gen.ONLY),), b"x\n"), b"#if defined(SBC)\nx\n#endif\n")
        self.assertEqual(gen.wrap((("SBC", False, False),), b"x\n"),
                         b"#if defined(SBC) || !defined(ESP_PLATFORM)\nx\n#endif\n")
        self.assertEqual(gen.wrap((("SBC", False, True),), b"x\n"),
                         b"#if !defined(SBC) || !defined(ESP_PLATFORM)\nx\n#endif\n")

    def test_an_only_file_that_owns_a_section_takes_the_tags_and_splits_into_its_own_wrapped_parts(self):
        shell = USHELL.replace(b"</main>", b'<section id="sec-sbc" hidden></section>\n</main>')
        make_uweb(self.web, shell=shell)
        long_html = b"".join(b"<p>sbc line %d %s</p>\n" % (i, b"s" * 70) for i in range(500))      # ~45 KB
        write(self.web, "sections/05-sbc.html", long_html)
        out = self.gen()
        parts = spa_parts(out)
        sbc_ids = sorted(k for k, v in parts.items() if b"sbc line" in v)
        self.assertGreater(len(sbc_ids), 2)
        joined = b"".join(parts[k] for k in sbc_ids)
        self.assertTrue(joined.startswith(b'<section id="sec-sbc" hidden>\n<p>sbc line 0 '))
        self.assertTrue(joined.endswith(b"</p>\n</section>"))
        for i in sbc_ids:
            self.assertLessEqual(len(parts[i]), gen.PART_CAP)
            self.assertIn(ONLY_SBC + b"static const char PD_HTML_%d[] =" % i, out)
            self.assertIn(ONLY_SBC + b"\t{ PD_HTML_%d, sizeof(PD_HTML_%d) - 1 },\n#endif\n" % (i, i), out)
        self.assertNotIn(b"sec-sbc", preprocessed_spa(out, {}))
        self.assertNotIn(b"sec-sbc", preprocessed_spa(out, {"ESP_PLATFORM": 1, "PAGING": 1}))
        self.assertIn(b'<section id="sec-sbc" hidden>', preprocessed_spa(out, {"SBC": 1}))
        self.assertEqual(b"".join(parts[k] for k in sorted(parts)), gen.assemble_spa(self.web))

    def test_the_marker_in_an_only_file_is_refused(self):
        for rel, data in (("app/05-sbc.js", b'var t="__PD_CSRF__";\n'), ("sections/05-sbc.html", b"<p>__PD_CSRF__</p>\n")):
            with self.subTest(rel=rel):
                make_uweb(self.web)
                write(self.web, rel, data)
                with self.assertRaisesRegex(gen.GenError, "in a guarded file.*unguarded part"):
                    self.gen()

    def test_an_only_host_takes_a_guest_only_under_the_same_only_guard(self):
        shell = USHELL.replace(b"</main>", b'<section id="sec-sbc" hidden></section>\n</main>')
        man = UMANIFEST.replace(b"@unless SBC\nsections/15-wifi.html\n", b"@unless SBC\nsections/15-wifi.html\n"
                                b"@only SBC\nsections/16-extra.html\n")
        make_uweb(self.web, manifest=man, shell=shell)
        write(self.web, "sections/05-sbc.html", b'<p>sbc ui</p>\n<div id="extra-slot"></div>\n')
        write(self.web, "sections/16-extra.html", b"<p>extra</p>\n")
        out = self.gen()
        self.assertIn(b'<div id="extra-slot">\n<p>extra</p>\n</div>', gen.assemble_spa(self.web))
        self.assertNotIn(b"extra", preprocessed_spa(out, {}))
        self.assertIn(b"<p>extra</p>", preprocessed_spa(out, {"SBC": 1, "ESP_PLATFORM": 1, "PAGING": 1}))
        man2 = man.replace(b"@only SBC\nsections/16-extra.html\n", b"sections/16-extra.html\n")
        make_uweb(self.web, manifest=man2, shell=shell)                     # an unguarded guest in an @only host
        write(self.web, "sections/05-sbc.html", b'<p>sbc ui</p>\n<div id="extra-slot"></div>\n')
        write(self.web, "sections/16-extra.html", b"<p>extra</p>\n")
        with self.assertRaisesRegex(gen.GenError, "16-extra.html.*extra-slot.*implies"):
            self.gen()


class RealGuardedSourcesTest(unittest.TestCase):
    """Builds that leave a guarded file out must still run: nothing unguarded may name what a guarded
    file defines, and every literal $("id") in the unguarded page must resolve to an id in it."""
    WEB = os.path.join(REPO, "web")
    # the only references unguarded code is allowed to make, behind a typeof check
    ALLOWED = (b'if(typeof chPagingTick==="function")chPagingTick(authed);',
               b'if(typeof tnDidLoad==="function")tnDidLoad();')

    def setUp(self):
        if not os.path.isfile(os.path.join(self.WEB, "manifest.txt")):
            self.skipTest("web/ not present")
        self.guards = {e: g for e, g in gen.read_manifest_guards(self.WEB) if g}
        self.assertTrue(self.guards)
        segs = gen.assemble_segments(self.WEB)
        self.unguarded = b"".join(b for g, b in segs if g is None)
        self.guarded = b"".join(b for g, b in segs if g is not None)
        for allowed in self.ALLOWED:
            self.unguarded = self.unguarded.replace(allowed, b"")

    def test_unguarded_code_never_names_anything_a_guarded_file_defines(self):
        names = set()
        for e in self.guards:
            if e.endswith(".js"):
                data = gen.read_source(self.WEB, e)
                names |= set(re.findall(rb"^(?:function|var) ([A-Za-z0-9_$]+)", data, re.M))
        self.assertTrue({b"renderWifi", b"startApMode", b"holdConfigMode", b"chLoadMulticast",
                         b"chSaveMulticast", b"mntWifiSelected", b"mntBars", b"tnDidLoad", b"tnAddDid",
                         b"rtLoaded", b"mohUploading"} <= names, sorted(names))
        for n in sorted(names):
            self.assertIsNone(re.search(rb"(?<![A-Za-z0-9_$])" + re.escape(n) + rb"(?![A-Za-z0-9_$])", self.unguarded),
                              "unguarded page text still names %s" % n.decode())

    def test_every_literal_dollar_id_in_the_unguarded_page_resolves_without_the_guarded_markup(self):
        ids = set(re.findall(rb'\bid="([^"]+)"', self.unguarded))
        refs = set(re.findall(rb'\$\("([^"]+)"\)', self.unguarded))
        self.assertTrue(refs)
        self.assertEqual(sorted(r for r in refs if r not in ids), [])

    def test_guarded_markup_ids_are_not_used_by_name_in_the_unguarded_page(self):
        gids = set(re.findall(rb'\bid="([^"]+)"', self.guarded)) - set(re.findall(rb'\bid="([^"]+)"', self.unguarded))
        self.assertIn(b"mnt-scan-btn", gids)
        self.assertIn(b"ch-mc-save", gids)
        self.assertIn(b"tn-did-add", gids)
        self.assertIn(b"sec-audio", gids)                                    # the SBC build has no Audio section
        for i in sorted(gids):
            self.assertNotIn(b'"' + i + b'"', self.unguarded, i.decode())
            self.assertNotIn(b"'" + i + b"'", self.unguarded, i.decode())

    def test_the_real_header_wraps_only_the_guarded_files(self):
        out = gen.generate(self.WEB, OLD_HEADER)
        self.assertEqual(out.count(IF_PAGING_NOT_SBC.replace(b"PAGING", b"POCKETDIAL_MULTICAST_PAGING")
                                   .replace(b"SBC", b"POCKETDIAL_PROFILE_SBC")), 4)             # 2 defs + 2 entries
        self.assertEqual(out.count(IF_WIFI.replace(b"HAS_WIFI", b"POCKETDIAL_HAS_WIFI")), 4)
        self.assertEqual(out.count(b"#if defined(POCKETDIAL_PROFILE_SBC)\n"), 4)   # @only: bare, 2 defs + 2 entries
        self.assertNotIn(b"#if defined(POCKETDIAL_PROFILE_SBC) ||", out)
        unless = out.count(UNLESS_SBC.replace(b"SBC", b"POCKETDIAL_PROFILE_SBC"))
        n_unless_parts = sum(1 for g, _ in gen.split_segments(gen.assemble_segments(self.WEB))
                             if g == (("POCKETDIAL_PROFILE_SBC", False, True),))
        self.assertGreaterEqual(n_unless_parts, 8)                           # 4 fragments + 4 JS files, at least
        self.assertEqual(unless, 2 * n_unless_parts)
        self.assertEqual(out.count(b"\n#if "), 13 + unless)                 # 12 wrappers + the #error belt
        self.assertEqual(out.count(b"#error"), 1)
        self.assertIn(b"POCKETDIAL_MULTICAST_PAGING must be defined", out)
        self.assertEqual(gen.generate(self.WEB, out), out)
        flat = gen.assemble_spa(self.WEB)
        parts = spa_parts(out)
        self.assertEqual(b"".join(parts[k] for k in sorted(parts)), flat)
        self.assertEqual(flat.count(MARKER), 1)
        self.assertIn(b"function renderWifi(nets){", flat)             # the host page keeps everything
        self.assertIn(b"function chLoadMulticast(){", flat)
        self.assertIn(b"function tnAddDid(){", flat)
        self.assertIn(b'<section id="sec-audio"', flat)

    def test_the_sbc_build_keeps_the_profile_copy_and_loses_the_3cx_owned_sections(self):
        """What an ESP build with POCKETDIAL_PROFILE_SBC serves: the parts whose #if holds."""
        sbc = b"".join(b for g, b in gen.assemble_segments(self.WEB)
                       if g is None or g == (("POCKETDIAL_PROFILE_SBC", False, gen.ONLY),))
        self.assertIn(b"POCKET-DIAL SBC", sbc)
        self.assertIn(b"E911 VIA 3CX", sbc)
        self.assertIn(b"SBC mode: host-tested only", sbc)
        self.assertEqual(sbc.count(MARKER), 1)
        for gone in (b"sec-routing", b"sec-call-handling", b"sec-audio", b"tn-did-add", b"paging-slot\">\n<",
                     b"function tnAddDid(", b"function chLoadMulticast(", b"function rtAria("):
            self.assertNotIn(gone, sbc, gone.decode())
        for kept in (b"sec-overview", b"sec-extensions", b"sec-trunks-numbers", b"sec-security",
                     b"sec-maintenance", b"sec-console", b'<div id="did-slot">\n\n</div>'):
            self.assertIn(kept, sbc, kept.decode())

    # the `@only` copy's strings: present on an SBC build, absent from every other build AND the host page
    SBC_STRINGS = (b"POCKET-DIAL SBC", b"E911 VIA 3CX", b"SBC mode: host-tested only", b'window.PD_PRODUCT="')
    # what the ESP build without the profile and the host build keep in each case
    ESP = ("ESP_PLATFORM", "POCKETDIAL_MULTICAST_PAGING=1")        # the value form's belt demands PAGING on ESP
    SBC = ("POCKETDIAL_PROFILE_SBC",)

    def check_profile_page(self, page, defines, want_sbc, marker_count):
        for s in self.SBC_STRINGS:
            self.assertEqual(s in page, want_sbc, "%s with -D%s" % (s.decode(), " -D".join(defines) or "nothing"))
        self.assertEqual(page.count(MARKER), marker_count, defines)
        self.assertEqual(b"function renderWifi(nets){" in page, "ESP_PLATFORM" not in defines, defines)
        self.assertEqual(b'<section id="sec-audio"' in page, "POCKETDIAL_PROFILE_SBC" not in defines
                         or "ESP_PLATFORM" not in defines, defines)

    def test_the_real_header_evaluated_per_build_carries_the_sbc_copy_on_sbc_builds_alone(self):
        out = gen.generate(self.WEB, OLD_HEADER)
        for defines, want_sbc in ((self.ESP, False), ((), False), (self.SBC, True), (self.ESP + self.SBC, True)):
            env = {d.split("=")[0]: int(d.split("=")[1]) if "=" in d else 1 for d in defines}
            self.check_profile_page(preprocessed_spa(out, env), defines, want_sbc, 1)

    def test_the_real_header_through_gxx_dash_e_carries_the_sbc_copy_on_sbc_builds_alone(self):
        """The same four builds through the real preprocessor (g++ -E, natively or via WSL); the three
        __PD_CSRF__ are the SPA's one plus the two standalone pages, which no guard touches."""
        out = gen.generate(self.WEB, OLD_HEADER)
        with tempfile.TemporaryDirectory() as tmp:
            header = os.path.join(tmp, "index_html.h")
            with open(header, "wb") as f:
                f.write(out)
            for defines, want_sbc in ((self.ESP, False), ((), False), (self.SBC, True), (self.ESP + self.SBC, True)):
                page = gxx_preprocess(header, defines)
                if page is None:
                    self.skipTest("no g++ reachable (natively or through WSL)")
                self.check_profile_page(page, defines, want_sbc, 3)


if __name__ == "__main__":
    unittest.main()
