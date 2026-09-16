#!/usr/bin/env python3
"""Enforce MSVC's string-literal size cap on a Linux runner (issue #270).

WHY THIS EXISTS
---------------
`src/Helpers/index_html.h` is split into PD_HTML_0..N for one reason, stated
at length in that file's own header: MSVC caps a single string-literal TOKEN,
and this page's HTML+CSS+JS is far past it. GCC and Clang have no comparable
limit, and every runner in .github/workflows/ is Linux. So a part that grows
past the cap builds green here, merges, and then fails for whoever next
compiles on Windows with a `C2026: string too big, trailing characters
truncated` pointing at a line they did not write.

The constraint is a byte count, so it does not need the compiler that
enforces it. This script is that check.

THE CAPS, MEASURED
------------------
Every constant below was measured against the real toolset rather than taken
from documentation -- `tools/msvc_literal_cap_probe.py` regenerates the
probes. Compiler: cl 19.44.35228 (VS 2022 BuildTools), `/std:c++17 /c`.

  raw string literal        16384 bytes of content  -> OK
                            16385                   -> C2026, exit 2
  ordinary string literal   16383 chars of result   -> OK
                            16384                   -> C2026, exit 2

The two differ by one, consistently and reproducibly. The likely reason is
that the ordinary path counts the object including its NUL terminator and the
raw path does not, but the caps here record what was MEASURED rather than
that guess -- the guess does not move the boundary.

MSVC's own docs cite 16380 for the single-token limit, which this toolset
does not match. The hard failure therefore uses the measured value, and the
"tight" warning band is wide enough (512 bytes) that the disagreement can
never be the thing that decides a build.

ESCAPES COUNT ONCE, NOT TWICE. MSVC counts an ordinary literal's RESULTING
characters, not its source bytes: a literal of 16383 backslash-n escapes is
32766 source bytes and compiles clean, while 16384 of them fails. Measuring
source bytes would therefore reject valid code, so ordinary literals are
decoded before they are measured. Raw literals have no escapes, so their
content is their bytes.

THE CONCATENATION LIMIT IS NOT REAL HERE. index_html.h's header, and MSVC's
docs, both state that a run of ADJACENT literal tokens is separately capped
at 65535 bytes. On cl 19.44 it is not enforced: 64 adjacent ordinary literals
totalling 1048512 bytes compile clean, as do 40 raw ones totalling 655360. So
this is reported as a WARNING and never fails a build -- the documented limit
may be real on some other toolset, and the check costs nothing, but it must
not redden a PR over a limit this project's actual compiler does not apply.

LINE ENDINGS ARE NORMALIZED BEFORE MEASURING, and that is correctness, not
tidiness. Translation phase 1 maps a physical end-of-line sequence to one
newline character, so a CRLF file's literal holds LF and each line costs the
compiler one byte, not two. This repo stores index_html.h with LF and checks
it out with CRLF on Windows, so measuring raw bytes made the same tree report
~2000 bytes larger on a developer's box than on the Linux runner -- enough to
fail a build MSVC compiles happily. `tools/msvc_literal_cap_probe.py` ends by
cross-checking every part's byte count against the compiler's own
sizeof(PD_HTML_N)-1; they agree exactly, which is the only real proof that
this script and cl are measuring the same thing.

THE EXTRACTION TRAP
-------------------
index_html.h uses a DIFFERENT raw-string delimiter per part -- `R"html3( ...
)html3";`, not one shared tag -- and the opener sits inline with content
rather than on its own line. A regex that assumes a single uniform delimiter
silently mis-measures every part after the first. That has already cost real
time once; see the note in issue #270.

So this walks the file as C++ source rather than pattern-matching it:
comments, character literals, ordinary string literals and raw string
literals are each consumed by their own rule. A `R"html3(` inside a comment
or inside another string cannot be mistaken for an opener, and the closer
matched is always the one that was actually opened. `--selftest` pins the
cases a naive extractor gets wrong.

Usage:
    python3 tools/check_string_literal_caps.py [path ...]
    python3 tools/check_string_literal_caps.py --selftest

With no arguments it scans src/ and main/. Exits non-zero if any literal is
over cap.
"""

import os
import sys
import tempfile

# Measured on cl 19.44.35228; see the module docstring and the probe script.
RAW_CAP = 16384
ORDINARY_CAP = 16383

# Documented by MSVC and by index_html.h's header, but NOT enforced by cl
# 19.44 at 16x this size. Warning only -- see the docstring.
RUN_CAP = 65535

# Headroom below which a literal is reported as tight. NOT a failure -- the
# point is to make "this part is nearly full" visible in review, while the
# split point can still be moved in the same PR, instead of only at the
# cliff. The accessibility pass (#269) left a part at 112 bytes free: that
# state was CI-green, and the NEXT edit to it would have been the one that
# broke, for someone who did nothing wrong. 512 bytes is roughly one modest
# form control's worth of markup -- enough lead time to act on, rare enough
# not to become noise.
TIGHT_BYTES = 512

# Literals smaller than this are never listed in the table. There are
# thousands of them and neither cap is reachable from here; listing them
# would bury the ones that matter.
REPORT_FLOOR = 1024

SOURCE_EXTS = (".h", ".hpp", ".hxx", ".c", ".cc", ".cpp", ".cxx", ".ipp")

SKIP_DIRS = (".git", "build", "build-wsl", "managed_components")

# Encoding prefixes a string literal may carry. Longest first so that `u8`
# is not matched as a bare `u`.
STR_PREFIXES = ("u8", "L", "u", "U")

# Escapes that always produce exactly one byte.
SIMPLE_ESCAPES = set("abfnrtv'\"?\\")
OCTAL_DIGITS = set("01234567")
HEX_DIGITS = set("0123456789abcdefABCDEF")


class Literal:
    """One string-literal token, with the span the compiler counts."""

    def __init__(self, kind, tag, start, end, body):
        self.kind = kind      # "raw" or "ordinary"
        self.tag = tag        # raw delimiter, or "" for ordinary
        self.start = start    # offset of the first char of the token
        self.end = end        # offset one past the last char of the token
        self.body = body      # source text between the delimiters

    @property
    def cap(self):
        return RAW_CAP if self.kind == "raw" else ORDINARY_CAP

    @property
    def counted(self):
        """Bytes the compiler counts against the cap.

        Raw literals have no escapes, so their content is their bytes.
        Ordinary literals are counted by RESULT -- see the docstring.
        """
        if self.kind == "raw":
            return len(self.body.encode("utf-8"))
        return decoded_length(self.body)


def decoded_length(s):
    """Length in bytes of an ordinary literal's body after escape processing."""
    out = 0
    i = 0
    n = len(s)
    while i < n:
        ch = s[i]
        if ch != "\\":
            out += len(ch.encode("utf-8"))
            i += 1
            continue
        i += 1
        if i >= n:
            out += 1
            break
        e = s[i]
        if e in SIMPLE_ESCAPES:
            out += 1
            i += 1
        elif e in OCTAL_DIGITS:
            j = i
            while j < n and j - i < 3 and s[j] in OCTAL_DIGITS:
                j += 1
            out += 1
            i = j
        elif e == "x":
            j = i + 1
            while j < n and s[j] in HEX_DIGITS:
                j += 1
            out += 1
            i = j
        elif e in "uU":
            width = 4 if e == "u" else 8
            digits = s[i + 1:i + 1 + width]
            try:
                out += len(chr(int(digits, 16)).encode("utf-8"))
            except (ValueError, OverflowError):
                out += 1
            i += 1 + len(digits)
        else:
            # Not a valid escape; the compiler would diagnose it. Count the
            # character and keep going rather than derail the scan.
            out += 1
            i += 1
    return out


def _ident_char(ch):
    return ch.isalnum() or ch == "_"


def scan_literals(text):
    """Walk C++ source, returning every string-literal token in order.

    Deliberately a scanner and not a regex: the whole point is that a
    delimiter-shaped thing inside a comment or another string must not be
    treated as a delimiter.
    """
    literals = []
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]

        # -- comments ----------------------------------------------------
        if ch == "/" and i + 1 < n:
            if text[i + 1] == "/":
                j = text.find("\n", i)
                i = n if j < 0 else j + 1
                continue
            if text[i + 1] == "*":
                j = text.find("*/", i + 2)
                i = n if j < 0 else j + 2
                continue

        # -- character literal -------------------------------------------
        # Guarded against C++14 digit separators (1'000'000), where the
        # quote follows an identifier character rather than opening
        # anything.
        if ch == "'" and not (i > 0 and _ident_char(text[i - 1])):
            i += 1
            while i < n:
                if text[i] == "\\":
                    i += 2
                    continue
                if text[i] == "'":
                    i += 1
                    break
                i += 1
            continue

        # -- string literal, raw or ordinary -----------------------------
        if ch == '"' or ch == "R":
            start = i
            prefix_start = start
            for p in STR_PREFIXES:
                q = start - len(p)
                if q >= 0 and text.startswith(p, q):
                    # Only a prefix if it is not itself part of a longer
                    # identifier.
                    if q == 0 or not _ident_char(text[q - 1]):
                        prefix_start = q
                        break

            if ch == "R":
                if i + 1 >= n or text[i + 1] != '"':
                    i += 1
                    continue
                # An R that is the tail of an identifier (FOOR"...") is not
                # a raw-string introducer.
                if start > 0 and _ident_char(text[start - 1]) and prefix_start == start:
                    i += 1
                    continue
                j = text.find("(", i + 2)
                if j < 0:
                    i += 1
                    continue
                tag = text[i + 2:j]
                closer = ")" + tag + '"'
                k = text.find(closer, j + 1)
                if k < 0:
                    i += 1
                    continue
                literals.append(Literal("raw", tag, prefix_start,
                                        k + len(closer), text[j + 1:k]))
                i = k + len(closer)
                continue

            # Ordinary "...". A malformed raw literal (an `R"` with no
            # following `(`, or no matching closer) falls through to here
            # from the branch above and is read as an ordinary string, which
            # keeps the scanner in sync with the rest of the file rather
            # than derailing it.
            i += 1
            body_start = i
            while i < n:
                if text[i] == "\\":
                    i += 2
                    continue
                if text[i] == '"':
                    break
                if text[i] == "\n":
                    # Unterminated -- abandon this token rather than swallow
                    # the rest of the file.
                    break
                i += 1
            if i < n and text[i] == '"':
                literals.append(Literal("ordinary", "", prefix_start, i + 1,
                                        text[body_start:i]))
                i += 1
            continue

        i += 1

    return literals


def label_for(text, lit):
    """Best-effort name for a literal: the variable it initializes."""
    head = text[max(0, lit.start - 400):lit.start]
    j = len(head)
    while j > 0 and head[j - 1].isspace():
        j -= 1
    if j == 0 or head[j - 1] != "=":
        return None
    j -= 1
    while j > 0 and head[j - 1].isspace():
        j -= 1
    if j > 0 and head[j - 1] == "]":
        k = head.rfind("[", 0, j)
        if k < 0:
            return None
        j = k
        while j > 0 and head[j - 1].isspace():
            j -= 1
    end = j
    while j > 0 and _ident_char(head[j - 1]):
        j -= 1
    name = head[j:end]
    return name or None


def between_is_blank(text, a, b):
    """True if only whitespace and comments separate two tokens.

    That is exactly the condition under which the compiler concatenates
    them into one object.
    """
    i = a
    while i < b:
        ch = text[i]
        if ch.isspace():
            i += 1
            continue
        if ch == "/" and i + 1 < b:
            if text[i + 1] == "/":
                j = text.find("\n", i)
                if j < 0 or j >= b:
                    return False
                i = j + 1
                continue
            if text[i + 1] == "*":
                j = text.find("*/", i + 2)
                if j < 0 or j + 2 > b:
                    return False
                i = j + 2
                continue
        return False
    return True


def runs_of(text, literals):
    """Group literals into maximal runs the compiler would concatenate."""
    out = []
    run = []
    for lit in literals:
        if run and between_is_blank(text, run[-1].end, lit.start):
            run.append(lit)
        else:
            if len(run) > 1:
                out.append(run)
            run = [lit]
    if len(run) > 1:
        out.append(run)
    return out


def read_source(path):
    """Read a source file the way the compiler sees it.

    LINE ENDINGS ARE NORMALIZED, and that is load-bearing rather than
    tidiness. Translation phase 1 maps physical end-of-line sequences to
    newline characters, so a CRLF file's literal holds LF and each line
    costs the compiler ONE byte, not two. Verified against cl 19.44: the
    sum of sizeof(PD_HTML_N)-1 over index_html.h's parts is 115588, which
    is the LF count; the CRLF count is 117580.

    This repo stores the file with LF and checks it out with CRLF on
    Windows, so without this the same tree measures differently on a
    developer's box than on the Linux runner -- and the Windows reading
    over-reports every part by roughly its line count (~2000 bytes on a
    16 KB part), which is enough to fail a build that MSVC would compile
    perfectly happily.
    """
    with open(path, "rb") as f:
        text = f.read().decode("utf-8", errors="replace")
    CR, LF = chr(13), chr(10)
    return text.replace(CR + LF, LF).replace(CR, LF)


def check_file(path):
    """Return (errors, warnings, rows) for one source file."""
    text = read_source(path)

    literals = scan_literals(text)
    errors, warnings, rows = [], [], []

    for lit in literals:
        size = lit.counted
        if size < REPORT_FLOOR:
            continue
        cap = lit.cap
        line = text.count("\n", 0, lit.start) + 1
        name = label_for(text, lit) or ("line %d" % line)
        rows.append((path, name, lit.kind, line, size, cap - size))
        if size > cap:
            errors.append(
                "%s:%d: %s literal %s is %d bytes, %d over MSVC's %d-byte "
                "single-token cap (C2026)."
                % (path, line, lit.kind, name, size, size - cap, cap))
        elif cap - size < TIGHT_BYTES:
            warnings.append(
                "%s:%d: literal %s has only %d bytes of headroom under the "
                "%d-byte cap. Move a split point before adding to it."
                % (path, line, name, cap - size, cap))

    for run in runs_of(text, literals):
        total = sum(l.counted for l in run)
        if total <= RUN_CAP:
            continue
        line = text.count("\n", 0, run[0].start) + 1
        warnings.append(
            "%s:%d: %d adjacent literals concatenate to %d bytes, past the "
            "%d-byte limit MSVC documents for a concatenated literal. Not an "
            "error: cl 19.44 does not enforce it (measured clean at 1048512 "
            "bytes), but another toolset might."
            % (path, line, len(run), total, RUN_CAP))

    return errors, warnings, rows


def iter_sources(paths):
    for p in paths:
        if os.path.isfile(p):
            yield p
            continue
        for root, dirs, files in os.walk(p):
            dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
            for f in sorted(files):
                if f.endswith(SOURCE_EXTS):
                    yield os.path.join(root, f)


# ---------------------------------------------------------------------------
# Self-test.
#
# The scanner is the part of this check that can be WRONG WITHOUT LOOKING
# WRONG -- a mis-extraction reports a confident, specific, and entirely fake
# byte count, which is exactly the failure mode issue #270 warns about. So
# the tricky cases are pinned here rather than left to the reader's trust,
# and CI runs them before it runs the check itself.
# ---------------------------------------------------------------------------

def _selftest():
    q = chr(34)      # a double quote, kept out of this file's own literals
    bs = chr(92)     # a backslash, likewise
    nl = chr(10)
    cases = []

    def case(name, src, expect):
        """expect: list of (kind, tag, body) for every literal, in order."""
        cases.append((name, src, expect))

    # The actual trap: per-part delimiters, openers inline with content. A
    # uniform-tag regex closes part 0 on part 1's closer and reports one
    # enormous literal instead of two correct ones.
    case("per-part delimiters",
         'static const char A[] =' + nl + 'R' + q + 'html0(alpha)html0' + q + ';' + nl +
         'static const char B[] =' + nl + 'R' + q + 'html1(beta)html1' + q + ';' + nl,
         [("raw", "html0", "alpha"), ("raw", "html1", "beta")])

    # A delimiter inside a line comment is not a delimiter.
    case("opener in a line comment",
         '// R' + q + 'html3( this is prose' + nl +
         'const char* x = ' + q + 'ok' + q + ';' + nl,
         [("ordinary", "", "ok")])

    # ...nor inside a block comment.
    case("opener in a block comment",
         '/* R' + q + 'html3( and a stray ' + q + ' too */ const char* x = '
         + q + 'ok' + q + ';',
         [("ordinary", "", "ok")])

    # ...nor inside another string literal's body.
    case("opener inside a raw body",
         'R' + q + 'outer(text R' + q + 'html3( more)outer' + q + ';',
         [("raw", "outer", 'text R' + q + 'html3( more')])

    # An escaped quote does not end an ordinary literal.
    case("escaped quote",
         'const char* s = ' + q + 'a' + bs + q + 'b' + q + ';',
         [("ordinary", "", 'a' + bs + q + 'b')])

    # A quote inside a character literal is not a string.
    case("quote in a char literal",
         "char c = '" + q + "'; const char* s = " + q + 'ok' + q + ';',
         [("ordinary", "", "ok")])

    # C++14 digit separators must not open a character literal and swallow
    # the rest of the line.
    case("digit separator",
         "int n = 1'000'000; const char* s = " + q + 'ok' + q + ';',
         [("ordinary", "", "ok")])

    # Encoding prefixes.
    case("prefixes",
         'auto a = u8' + q + 'p' + q + '; auto b = LR' + q + 't(r)t' + q + ';',
         [("ordinary", "", "p"), ("raw", "t", "r")])

    failures = []
    for name, src, expect in cases:
        got = [(l.kind, l.tag, l.body) for l in scan_literals(src)]
        if got != expect:
            failures.append("  %s:" % name)
            failures.append("    expected %r" % (expect,))
            failures.append("    got      %r" % (got,))

    # Escapes are counted ONCE. MSVC counts an ordinary literal's result,
    # not its source bytes -- measured: 16383 backslash-n escapes (32766
    # source bytes) compiles, 16384 does not. Counting source bytes here
    # would reject valid code.
    esc = Literal("ordinary", "", 0, 0, (bs + "n") * ORDINARY_CAP)
    if esc.counted != ORDINARY_CAP:
        failures.append("  escape counting: expected %d, got %d"
                        % (ORDINARY_CAP, esc.counted))
    if esc.counted > esc.cap:
        failures.append("  escape counting: a valid literal was reported over cap")
    # \x41 -> 1 byte, \101 -> 1 byte, é -> 2 bytes of UTF-8.
    mixed = Literal("ordinary", "", 0, 0, bs + "x41" + bs + "101" + bs + "u00e9")
    if mixed.counted != 4:
        failures.append("  escape counting: hex/octal/universal got %d, expected 4"
                        % mixed.counted)

    # The two caps differ by one, and each is measured against cl 19.44.
    if (RAW_CAP, ORDINARY_CAP) != (16384, 16383):
        failures.append("  caps changed without re-measuring (see the probe script)")
    if Literal("raw", "t", 0, 0, "x" * RAW_CAP).counted > RAW_CAP:
        failures.append("  a raw literal at exactly the cap must pass")
    if Literal("raw", "t", 0, 0, "x" * (RAW_CAP + 1)).counted <= RAW_CAP:
        failures.append("  a raw literal one byte over the cap must fail")
    if Literal("ordinary", "", 0, 0, "x" * ORDINARY_CAP).counted > ORDINARY_CAP:
        failures.append("  an ordinary literal at exactly the cap must pass")
    if Literal("ordinary", "", 0, 0, "x" * (ORDINARY_CAP + 1)).counted <= ORDINARY_CAP:
        failures.append("  an ordinary literal one byte over the cap must fail")

    # Adjacency: only whitespace and comments between two tokens means the
    # compiler concatenates them.
    adj = (q + 'a' + q + '  /* c */ ' + q + 'b' + q + '; '
           + q + 'c' + q + ' + ' + q + 'd' + q + ';')
    lits = scan_literals(adj)
    if len(lits) != 4:
        failures.append("  adjacency: expected 4 literals, got %d" % len(lits))
    else:
        if not between_is_blank(adj, lits[0].end, lits[1].start):
            failures.append("  adjacency: 'a' and 'b' should be adjacent")
        if between_is_blank(adj, lits[1].end, lits[2].start):
            failures.append("  adjacency: 'b' and 'c' are separated by ';'")
        if between_is_blank(adj, lits[2].end, lits[3].start):
            failures.append("  adjacency: 'c' and 'd' are separated by '+'")
        if [len(r) for r in runs_of(adj, lits)] != [2]:
            failures.append("  adjacency: expected exactly one run of 2")

    # Line endings. A CRLF source measures the same as an LF one, because
    # the compiler counts the post-phase-1 newline. Getting this wrong
    # over-reports a 16 KB HTML part by roughly its line count.
    body_lf = "a" + nl + "b" + nl + "c"
    lf_src = 'static const char T[] = R' + q + 't(' + body_lf + ')t' + q + ';'
    crlf_src = lf_src.replace(nl, chr(13) + nl)
    fd, tmp = tempfile.mkstemp(suffix=".h")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(crlf_src.encode("utf-8"))
        lits = scan_literals(read_source(tmp))
        if len(lits) != 1 or lits[0].counted != len(body_lf):
            failures.append("  CRLF: expected one %d-byte literal, got %r"
                            % (len(body_lf), [l.counted for l in lits]))
    finally:
        os.unlink(tmp)

    # The label lookup, on the real declaration shape.
    over = ('static const char PD_HTML_9[] =' + nl + 'R' + q + 'h9('
            + ("x" * (RAW_CAP + 1)) + ')h9' + q + ';')
    lits = scan_literals(over)
    if len(lits) != 1 or lits[0].counted != RAW_CAP + 1:
        failures.append("  over-cap fixture did not extract cleanly")
    elif label_for(over, lits[0]) != "PD_HTML_9":
        failures.append("  label lookup: expected PD_HTML_9, got %r"
                        % label_for(over, lits[0]))

    if failures:
        print("SELF-TEST: FAIL")
        for line in failures:
            print(line)
        return 1
    print("SELF-TEST: PASS (%d scanner cases, escape counting, both caps, "
          "CRLF normalization, adjacency, label lookup)" % len(cases))
    return 0


def main(argv):
    if "--selftest" in argv[1:]:
        return _selftest()

    paths = [p for p in (argv[1:] or ["src", "main"]) if os.path.exists(p)]
    if not paths:
        print("check_string_literal_caps: nothing to scan", file=sys.stderr)
        return 1

    all_errors, all_warnings, all_rows = [], [], []
    scanned = 0
    for path in iter_sources(paths):
        scanned += 1
        e, w, r = check_file(path)
        all_errors += e
        all_warnings += w
        all_rows += r

    print("MSVC STRING-LITERAL CAP CHECK")
    print("  scanned %d source files; raw-literal cap %d bytes, "
          "ordinary-literal cap %d bytes" % (scanned, RAW_CAP, ORDINARY_CAP))
    print()
    if all_rows:
        print("  %-34s %-26s %-9s %9s %9s"
              % ("FILE", "LITERAL", "KIND", "BYTES", "HEADROOM"))
        for path, name, kind, line, size, headroom in sorted(
                all_rows, key=lambda r: (r[0], r[3])):
            flag = "  OVER CAP" if headroom < 0 else (
                "  tight" if headroom < TIGHT_BYTES else "")
            print("  %-34s %-26s %-9s %9d %9d%s"
                  % (path, name, kind, size, headroom, flag))
        print()
        print("  (literals under %d bytes are omitted -- neither cap is "
              "reachable from there)" % REPORT_FLOOR)
        print()

    for w in all_warnings:
        print("::warning::" + w)
    for e in all_errors:
        print("::error::" + e)

    if all_errors:
        print()
        print("LITERAL CAP CHECK: FAIL")
        print("  These build fine on GCC/Clang and fail on MSVC with C2026.")
        print("  Fix by MOVING A SPLIT POINT, not by deleting content: the")
        print("  parts concatenate in order at runtime, so a boundary may fall")
        print("  at any byte. See the header comment in src/Helpers/index_html.h.")
        return 1

    print("LITERAL CAP CHECK: PASS (every literal within MSVC's caps)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
