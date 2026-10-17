#!/usr/bin/env python3
"""Generate src/Helpers/index_html.h from the web/ sources.

    python tools/gen_index_html.py            write src/Helpers/index_html.h
    python tools/gen_index_html.py --check    exit 1 if the written file would differ (CI)

WHY
---
The dashboard is ONE page served from flash as a table of raw-string parts
(see the header's own top comment for the MSVC literal-cap reason). Editing a
page as C++ raw literals is miserable, so the page lives in web/ as ordinary
HTML, CSS and JS, and this tool inlines it into the header.

SOURCE LAYOUT (web/manifest.txt is the authority)
-------------------------------------------------
    web/index.html            the shell
    web/app.css               inlined as <style>
    web/app/NN-name.js        concatenated, in manifest order, into ONE <script>
    web/sections/NN-name.html inner markup of <section id="sec-name">

manifest.txt: one path per line, relative to web/, '#' starts a comment, blank
lines ignored. Order matters for the JS files only. Every path must exist and
every file under web/ that the shell mentions must be listed.

COMPILE-GUARDED FILES (builds that lack a feature leave its UI out of flash)
----------------------------------------------------------------------------
A line `@if NAME` or `@unless NAME` before a path applies to that one file (a dangling guard
line is an error). Several guard lines before one path stack as AND (`@if PAGING!=0` then
`@unless PROFILE_SBC`: kept only when both hold); the same macro twice is an error. Only
app/NN-name.js (not app/00-*) and sections/NN-name.html may be guarded.
  @if NAME        the file is kept when `defined(NAME)`            (a flag macro)
  @if NAME!=0     the file is kept when NAME is defined and not 0  (a 0/1 macro that is
                  always defined, e.g. POCKETDIAL_MULTICAST_PAGING; plain `defined()`
                  would keep the file on every build)
  @unless NAME    the inverse of `@if NAME`: kept when `!defined(NAME)` (a build profile
                  such as POCKETDIAL_PROFILE_SBC leaves the file out; no `!=0` form)
  @only NAME      the STRICT form: kept when `defined(NAME)` and NOTHING else, no host
                  fallback (product-profile copy such as 05-sbc never reaches the desktop
                  build; the generator's unit test preprocesses the header both ways
                  instead). Stands alone: no `!=0` form and it cannot stack.
A guarded file is emitted as its own PD_HTML part(s), never sharing a literal with
unguarded bytes or with another guarded file (so an `@if` and an `@unless` never share a
part), and both the part definition and its CGA_INDEX_HTML_PARTS entry are wrapped in
`#if <cond> || !defined(ESP_PLATFORM)`, so host builds and tests keep the whole page
(`@only` wraps in a bare `#if defined(NAME)`: host builds lose it too). The
value form also emits `#error` on ESP builds where NAME is not defined yet (the header that
defaults it was not included first), so that mistake is loud, not silent.
  * A guarded JS file is spliced into the single <script> at its manifest position.
    The unguarded JS must never name anything a guarded file defines (it would throw on
    a build without it); the unit tests check that on the real sources.
  * A guarded fragment either owns a <section> in the shell, in which case the section's
    own open and close tags go into the guarded part with it (a build without the file has
    no `#sec-name` at all, and the shell must treat a missing section as absent, never as
    an error), or has none and is inserted at `<div id="name-slot"></div>` in exactly one
    section-owning fragment that is unguarded or whose guard the guest's guard implies
    (every clause of the host's guard is also one of the guest's, e.g. 61-paging under
    `@if PAGING!=0` + `@unless SBC` inside 60-call-handling under `@unless SBC`), so the
    host is present whenever the guest is. The div's own tags stay with the host. The
    shell's <script src> list may omit guarded files; any it does list must be in manifest
    order.
  * `__PD_CSRF__` must stay in an unguarded part (never behind `@if`, `@unless` or `@only`).

How the shell is inlined (all relative URLs; nothing external):
  * <link rel="stylesheet" href="app.css">     -> <style>...</style> at that spot
  * <script src="app/NN-name.js"></script>     -> the first one becomes the single
    <script> holding every manifest JS file in manifest order; the rest are
    dropped. The shell's script list must equal the manifest's JS list, in the
    same order, or the tool fails (so the two cannot drift).
  * <section id="sec-name" ...></section>      -> sections/NN-name.html goes inside.
    The shell's section must be empty (whitespace or an HTML comment only).
    Every section needs a fragment and every fragment needs a section.

WHAT STAYS BYTE FOR BYTE
------------------------
From the existing header, this tool keeps verbatim:
  1. the top comment block through `struct HtmlPart {...};`
  2. everything from the `// Issue #159 (SMTP client)` comment above PD_HTML_8
     through the end of `)html9";` (the two standalone setup pages).
Everything between and after is regenerated. The SPA parts are numbered
0..7, 10, 11, ... : 8 and 9 belong to the standalone pages and are never reused,
and CGA_INDEX_HTML_PARTS lists the SPA parts only.

CONSTRAINTS ENFORCED (each one fails loudly, nothing is silently adjusted)
  * every part is <= PART_CAP (16000) bytes of content, 384 under the 16384 raw
    literal cap measured for MSVC, so tools/check_string_literal_caps.py's
    512-byte "tight" warning is the only thing that can fire;
  * parts split at a newline when possible, never inside a UTF-8 sequence and
    never inside the CSRF marker;
  * `__PD_CSRF__` occurs exactly once in the SPA, whole, inside one part;
  * no source contains `)html<digits>"` (it would end a raw literal early);
  * sources are LF (CRLF is normalised on read; a bare CR is an error), UTF-8;
  * no external URL in the shell's <link>/<script>, no @import or url(http..)
    in the CSS; no `</script` inside JS and no `</style` inside CSS.
Output is always LF.

MINIFYING (size only, nothing is renamed or reordered)
------------------------------------------------------
The generated SPA has a size budget, so each source is squeezed before it is inlined:
  * JS:   whole-line `//` comments and whole-line `/* ... */` blocks are dropped, leading
          indentation and trailing blanks are stripped, blank lines are dropped. A nested
          closing brace keeps ONE leading space so a line that is exactly `}` still means
          "end of a top-level function" (tests slice page functions up to the next
          newline-brace-newline).
          The one comment kept is `/* #167` (DashboardE911Form_test slices up to it).
  * CSS:  comments dropped, whitespace around `{ } ; ,` and `>` squeezed, strings untouched.
  * HTML: comments dropped, indentation stripped, blank lines dropped.
Text inside quotes is never rewritten. Backticks and backslash-newline in JS, and non-empty
<pre>/<textarea> in HTML, are refused (indentation stripping would change their meaning).
"""
import argparse
import itertools
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.normpath(os.path.join(HERE, ".."))
DEFAULT_WEB = os.path.join(REPO, "web")
DEFAULT_OUT = os.path.join(REPO, "src", "Helpers", "index_html.h")

PART_CAP = 16000                      # bytes of content per part (cap 16384 - 384)
MARKER = b"__PD_CSRF__"
STANDALONE_IDS = (8, 9)               # PD_HTML_8 / PD_HTML_9 are the standalone pages
STANDALONE_START = b"// Issue #159 (SMTP client)"
STANDALONE_END = b')html9";\n'

KEEP_JS_COMMENT = b"/* #167"          # pinned: tests/DashboardE911Form_test.cpp finds this after applyE911

GENERATED_NOTE = (b"// GENERATED by tools/gen_index_html.py from web/ -- do not edit by hand;\n"
                  b"// edit the web/ sources and re-run the tool (CI runs it with --check).\n")

FOOTER = (b"// One HttpServer::sendHtml() assembles these into a single std::string per\n"
          b"// request (as it already did with the old single literal) -- the parts\n"
          b"// themselves stay in flash the whole time. sizeof(PD_HTML_N)-1 drops the\n"
          b"// implicit NUL each array's initializer added, same as strlen() would but\n"
          b"// resolved at compile time.\n"
          b"static const HtmlPart CGA_INDEX_HTML_PARTS[] = {\n")


class GenError(Exception):
    pass


# ------------------------------------------------------------------ source reading
def normalize(data, what):
    """CRLF -> LF; a remaining bare CR is an error. Returns bytes."""
    data = data.replace(b"\r\n", b"\n")
    if b"\r" in data:
        raise GenError("%s: bare CR (use LF line endings)" % what)
    return data


def read_source(web, rel):
    path = os.path.join(web, *rel.split("/"))
    if not os.path.isfile(path):
        raise GenError("manifest lists %s but %s does not exist" % (rel, path))
    with open(path, "rb") as f:
        data = normalize(f.read(), rel)
    try:
        data.decode("utf-8")
    except UnicodeDecodeError as e:
        raise GenError("%s: not valid UTF-8 (%s)" % (rel, e))
    if re.search(rb'\)html[0-9]+"', data):
        raise GenError("%s: contains )html<digit>\" which would end a raw literal early" % rel)
    if b"\x00" in data:
        raise GenError("%s: contains a NUL byte" % rel)
    return data


GUARD_RE = re.compile(r"@(if|unless|only)[ \t]+([A-Za-z_][A-Za-z0-9_]*)(!=0)?$")
GUARDABLE_RE = re.compile(r"(?:app/(?!00-)[^/]+\.js|sections/[^/]+\.html)$")

# A guard clause is (MACRO, value_form, mode): mode False is `@if`, True is `@unless`, ONLY is `@only`
# (strict: no `|| !defined(ESP_PLATFORM)` fallback for the part it guards).
ONLY = "only"


def clause_word(clause):
    return "only" if clause[2] is ONLY else "unless" if clause[2] else "if"


def is_strict(guard):
    return any(c[2] is ONLY for c in guard)


def clause_cond(clause):
    name, value, unless = clause
    if unless is ONLY:
        return "defined(%s)" % name
    if unless:
        return "!defined(%s)" % name
    return "(defined(%s) && (%s) != 0)" % (name, name) if value else "defined(%s)" % name


def guard_cond(guard):
    """Preprocessor condition (without the ESP_PLATFORM escape) for a guard: a tuple of one or more
    (MACRO, value_form, unless) clauses, ANDed."""
    conds = [clause_cond(c) for c in guard]
    return conds[0] if len(conds) == 1 else "(" + " && ".join(conds) + ")"


def read_manifest_guards(web):
    """[(path, guard-or-None)] in manifest order; a guard is a tuple of (MACRO, value_form, unless)
    clauses in the order their lines appear."""
    path = os.path.join(web, "manifest.txt")
    if not os.path.isfile(path):
        raise GenError("missing %s" % path)
    with open(path, "rb") as f:
        text = normalize(f.read(), "manifest.txt").decode("utf-8")
    entries, seen, pending = [], set(), None
    for n, line in enumerate(text.split("\n"), 1):
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith("@"):
            m = GUARD_RE.match(line)
            if not m:
                raise GenError("manifest.txt:%d: expected `@if NAME`, `@if NAME!=0`, `@unless NAME` or "
                               "`@only NAME`, got %s" % (n, line))
            if m.group(1) != "if" and m.group(3):
                raise GenError("manifest.txt:%d: `@%s` takes a flag macro only (no `!=0` form): %s"
                               % (n, m.group(1), line))
            clause = (m.group(2), bool(m.group(3)), ONLY if m.group(1) == "only" else m.group(1) == "unless")
            if pending is not None and (clause[2] is ONLY or is_strict(pending)):
                raise GenError("manifest.txt:%d: `@only` stands alone; it cannot stack with another guard line: %s"
                               % (n, line))
            if pending is not None and any(c[0] == clause[0] for c in pending):
                raise GenError("manifest.txt:%d: %s is already in the guard of the next path" % (n, clause[0]))
            pending = (pending or ()) + (clause,)
            continue
        if line.startswith("/") or ".." in line.split("/") or "\\" in line:
            raise GenError("manifest.txt:%d: path must be relative with forward slashes: %s" % (n, line))
        if line in seen:
            raise GenError("manifest.txt:%d: duplicate entry %s" % (n, line))
        if pending is not None and not GUARDABLE_RE.match(line):
            raise GenError("manifest.txt:%d: `@if`/`@unless`/`@only` may guard only app/NN-name.js (not app/00-*) "
                           "or sections/NN-name.html, not %s" % (n, line))
        seen.add(line)
        entries.append((line, pending))
        pending = None
    if pending is not None:
        raise GenError("manifest.txt: `@%s %s` at the end with no path after it"
                       % (clause_word(pending[-1]), pending[-1][0]))
    return entries


def read_manifest(web):
    return [e for e, _ in read_manifest_guards(web)]


# ------------------------------------------------------------------ minifying
def min_js(data, what):
    if b"`" in data or b"\\\n" in data:
        raise GenError("%s: backtick or backslash-newline in JS (the line minifier cannot keep it intact)" % what)
    out, in_block = [], False
    for line in data.split(b"\n"):
        t = line.strip()
        if in_block:
            if b"*/" not in t:
                continue
            in_block = False
            line = t.split(b"*/", 1)[1]               # code after a block's closer survives
            if not line.strip():
                continue
        elif not t or t.startswith(b"//"):
            continue
        elif t.startswith(b"/*") and not t.startswith(KEEP_JS_COMMENT):
            if b"*/" not in t:
                in_block = True
                continue
            line = t.split(b"*/", 1)[1]
            if not line.strip():
                continue
        t = line.strip()
        out.append(b" }" if (t == b"}" and line[:1] in (b" ", b"\t")) else t)
    return b"\n".join(out) + b"\n"


CSS_STRING_RE = re.compile(rb'("(?:[^"\\]|\\.)*"|\'(?:[^\'\\]|\\.)*\')')


def min_css(data, what):
    # comments first, string-aware (a comment may hold an apostrophe)
    data = re.sub(rb'("(?:[^"\\]|\\.)*"|\'(?:[^\'\\]|\\.)*\')|/\*.*?\*/',
                  lambda m: m.group(1) or b"", data, flags=re.S)
    parts = CSS_STRING_RE.split(data)                 # even items are code, odd items are strings
    for i in range(0, len(parts), 2):
        p = re.sub(rb"\s+", b" ", parts[i])
        p = re.sub(rb"\s*([{};,>])\s*", rb"\1", p)
        p = re.sub(rb"([A-Za-z-]):\s+", rb"\1:", p)
        p = p.replace(b";}", b"}")
        parts[i] = p.replace(b"}", b"}\n")
    return b"".join(parts).strip(b" \n") + b"\n"


def min_html(data, what):
    if re.search(rb"<(?:pre|textarea)\b[^>]*>(?!\s*</)", data, re.I):
        raise GenError("%s: non-empty <pre>/<textarea> (whitespace would change)" % what)
    data = re.sub(rb"<!--.*?-->", b"", data, flags=re.S)
    lines = [l.strip() for l in data.split(b"\n")]
    return b"\n".join(l for l in lines if l) + b"\n"


# ------------------------------------------------------------------ SPA assembly
SCRIPT_SRC_RE = re.compile(rb'<script\b[^>]*\bsrc\s*=\s*"([^"]*)"[^>]*>[ \t]*</script>[ \t]*\n?')
EXTERNAL_RE = re.compile(rb'^(?:[a-zA-Z][a-zA-Z0-9+.-]*:|//)')
EMPTY_SECTION_RE = re.compile(rb'^(?:\s|<!--.*?-->)*$', re.S)
# link / script-with-src / section, matched in ONE pass over the original shell so text
# inside an inlined fragment, script or stylesheet is never re-scanned.
TAG_RE = re.compile(
    rb'(?P<link><link\b[^>]*>)'
    rb'|(?P<script><script\b[^>]*\bsrc\s*=\s*"[^"]*"[^>]*>[ \t]*</script>[ \t]*\n?)'
    rb'|(?P<sopen><section\b[^>]*\bid="sec-(?P<sname>[A-Za-z0-9-]+)"[^>]*>)(?P<sbody>.*?)(?P<sclose></section>)',
    re.S)


PH_RE = re.compile(rb"\x00PDG(\d+)\x00")


def assemble_segments(web):
    """The page as ordered [(guard-or-None, bytes)] runs; a guard is a tuple of (MACRO, value_form, unless).

    A guarded file's bytes are spliced in through NUL-delimited placeholders (NUL is refused in
    every source), so each guarded run is exactly that file's inlined bytes and the unguarded
    runs around it never contain them. Empty runs are dropped."""
    mentries = read_manifest_guards(web)
    entries = [e for e, _ in mentries]
    guards = {e: g for e, g in mentries if g is not None}
    shells = [e for e in entries if e == "index.html"]
    if len(shells) != 1:
        raise GenError("manifest.txt must list index.html exactly once")
    css = [e for e in entries if e.endswith(".css")]
    js = [e for e in entries if e.endswith(".js")]
    frags = [e for e in entries if e.startswith("sections/") and e.endswith(".html")]
    other = [e for e in entries if e not in css + js + frags + shells]
    if other:
        raise GenError("manifest.txt: do not know what to do with %s" % ", ".join(other))
    if not js:
        raise GenError("manifest.txt lists no JS")

    shell = min_html(read_source(web, "index.html"), "index.html")
    css_data = {e: min_css(read_source(web, e), e) for e in css}
    js_data = {e: min_js(read_source(web, e), e) for e in js}
    frag_data, frag_file = {}, {}
    for e in frags:
        m = re.match(r"sections/\d+-([A-Za-z0-9-]+)\.html$", e)
        if not m:
            raise GenError("%s: fragment names must look like sections/NN-name.html" % e)
        frag_data[m.group(1)] = min_html(read_source(web, e), e)
        frag_file[m.group(1)] = e

    placed = []                                   # (guard, bytes) behind each placeholder

    def placeholder(guard, body):
        placed.append((guard, body))
        return b"\x00PDG%d\x00" % (len(placed) - 1)

    # A fragment with no <section> in the shell goes into a <div id="NAME-slot"></div> of exactly one
    # section-owning fragment whose guard (none, or a subset of the guest's clauses) holds whenever the
    # guest's does; its bytes become a placeholder (guarded or not), the div tags stay with the host.
    shell_sections = {m.group("sname").decode("utf-8") for m in TAG_RE.finditer(shell) if m.group("sname")}

    def may_host(host, guest):
        return frag_file[host] not in guards or set(guards[frag_file[host]]) <= set(guards.get(frag_file[guest], ()))

    for name in [n for n in frag_data if n not in shell_sections]:
        slot = b'<div id="%s-slot"></div>' % name.encode("utf-8")
        hosts = [n for n in frag_data if n in shell_sections and may_host(n, name) and slot in frag_data[n]]
        if len(hosts) != 1 or frag_data[hosts[0]].count(slot) != 1:
            raise GenError("%s has no <section id=\"sec-%s\"> in index.html, so it needs exactly one %s in an "
                           "unguarded fragment (or one whose guard its own guard implies)"
                           % (frag_file[name], name, slot.decode("utf-8")))
        frag_data[hosts[0]] = frag_data[hosts[0]].replace(
            slot, b'<div id="%s-slot">\n' % name.encode("utf-8")
            + placeholder(guards.get(frag_file[name]), frag_data[name].strip(b"\n")) + b"\n</div>")
        del frag_data[name]

    # the shell's script include order must match the manifest's JS order; guarded files may be
    # left out of the shell (a build without them never loads them), but if listed keep the order
    srcs = []
    for m in SCRIPT_SRC_RE.finditer(shell):
        if EXTERNAL_RE.match(m.group(1)):
            raise GenError("index.html: external script %s (relative URLs only)" % m.group(1).decode("utf-8"))
        srcs.append(m.group(1).decode("utf-8"))
    expect = [e for e in js if e not in guards or e in srcs]
    if srcs != expect:
        raise GenError("index.html script includes do not match manifest.txt JS order:\n  shell:    %s\n  manifest: %s"
                       % (srcs, js))
    chunks = []
    for e in js:
        body = js_data[e]
        if re.search(rb'</script', body, re.I):
            raise GenError("%s: contains </script" % e)
        if not body.endswith(b"\n"):
            body += b"\n"
        chunks.append(placeholder(guards[e], body) if e in guards else body)
    script = b"<script>\n" + b"".join(chunks) + b"</script>\n"

    used_css, shell_names, scripts_seen = [], [], []

    def do_link(tag):
        if not re.search(rb'\brel\s*=\s*"stylesheet"', tag):
            return tag
        h = re.search(rb'\bhref\s*=\s*"([^"]*)"', tag)
        if not h:
            raise GenError("index.html: stylesheet <link> without href")
        href = h.group(1).decode("utf-8")
        if EXTERNAL_RE.match(h.group(1)):
            raise GenError("index.html: external stylesheet %s (relative URLs only)" % href)
        if href not in css_data:
            raise GenError("index.html links %s which is not in manifest.txt" % href)
        body = css_data[href]
        if re.search(rb'</style', body, re.I):
            raise GenError("%s: contains </style" % href)
        if re.search(rb'@import|url\(\s*["\']?\s*(?:[a-zA-Z][a-zA-Z0-9+.-]*:|//)', body, re.I):
            raise GenError("%s: @import or external url() (offline page: nothing external)" % href)
        used_css.append(href)
        if not body.endswith(b"\n"):
            body += b"\n"
        return b"<style>\n" + body + b"</style>"

    def do_section(m):
        name = m.group("sname").decode("utf-8")
        if name not in frag_data:
            raise GenError("index.html has <section id=\"sec-%s\"> but manifest has no sections/NN-%s.html"
                           % (name, name))
        if not EMPTY_SECTION_RE.match(m.group("sbody")):
            raise GenError("index.html: <section id=\"sec-%s\"> must be empty (the fragment goes inside)" % name)
        if name in shell_names:
            raise GenError("index.html: duplicate <section id=\"sec-%s\">" % name)
        shell_names.append(name)
        body = m.group("sopen") + b"\n" + frag_data[name].strip(b"\n") + b"\n" + m.group("sclose")
        # a guarded fragment takes its <section> tags with it: a build without it has no #sec-name
        return placeholder(guards[frag_file[name]], body) if frag_file[name] in guards else body

    def dispatch(m):
        if m.group("link") is not None:
            return do_link(m.group("link"))
        if m.group("script") is not None:
            scripts_seen.append(1)
            return script if len(scripts_seen) == 1 else b""
        return do_section(m)

    shell = TAG_RE.sub(dispatch, shell)
    unused = [c for c in css if c not in used_css]
    if unused:
        raise GenError("manifest lists %s but index.html does not link it" % ", ".join(unused))
    missing = [n for n in frag_data if n not in shell_names]
    if missing:
        raise GenError("fragments with no <section id=\"sec-NAME\"> in index.html: %s" % ", ".join(missing))

    # unfold the placeholders into ordered runs (a guest inside a guarded host nests one level)
    segments = []

    def unfold(guard, text):
        for i, piece in enumerate(PH_RE.split(text)):         # [text, id, text, id, ..., text]
            if i % 2:
                unfold(*placed[int(piece)])
            elif piece and guard is None and segments and segments[-1][0] is None:
                segments[-1] = (None, segments[-1][1] + piece)   # unguarded neighbours share a run
            elif piece:
                segments.append((guard, piece))

    unfold(None, shell)
    spa = b"".join(b for _, b in segments)

    # the CSRF marker, once, and never in a guarded run (an `@only` run least of all: the host build
    # would lose the marker with it)
    if any(g is not None and MARKER in b for g, b in segments):
        raise GenError("%s is in a guarded file; the CSRF marker must stay in an unguarded part" % MARKER.decode())
    n = spa.count(MARKER)
    if n != 1:
        raise GenError("%s must appear exactly once in the SPA, found %d" % (MARKER.decode(), n))
    if re.search(rb'\)html[0-9]+"', spa):
        raise GenError("assembled SPA contains )html<digit>\"")
    return segments


def assemble_spa(web):
    """The whole page, every guarded file included (what host builds and tests see)."""
    return b"".join(b for _, b in assemble_segments(web))


# ------------------------------------------------------------------ splitting
def split_parts(spa, cap=PART_CAP):
    if not spa:
        raise GenError("empty SPA")
    marker_spans = [(m.start(), m.end()) for m in re.finditer(re.escape(MARKER), spa)]
    parts = []
    pos = 0
    while pos < len(spa):
        if len(spa) - pos <= cap:
            parts.append(spa[pos:])
            break
        end = pos + cap                           # exclusive; spa[end] starts the next part if we cut here
        nl = spa.rfind(b"\n", pos, end)
        if nl >= pos:
            cut = nl + 1
        else:
            cut = end
            while cut > pos and (spa[cut] & 0xC0) == 0x80:   # never inside a UTF-8 sequence
                cut -= 1
        for a, b in marker_spans:                 # never inside the marker
            if a < cut < b:
                cut = a
        if cut <= pos:
            raise GenError("cannot split near byte %d without breaking a UTF-8 sequence or the marker" % pos)
        parts.append(spa[pos:cut])
        pos = cut
    return parts


def part_ids(count):
    ids = []
    for i in itertools.count():
        if i in STANDALONE_IDS:
            continue
        ids.append(i)
        if len(ids) == count:
            return ids


# ------------------------------------------------------------------ the header
def extract_regions(old):
    """Return (head, standalone) byte regions of an existing header (LF-normalised)."""
    m = re.search(rb'struct HtmlPart \{[^}]*\};[ \t]*\n', old)
    if not m:
        raise GenError("existing header: `struct HtmlPart {...};` not found")
    head = old[:m.end()]
    s = old.find(STANDALONE_START)
    if s < 0 or (s > 0 and old[s - 1:s] != b"\n"):
        raise GenError("existing header: line `%s` not found" % STANDALONE_START.decode())
    e = old.find(STANDALONE_END, s)
    if e < 0:
        raise GenError("existing header: end of PD_HTML_9 (`)html9\";`) not found")
    e += len(STANDALONE_END)
    standalone = old[s:e]
    if s < m.end():
        raise GenError("existing header: standalone region starts before `struct HtmlPart`")
    for n in STANDALONE_IDS:
        if b"static const char PD_HTML_%d[] =" % n not in standalone:
            raise GenError("existing header: PD_HTML_%d missing from the preserved standalone region" % n)
    return head, standalone


def split_segments(segments, cap=PART_CAP):
    """[(guard, bytes)] runs -> [(guard, part bytes)]. Each run is split on its own, so a part never
    holds guarded and unguarded bytes (or two guarded files) together."""
    return [(g, p) for g, body in segments for p in split_parts(body, cap)]


def wrap(guard, text):
    """Wrap a block of header text in `#if <cond> || !defined(ESP_PLATFORM)` for a guarded part; an
    `@only` guard gets the bare `#if <cond>` (no host fallback)."""
    if guard is None:
        return text
    cond = guard_cond(guard)
    if not is_strict(guard):
        cond += " || !defined(ESP_PLATFORM)"
    return b"#if %s\n" % cond.encode("ascii") + text + b"#endif\n"


def render(head, parts, standalone):
    """parts: [(guard-or-None, bytes)] in page order."""
    ids = part_ids(len(parts))
    out = [head, b"\n", GENERATED_NOTE, b"\n"]
    belted = set()
    for i, (guard, body) in zip(ids, parts):
        for name, value, _ in guard or ():
            if value and name not in belted:                                 # value form: loud, not silent
                belted.add(name)
                out.append(b"#if defined(ESP_PLATFORM) && !defined(%s)\n"
                           b"#error \"%s must be defined (include its header) before index_html.h\"\n"
                           b"#endif\n\n" % (name.encode("ascii"), name.encode("ascii")))
        text = (b"static const char PD_HTML_%d[] =\n" % i
                + b'R"html%d(' % i + body + b')html%d";\n' % i)
        out.append(wrap(guard, text) + b"\n")
    out.append(standalone)
    out.append(b"\n\n")
    out.append(FOOTER)
    for i, (guard, _) in zip(ids, parts):
        out.append(wrap(guard, b"\t{ PD_HTML_%d, sizeof(PD_HTML_%d) - 1 },\n" % (i, i)))
    out.append(b"};\n"
               b"static constexpr size_t CGA_INDEX_HTML_PART_COUNT =\n"
               b"\tsizeof(CGA_INDEX_HTML_PARTS) / sizeof(CGA_INDEX_HTML_PARTS[0]);\n"
               b"\n"
               b"#endif // INDEX_HTML_H\n")
    return b"".join(out)


def generate(web, old):
    """Return the new header bytes for web/ sources `web` and existing header bytes `old`."""
    head, standalone = extract_regions(normalize(old, "existing header"))
    segments = assemble_segments(web)
    spa = b"".join(b for _, b in segments)
    parts = split_segments(segments)
    # belt and braces: the properties the unit test also pins
    if b"".join(p for _, p in parts) != spa:
        raise GenError("internal: parts do not re-join to the SPA")
    if any(len(p) > PART_CAP for _, p in parts):
        raise GenError("internal: part over cap")
    holders = [i for i, (_, p) in enumerate(parts) if MARKER in p]
    if len(holders) != 1 or parts[holders[0]][1].count(MARKER) != 1 or parts[holders[0]][0] is not None:
        raise GenError("internal: %s straddles, repeats across parts or is guarded" % MARKER.decode())
    return render(head, parts, standalone)


# ------------------------------------------------------------------ cli
def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    ap.add_argument("--check", action="store_true",
                    help="write nothing; exit 1 if the output file would differ")
    ap.add_argument("--web", default=DEFAULT_WEB, help="source directory (default: web/)")
    ap.add_argument("--out", default=DEFAULT_OUT, help="header to read the preserved regions from and write")
    args = ap.parse_args(argv)

    try:
        with open(args.out, "rb") as f:
            old = f.read()
        new = generate(args.web, old)
    except (GenError, OSError) as e:
        sys.stderr.write("gen_index_html: %s\n" % e)
        return 2

    same = normalize(old, "existing header") == new   # a CRLF checkout of identical content is "same"
    if args.check:
        if same:
            print("gen_index_html: %s is up to date" % args.out)
            return 0
        sys.stderr.write("gen_index_html: %s is stale; run `python tools/gen_index_html.py`\n" % args.out)
        return 1
    if same:
        print("gen_index_html: %s already up to date (%d bytes)" % (args.out, len(new)))
        return 0
    with open(args.out, "wb") as f:
        f.write(new)
    print("gen_index_html: wrote %s (%d bytes)" % (args.out, len(new)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
