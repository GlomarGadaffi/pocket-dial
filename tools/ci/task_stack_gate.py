#!/usr/bin/env python3
"""Per-task worst-case static stack depth vs configured stack size (#457).

Inputs:
  * a directory of GCC `-fcallgraph-info=su -fstack-usage` .ci files (the same
    format T-7's tests/tools/check_parser_callgraph.py parses; its load_graph()
    is reused here), and
  * tools/ci/task_stacks.json: one entry per task-creation call site in
    src/ and main/, giving the entry function, the configured stack bytes and
    a file:line reference.

Fails (exit 1) when, for any task,
  * worst static chain + margin > configured bytes, or
  * the entry function is not in the call graph (fails closed), or
  * a single project frame exceeds frame_ceiling without an allowlist entry, or
  * a reachable function has a dynamic/VLA frame without an allowlist entry, or
  * a reachable project function has no frame data (a partial --ci-dir), or
  * a reachable library callee has no frame data, no library_defaults
    match and no allowlist entry, or
  * no function in the graph is under the project root (fails closed), or
  * a cycle (recursion, direct or mutual) is reachable from a walked task and
    has no recursion_allowlist row stating a depth bound and a reason;
  * a task marked "indirect": "bounded" (a 911 path: tel_sweep, tel_ctl, sip_server)
    reaches a function that makes an indirect call no indirect_allowlist row bounds;
and when the number of task-creation sites (xTaskCreate*, including Static
and WithCaps, pd::createTaskPreferPsram, std::thread/jthread) in a
source file differs from the number of table entries for that file (a new
task that nobody budgeted fails closed). Line numbers in the table are
references only, so unrelated edits don't break the gate.

The numbers only mean something on Xtensa .ci files from the ESP build
(CI runs it in the stack-depth-gate job, which builds the esp32s3/eth image with
the call-graph flags; BigDog's gate runs it by hand; the Call-Graph Guard job runs
the self-test only). Host
x86-64 frames differ. Static depth is an upper bound over direct calls; it
can't see indirect calls, except where indirect_allowlist names the targets of a site
(see below). The runtime stackHwm_* (#451) stays ground truth.

Indirect calls: GCC names every indirect site by one placeholder node, so a site is the
function that calls it, and it puts the call's file:line:col on the edge. An edge without one is
no call through a pointer: it is the memset/memcpy libcall that zero-filling or copying an
aggregate expands to (`char b[64] = {0}`), which GCC cannot name. That is charged as a call of
memcpy and needs no row. A task row marked "indirect": "bounded" must have every such
function it reaches matched by an indirect_allowlist row {"targets": [regex over a
function name, ...], "reason": "who installs the pointer, file:line"} ([] = no
target exists in the image, the reason says why); the key is a
regex searched in the caller's demangled name. The walk of those tasks (and only those) gets an edge
from the caller to every function a target regex matches, so the heaviest target chain
is charged, and a target nothing matches, or a row no indirect caller matches, fails.
Any other task keeps the base graph and only reports its sites, charging 0 B.

Recursion: the call graph is condensed first (Tarjan, reused from T-7), so a
cycle can't be walked as a longest simple path, which is no upper bound. Every
cycle reachable from a task the image walks (a self-loop counts) fails unless
recursion_allowlist has a row whose key is a substring of one member's name,
with {"depth": N, "reason": "..."}. N is how many levels deep the recursion
can go: the most times one chain goes round the cycle, the last, partial trip
counted as a whole one. Each level is charged the heaviest simple cycle's
frames (the JSON parser's level is parseValue + parseValueInner + parseObject,
not parseArray as well), so the cycle costs N x that, once, in each chain
through it. Past 200000 search steps every member is charged instead: more,
never less. A cycle with two rows, or a row that matches two cycles, fails as
ambiguous; a depth that is not a whole number >= 1, or a blank reason, fails.
A cycle no walked task reaches is not checked. The condensed walk is still path
blind: two cycles in one chain are both charged at their bounds.

Determinism: successors are walked in sorted order and the condensed graph has
no cycles to cut, so PYTHONHASHSEED can't change the report.

Usage:
  python3 tools/ci/task_stack_gate.py --ci-dir DIR [--table FILE] [--src-root DIR] [--project-root DIR] [--with FEATURE ...]

DIR is walked recursively. build/esp-idf/main holds the project component's
.ci files and build/esp-idf every component's (a library callee compiled in
that build then has its real frame; the prebuilt libc/libgcc ones still have
none). Not build/: it also holds the bootloader's .ci files, which are not in
the app image.

Project code is what GCC compiled from <project-root>/src, /main or
/components. GCC writes each label's path as the compile line gave it:
absolute in CI, but `../src/...` (relative to <project-root>/build) on the
local gate, whose ccache rewrites paths under CCACHE_BASEDIR (~/gate/env.sh).
A relative path counts only when the file exists in the checkout; an absolute
one only under the root, so IDF's own components/ and src/ stay library.
Everything else (IDF, the toolchain's libstdc++) is a library callee, so the
frame ceiling is for ours only. The project root defaults to --src-root; pass
--project-root when the .ci files came from another checkout. A graph with no
project function at all fails closed, since "nothing of ours to cap" would pass
any frame. A callee GCC never saw defined is labelled with the location of one
of its uses, which may be in a file of ours, so a frameless node's project test
only picks the message: library_defaults rows apply to it either way.

An alias is not a missing frame: GCC emits one body for the complete- and
base-object constructor (C1/C2) and destructor (D1/D2) and reports the C1/D1
name as a node with no frame and an edge to the body. Such a node is a 0 B
pass-through, but only when it calls a C2/D2 title that has a frame; any other
frameless node is still unknown, not zero. That includes a constructor template,
whose C1I<args> title aliases its C2I<args> body the same way.

library_defaults charges a callee GCC never saw defined (prebuilt newlib, libgcc,
libstdc++, ROM): a figure per name pattern, each with its provenance in
_library_defaults_reasons. A figure is measured only where its reason says so;
the rest are estimates of the callee's frame plus the prebuilt code below it,
which this walk cannot see. Estimates are conservative, never 0 without a stated
reason, and stackHwm_* stays the ground truth.
"""

import argparse
import collections
import functools
import glob
import json
import os
import posixpath
import re
import sys

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(REPO, "tests", "tools"))
from check_parser_callgraph import find_cycles, load_graph, pretty  # noqa: E402

CREATE_RE = re.compile(r"\b(?:xTaskCreate\w*|pd::createTaskPreferPsram)\s*\("
                       r"|\bstd::j?thread\s*(?:\w+\s*)?[({]")


INDIRECT_RE = re.compile(r"^Indirect Call Placeholder$")
ALIAS_NODE_RE = re.compile(r'node:\s*\{\s*title:\s*"([^"]+)"\s*label:\s*"[^"]*"\s*shape\s*:\s*triangle')
EDGE_LABEL_RE = re.compile(r'edge:\s*\{\s*sourcename:\s*"([^"]+)"\s*targetname:\s*"([^"]+)"(?:\s*label:\s*"([^"]*)")?')


ALT_GROUP_RE = re.compile(r"\(\?:([\w:~<>]+(?:\|[\w:~<>]+)+)\)")


def alternatives(pat):
    """[(alternative, pattern with that group cut down to the alternative)] for every `(?:a|b|c)` group of
    plain names in `pat`, or [(None, pat)] when it has none. A row names several functions this way; the
    gate checks each one, so a name that is not in the image cannot hide behind its siblings."""
    groups = list(ALT_GROUP_RE.finditer(pat))
    if not groups:
        return [(None, pat)]
    return [(a, pat[:m.start()] + "(?:" + a + ")" + pat[m.end():]) for m in groups for a in m.group(1).split("|")]


def short_site(label):
    """A call position without the build machine's prefix: from the last components/, managed_components/,
    src/ or main/ directory on, else the last three path elements."""
    p = label.replace("\\", "/")
    m = re.search(r"(?:^|/)((?:managed_)?components|src|main)/(?!.*/(?:managed_)?components/)(.*)$", p)
    if m:
        return m.group(1) + "/" + m.group(2)
    return "/".join(p.split("/")[-3:])


def placeholder_edges(ci_dir, ind):
    """({function: {file:line:col, ...}}, {function, ...}, {alias title, ...}) for the edges into the
    indirect-call placeholder, and the nodes GCC marked `shape : triangle`: an `__attribute__((alias))`
    function (a declaration is an ellipse), which has no frame of its own and one edge to its target. GCC writes one edge per call and puts the call's position in its label. An edge
    without one is not a call through a pointer: it is the memset/memcpy libcall a block operation
    (`char b[64] = {0}`, `struct S s{}`) expands to, which GCC cannot name. The second set holds
    the functions with such an edge."""
    sites, block, aliases = collections.defaultdict(set), set(), set()
    for ci in sorted(glob.glob(os.path.join(ci_dir, "**", "*.ci"), recursive=True)):
        with open(ci, encoding="utf-8", errors="ignore") as f:
            txt = f.read()
        aliases.update(m.group(1) for m in ALIAS_NODE_RE.finditer(txt))
        for m in EDGE_LABEL_RE.finditer(txt):
            if m.group(2) in ind:
                if m.group(3):
                    sites[m.group(1)].add(m.group(3))
                else:
                    block.add(m.group(1))
    return sites, block, aliases


def head(label):
    """A function's name without GCC's trailing " [with T = ...]" template-argument note.
    That note names the arguments an instantiation was made with, not the function: the
    _M_run of a thread whose lambda sits in X::f carries "X::f(" in it, and is not X::f.
    A target pattern is matched against this, unless it contains "[with " itself."""
    return label.split(" [with ", 1)[0]


def count_sites(src_root):
    """{relpath: number of task-creation call sites} over src/ and main/."""
    out = {}
    for top in ("src", "main"):
        for dp, _, fns in os.walk(os.path.join(src_root, top)):
            for fn in sorted(fns):
                if not fn.endswith((".c", ".cpp", ".h", ".hpp")):
                    continue
                p = os.path.join(dp, fn)
                n = sum(1 for line in open(p, encoding="utf-8", errors="ignore")
                        if CREATE_RE.search(line.split("//")[0]) and not line.lstrip().startswith("*"))
                if n:
                    out[os.path.relpath(p, src_root).replace(os.sep, "/")] = n
    return out


PROJECT_DIRS = ("src", "main", "components")


def project_roots(root):
    """The checkout's root as given and with links resolved, as POSIX paths."""
    return tuple(sorted({posixpath.normpath(r.replace(os.sep, "/"))
                         for r in (os.path.abspath(root), os.path.realpath(root))}))


@functools.lru_cache(maxsize=None)
def _is_file(path):
    return os.path.isfile(path)


def is_project(label, roots):
    """True when a node's location is this repo's src/, main/ or components/.
    GCC writes the path the compile line gave it: absolute in CI, relative to
    the build directory (<root>/build) on the local gate (`../src/SIP/X.cpp`).
    A relative one counts only when that file is in this checkout, so a wrong
    root still fails closed; an absolute one only under the root, so IDF's own
    components/ and src/ trees stay library. Edge-only nodes have no location
    and are never project."""
    parts = re.split(r"\\+n", label)
    if len(parts) < 2:
        return False
    path = re.sub(r"(:\d+)+$", "", parts[1].replace(os.sep, "/"))
    for root in roots:
        full = posixpath.normpath(path if posixpath.isabs(path) else posixpath.join(root, "build", path))
        rel = posixpath.relpath(full, root)
        if rel.split("/")[0] in PROJECT_DIRS and (posixpath.isabs(path) or _is_file(full)):
            return True
    return False


# Itanium C1/D1, followed by the nested name's end (E) or a constructor template's arguments (I).
ALIAS_RE = re.compile(r"([CD])1(?=[EI])")


def alias_body(title, edges, frames):
    """The C2/D2 title that this C1/D1 title is an alias of, or None. Only when the
    alias calls it and it has a frame, so an unknown function never reads as 0 B.
    D0 (the deleting destructor) is a function of its own and never matches. A
    constructor template mangles as C1I<args>E<params>, not C1E<params>."""
    for m in ALIAS_RE.finditer(title):
        body = title[:m.start()] + m.group(1) + "2" + title[m.end():]
        if body in frames and body in edges.get(title, ()):
            return body
    return None


def alias_of_framed(v, aliases, edges, frames, seen=()):
    """True for an `__attribute__((alias))` node (GCC's `shape : triangle`) whose one edge goes to a
    function with a frame, or to another such alias: the target is charged, the alias is its name. Any
    other frameless node is still unknown."""
    out = edges.get(v, ())
    if v not in aliases or len(out) != 1 or v in seen:
        return False
    (w,) = tuple(out)
    return w in frames or alias_of_framed(w, aliases, edges, frames, seen + (v,))


def reachable(starts, edges):
    """Every node a direct-call chain from `starts` can reach, starts included."""
    seen, stack = set(), list(starts)
    while stack:
        v = stack.pop()
        if v not in seen:
            seen.add(v)
            stack.extend(edges.get(v, ()))
    return seen


def worst_chain(u, succ, cost, memo):
    """(bytes, [units]) of the deepest chain from unit u over the condensed graph.
    That graph has no cycle (each one is a single unit), so every result is
    memoised, and ties go to the first successor in sorted order."""
    if u not in memo:
        best = (0, [])
        for w in succ(u):
            r = worst_chain(w, succ, cost, memo)
            if r[0] > best[0]:
                best = r
        memo[u] = (cost[u] + best[0], [u] + best[1])
    return memo[u]


def heaviest_round(members, edges, size, budget=200000):
    """Bytes of the heaviest simple cycle through the strongly connected `members` (a
    self-loop is a cycle of one), or None past `budget` steps; the caller then charges
    every member, which is more but never less."""
    mem, best, steps = set(members), 0, [0]

    def walk(s, v, acc, on):
        nonlocal best
        for w in sorted(edges.get(v, ())):
            if w not in mem:
                continue
            steps[0] += 1
            if steps[0] > budget:
                raise OverflowError
            if w == s:
                best = max(best, acc)
            elif w > s and w not in on:
                on.add(w)
                walk(s, w, acc + size[w], on)
                on.discard(w)

    try:
        for s in sorted(mem):
            walk(s, s, size[s], {s})
    except OverflowError:
        return None
    return best


def valid_row(row):
    d = row.get("depth") if isinstance(row, dict) else None
    return (isinstance(d, int) and not isinstance(d, bool) and d >= 1
            and isinstance(row.get("reason"), str) and bool(row["reason"].strip()))


def find_entry(nodes, pattern):
    """Nodes whose function name matches the table's entry regex."""
    rx = re.compile(pattern)
    return sorted(t for t in nodes if rx.search(pretty(nodes[t])))


MAIN_VARIANT_RE = re.compile(r"^main/esp_main[^/]*\.cpp$")


def row_images(row):
    img = row.get("image")
    return None if img is None else ([img] if isinstance(img, str) else img)


def images_ok(row, key):
    """#1117: an "image" names esp_main files that exist; an unknown one is refused, never ignored."""
    imgs = row_images(row)
    if imgs is None:
        return True
    if not (isinstance(imgs, list) and imgs and all(isinstance(i, str) and MAIN_VARIANT_RE.match(i)
                                                    and os.path.isfile(os.path.join(REPO, i)) for i in imgs)):
        print(f"FAIL row '{key}': image {imgs!r} is not a list of existing main/esp_main*.cpp files")
        return False
    return True


def applies(row, main_variant):
    imgs = row_images(row)
    return imgs is None or main_variant in imgs


def run(ci_dir, table_path, src_root, main_variant, features=(), project_root=None):
    # #1117: a --main that names no esp_main file would skip every variant-bound row and pass.
    if not (MAIN_VARIANT_RE.match(main_variant) and os.path.isfile(os.path.join(REPO, main_variant))):
        print(f"FAIL --main {main_variant}: not a main/esp_main*.cpp file in the repo, so no variant would be gated")
        return 1
    table = json.load(open(table_path, encoding="utf-8"))
    margin = table["margin_bytes"]
    ceiling = table["frame_ceiling_bytes"]
    allow = table.get("frame_allowlist", {})
    cfg_rc = 0
    for a in table.get("sdkconfig_asserts", []):
        h = os.path.join(project_root or src_root, "build", "config", "sdkconfig.h")
        if not os.path.isfile(h):
            print(f"FAIL sdkconfig_asserts: build/config/sdkconfig.h is missing under {os.path.dirname(os.path.dirname(h))}, so '{a['reason']}' cannot be checked")
            cfg_rc = 1
            continue
        with open(h, encoding="utf-8", errors="ignore") as f:
            defined = set(re.findall(r"^#define\s+(\w+)\s+1\s*$", f.read(), re.M))
        for d in a.get("present", []):
            if d not in defined:
                print(f"FAIL sdkconfig_asserts: {d} is not defined in the build, but {a['reason']}")
                cfg_rc = 1
        for d in a.get("absent", []):
            if d in defined:
                print(f"FAIL sdkconfig_asserts: {d} is defined in the build, but {a['reason']}")
                cfg_rc = 1
    tasks = table["tasks"]
    known = table.get("known_findings", {})
    # A known_findings value is one row or a list of rows (a task whose total differs per image has one
    # row per image). A row with an "image" (an esp_main file, or a list of them) applies to those images only.
    for k, v in sorted(known.items()):
        for row in (v if isinstance(v, list) else [v]):
            if not (isinstance(row.get("max_total"), int) and row["max_total"] >= 1 and row.get("reason")
                    and isinstance(row.get("bytes"), int) and row["bytes"] >= 1):
                print(f"FAIL known_findings row '{k}': needs a whole-number max_total >= 1, the stack `bytes` it was written for, and a reason")
                return 1
            if not images_ok(row, k):
                return 1
    for k, row in sorted(table.get("indirect_allowlist", {}).items()):
        if isinstance(row, dict) and not images_ok(row, k):
            return 1
    names = {t["name"] for t in tasks}
    for k in sorted(known):
        if k not in names:
            print(f"FAIL known_findings row '{k}': no task of that name in the table (renamed or removed?)")
            return 1
    nodes, edges, frames = load_graph(ci_dir)
    roots = project_roots(project_root or src_root)

    def ours(label):
        return is_project(label, roots)

    for vs in list(edges.values()):
        for w in vs:
            nodes.setdefault(w, w)   # a callee seen only as an edge target
    lib = [(re.compile(k), b) for k, b in sorted(table.get("library_defaults", {}).items())]

    # Indirect calls (a vtable, std::function, a callback pointer). GCC names every site by one
    # shared placeholder node, so a site is its caller. A task marked "indirect": "bounded" (the
    # ones that carry a 911 path) fails when a function it reaches makes an indirect call that no
    # indirect_allowlist row bounds. A row names the targets that can be installed there; the
    # walk of those tasks gets an edge from the caller to each, so the heaviest target chain is
    # charged. Other tasks keep the base graph and report the sites, charging 0 B.
    ind = {v for v in nodes if INDIRECT_RE.search(pretty(nodes.get(v, v)))}
    # Only an edge with a call position is a call through a pointer. One without is a block operation
    # (see placeholder_edges), a call of the libc mem* leaf: charged as memcpy, needing no row.
    sites, block, aliases = placeholder_edges(ci_dir, ind)
    if block:
        nodes.setdefault("memcpy", "memcpy")
        for v in block:
            edges[v].add("memcpy")
    real = {v for v in sites if v in nodes}
    makers = sorted(real)
    bounded_edges = {v: set(ws) for v, ws in edges.items()}
    base_edges = edges      # analyse() shadows `edges` with the walk's own
    bound_of, edge_row, rc_rows = {}, {}, 0
    irows = table.get("indirect_allowlist", {})
    for k in sorted(irows):
        row = irows[k]
        if isinstance(row, dict) and not applies(row, main_variant):
            continue        # #1117: written for another image; says nothing here
        tg = row.get("targets") if isinstance(row, dict) else None
        if not (isinstance(tg, list) and all(isinstance(x, str) and x for x in tg)
                and isinstance(row.get("reason"), str) and row["reason"].strip()):
            rc_rows = 1
            print(f"FAIL indirect_allowlist row '{k}': needs a list of target patterns (empty only when the reason shows nothing can be installed) and a reason")
            continue
        try:
            by_title = k.startswith("title:")      # `title:REGEX` is searched in the .ci title, for a node whose name GCC lost
            krx = re.compile(k[6:] if by_title else k)
        except re.error as e:
            rc_rows = 1
            print(f"FAIL indirect_allowlist row '{k}': key is not a regex ({e})")
            continue
        callers = [v for v in makers if krx.search(v if by_title else pretty(nodes[v]))]
        if not callers:
            rc_rows = 1
            print(f"FAIL indirect_allowlist row '{k}': matches no function that makes an indirect call")
        hit = []
        resolved = False
        for pat in tg:
            rx = re.compile(pat)
            # The "[with ...]" note is searched only by a pattern that spells it out.
            note = "[with " in pat

            def find(r, note=note):
                return sorted(x for x in nodes if x not in ind
                              and r.search(pretty(nodes[x]) if note else head(pretty(nodes[x]))))
            found = find(rx)
            alts = alternatives(pat)
            if len(alts) > 1:
                for a, ap in alts:
                    here = find(re.compile(ap))
                    # #1117: "absent" {image: [alternative, ...]} names alternatives this image does not link.
                    # Such an alternative must still match nothing there: one that is linked is a stale entry.
                    gone = a in (row.get("absent") or {}).get(main_variant, ())
                    if gone and here:
                        rc_rows = 1
                        print(f"FAIL indirect_allowlist row '{k}': alternative '{a}' is listed absent on {main_variant} but matches a function there: remove it from absent")
                    elif not here and not gone:
                        rc_rows = 1
                        print(f"FAIL indirect_allowlist row '{k}': target alternative '{a}' (of '{pat}') matches no function, so it bounds nothing")
            elif not found:
                rc_rows = 1
                print(f"FAIL indirect_allowlist row '{k}': target '{pat}' matches no function, so it bounds nothing")
                # Show what the graph calls the nearest names, so the pattern can be fixed from the log.
                toks = re.findall(r"[A-Za-z_][A-Za-z0-9_]{5,}", pat)
                if toks:
                    tok = max(toks, key=len)
                    near = sorted({pretty(nodes[x])[:150] for x in nodes if x not in ind and tok in pretty(nodes[x])})
                    for n in near[:8]:
                        print(f"        near '{tok}': {n}")
            hit += found
            resolved = resolved or bool(found)
        for v in callers:
            if v in bound_of:
                rc_rows = 1
                print(f"FAIL indirect_allowlist: '{pretty(nodes[v])[:100]}' matches rows '{bound_of[v]}' and '{k}' (ambiguous)")
            if tg and not resolved:
                continue        # a row whose targets matched nothing bounds nothing
            bound_of[v] = k
            bounded_edges.setdefault(v, set()).update(hit)
            for h in hit:
                if h not in edges.get(v, ()):
                    edge_row.setdefault((v, h), k)

    def allowed(x):
        return any(k in pretty(nodes.get(x, x)) for k in allow)

    size, problem = {}, {}
    for v in nodes:
        label = pretty(nodes[v])
        if v in frames:
            size[v] = frames[v][0]
            if frames[v][1] != "static" and not allowed(v):
                problem[v] = f"{frames[v][1]} frame, no allowlist entry"
        elif alias_body(v, edges, frames) or alias_of_framed(v, aliases, edges, frames):
            size[v] = 0     # a pass-through: the walk goes on into the body, which has the frame
        else:
            # A callee GCC never saw defined carries the location of a use, which may be a
            # file of ours, so a library_defaults row is tried before the project test.
            size[v] = next((b for rx, b in lib if rx.search(label)), None)
            if size[v] is None:
                size[v] = 0
                if ours(nodes[v]):
                    problem[v] = "project function with no frame data (partial --ci-dir?)"
                elif not allowed(v):
                    problem[v] = "library callee with no frame data, no library_defaults match"
    print(f"call graph: {len(nodes)} functions, {len(frames)} frames with stack data; "
          f"margin {margin} B, frame ceiling {ceiling} B")
    rc = rc_rows | cfg_rc

    # .ci files compiled in another checkout have none of our paths in them, and
    # "nothing of ours to cap" would then pass any frame: fail closed.
    if not any(ours(nodes[x]) for x in frames):
        rc = 1
        root = os.path.abspath(project_root or src_root).replace(os.sep, "/")
        print(f"FAIL project root: no function with frame data is under {root}/src/ or {root}/main/ "
              f"(absolute, or relative to {root}/build; --project-root: the checkout the .ci "
              f"files were compiled from)")

    want = collections.Counter(t["file"] for t in tasks)
    have = count_sites(src_root)
    for f in sorted(set(want) | set(have)):
        if want[f] != have.get(f, 0):
            rc = 1
            print(f"FAIL table: {f} has {have.get(f, 0)} task-creation site(s), "
                  f"task_stacks.json lists {want[f]}")

    reached_from = {}
    walked = []     # (task row, its entry nodes) for the tasks this image walks
    for t in sorted(tasks, key=lambda t: (t["name"], t["file"], t["line"])):
        # One image links one esp_main variant; the others' tasks aren't in it.
        # "variants" names the images a row's code is linked into, when not all.
        variants = t.get("variants") or ([t["file"]] if MAIN_VARIANT_RE.match(t["file"]) else None)
        if t["entry"] is None or (variants and main_variant not in variants):
            continue
        # A site compiled only under a Kconfig overlay (heap_trace) is walked
        # only when this image has that feature; given --with, it must be found.
        if t.get("only") and t["only"] not in features:
            print(f"skip {t['name']}: only in a '{t['only']}' build ({t['file']}:{t['line']}); pass --with {t['only']}")
            continue
        hits = find_entry(nodes, t["entry"])
        if not hits:
            rc = 1
            print(f"FAIL {t['name']}: entry '{t['entry']}' not in call graph ({t['file']}:{t['line']})")
            continue
        walked.append((t, hits))

    def analyse(batch, edges, strict):
        """Recursion, cost and report for the tasks in `batch`, over the edges given."""
        # Recursion: every cycle a walked task reaches needs a row with a bound and a reason.
        reach_of = [reachable(hits, edges) for _, hits in batch]
        reach = set().union(*reach_of)
        sub = {v: {w for w in edges.get(v, ()) if w in reach} for v in sorted(reach)}
        cycles = sorted(sorted(c) for c in find_cycles(nodes, sub))
        rc = 0
        rows = table.get("recursion_allowlist", {})
        bad = {k for k in rows if not valid_row(rows[k])}
        for k in sorted(bad):
            rc = 1
            print(f"FAIL recursion_allowlist row '{k}': needs a whole-number depth >= 1 and a reason")
        unit, members, cycle_cost, cycle_label = {}, {}, {}, {}
        row_cycles = {k: 0 for k in rows}
        for c in cycles:
            rep = c[0]
            members[rep] = c
            unit.update({m: rep for m in c})
            names = sorted(pretty(nodes.get(m, m)) for m in c)
            shown = "; ".join(n[:80] for n in names[:4]) + (f"; +{len(names) - 4} more" if len(names) > 4 else "")
            by = ",".join(sorted({t["name"] for (t, _), r in zip(batch, reach_of) if any(m in r for m in c)}))
            matched = [k for k in sorted(rows) if any(k in n for n in names)]
            for k in matched:
                row_cycles[k] += 1
            depth = 1
            if not matched:
                rc = 1
                print(f"FAIL recursion: cycle of {len(c)} function(s) reachable from {by} has no "
                      f"recursion_allowlist row (a depth bound and a reason): {shown}")
                for n in names:
                    print(f"        member {n}")
            elif len(matched) > 1:
                rc = 1
                print(f"FAIL recursion: cycle of {len(c)} function(s) reachable from {by} matches "
                      f"{len(matched)} recursion_allowlist rows (ambiguous): {', '.join(repr(k) for k in matched)}")
                for n in names:
                    print(f"        member {n}")
            elif matched[0] not in bad:
                depth = rows[matched[0]]["depth"]
            trip = heaviest_round(c, edges, size)
            if trip is None:
                trip = sum(size[m] for m in c)      # too many cycles to list: charge every member
            cycle_cost[rep] = depth * trip
            cycle_label[rep] = f"recursion x{depth} of {trip} B, {len(c)} function(s): {names[0][:50]}"
            for m in c:
                if len(pretty(nodes.get(m, m)).strip()) <= 2:     # GCC lost the name: the title is all there is
                    print(f"        nameless member: title {m}")
            if len(matched) == 1 and matched[0] not in bad:
                print(f"ok   recursion: {len(c)} function(s), depth {depth} x {trip} B a level "
                      f"= {cycle_cost[rep]} B charged ({by}): {shown}")
        for k in sorted(row_cycles):
            if row_cycles[k] > 1:
                rc = 1
                print(f"FAIL recursion_allowlist row '{k}' matches {row_cycles[k]} cycles (ambiguous): "
                      f"a row names one cycle")

        cost = collections.ChainMap(cycle_cost, size)

        def via(u, w, members=None):
            members = members or {}
            """' (via indirect_allowlist row ...)' when the walk reached w from u only by a row's
            edge, '' for a direct call: it says which row drags a function into a chain."""
            rows = {edge_row[(s, t)] for s in members.get(u, (u,)) for t in members.get(w, (w,))
                    if t in edges.get(s, ()) and (s, t) in edge_row}
            direct = any(t in base_edges.get(s, ()) for s in members.get(u, (u,)) for t in members.get(w, (w,)))
            return "" if direct or not rows else f"  (via indirect_allowlist row '{sorted(rows)[0]}')"

        # Who reaches each function on a shortest path from a walked task's entry, for the frame failures.
        queue = collections.deque(sorted({h for _, hits in batch for h in hits}))
        seen = set(queue)
        while queue:
            a = queue.popleft()
            for b in sorted(edges.get(a, ())):
                if b not in seen:
                    seen.add(b)
                    reached_from.setdefault(b, f"{pretty(nodes.get(a, a))[:140]}{via(a, b)}")
                    queue.append(b)

        def succ(u):
            out = {unit.get(w, w) for s in members.get(u, (u,)) for w in edges.get(s, ())}
            return sorted(out - {u})

        memo = {}
        for t, hits in batch:
            total, path = max((worst_chain(unit.get(h, h), succ, cost, memo) for h in hits),
                              key=lambda r: r[0])
            ok = total + margin <= t["bytes"]
            # known_findings: a reported over-budget task that does not fail the job, so a red job means
            # something new. It holds only while the chain is no deeper than the recorded max_total; a
            # deeper chain is a new finding and fails. A ratchet: a stale row (the task fits again, the total
            # is below the cap, or the stack size differs from the row's) fails too and says what to change.
            kfs = known.get(t["name"])
            kfs = [r for r in (kfs if isinstance(kfs, list) else [kfs] if kfs else [])
                   if applies(r, main_variant) and r.get("file") in (None, t["file"])]
            if len(kfs) > 1:
                print(f"FAIL known_findings: {len(kfs)} rows for '{t['name']}' apply to {main_variant} ({t['file']}): ambiguous")
                rc |= 1
            kf = kfs[0] if len(kfs) == 1 else None      # a row for another image or site covers nothing here
            stale = []          # a known row is a ratchet: these make the job fail, whatever the total
            if kf and kf["bytes"] != t["bytes"]:
                stale.append(f"known finding was written for a {kf['bytes']} B stack, the site now has {t['bytes']} B: "
                             f"re-derive the row for the new budget")
            elif kf and ok:
                stale.append(f"known finding is stale, the task fits its {t['bytes']} B again: remove the row")
            elif kf and total < kf["max_total"]:
                stale.append(f"known finding cap {kf['max_total']} B is above the total {total} B: lower max_total to {total}")
            known_hit = bool(kf) and not ok and total <= kf["max_total"] and not stale
            rc |= 0 if ((ok and not stale) or known_hit) else 1
            # The walk cannot follow an indirect call (a vtable, std::function, a callback pointer), and
            # the placeholder is charged 0 B. A task marked "indirect": "bounded" gets the edges of its
            # indirect_allowlist rows instead and fails on a site with no row. Any other task passes
            # as a fit for the direct calls only: say how many sites it reaches and which chain
            # functions make one, never a silent 0.
            reached = reachable(hits, edges)
            # GCC names every indirect site by one shared placeholder node, so a site is its caller.
            callers = sorted(v for v in reached if v in real)
            blockops = sum(1 for v in reached if v in block)
            unbounded = [v for v in callers if v not in bound_of] if strict else []
            rc |= 1 if unbounded else 0
            label = "FAIL" if (unbounded or stale) else "ok  " if ok else "KNOWN" if known_hit else "FAIL"
            print(f"{label} {t['name']}: {total} B + {margin} margin "
                  f"{'<=' if ok else '>'} {t['bytes']} B ({t['file']}:{t['line']})")
            print(f"        block operations (unlabelled placeholder edges, charged as memcpy): {blockops} function(s) reachable")
            chain = {m for x in path for m in members.get(x, (x,))}
            on_chain = [v for v in callers if v in chain]
            if strict:
                print(f"        indirect call sites: {len(callers)} function(s) reachable make one, "
                      f"{len(callers) - len(unbounded)} bounded by an indirect_allowlist row (the heaviest target chain is charged)")
                if unbounded:
                    print(f"        FAIL {t['name']}: {len(unbounded)} reachable indirect call site(s) have no "
                          f"indirect_allowlist row, so the chain above is not an upper bound (a 911 task):")
                    parent = {h: None for h in hits}
                    queue = collections.deque(sorted(hits))
                    while queue:
                        a = queue.popleft()
                        for b in sorted(edges.get(a, ())):
                            if b not in parent:
                                parent[b] = a
                                queue.append(b)
                    # Only the entries that lead to a site with no row: for each such site, the first
                    # call on its shortest path from the entry that goes from our code into a library.
                    enter = set()
                    for v in unbounded:
                        chain = [v]
                        while parent.get(chain[-1]) is not None:
                            chain.append(parent[chain[-1]])
                        chain.reverse()
                        for a, b in zip(chain, chain[1:]):
                            if ours(nodes.get(a, "")) and not ours(nodes.get(b, "")):
                                enter.add((a, b))
                                break
                    enter = sorted(enter, key=lambda e: (pretty(nodes.get(e[0], e[0])), pretty(nodes.get(e[1], e[1]))))
                    for a, b in enter[:80]:
                        print(f"            library entered from project code: {pretty(nodes.get(a, a))[:110]} -> "
                              f"{pretty(nodes.get(b, b))[:90]}{via(a, b)}")
                    if len(enter) > 80:
                        print(f"            library entered from project code: +{len(enter) - 80} more")
                    for v in unbounded:
                        print(f"            {pretty(nodes.get(v, v))}")
                        steps = [v]
                        while parent.get(steps[-1]) is not None:
                            steps.append(parent[steps[-1]])
                        steps.reverse()
                        where = sorted(short_site(w) for w in sites[v])
                        print(f"                at: {', '.join(where[:12])}{f', +{len(where) - 12} more' if len(where) > 12 else ''}")
                        if parent.get(v) is not None:
                            print(f"                <- {pretty(nodes.get(parent[v], parent[v]))[:160]}"
                                  f"{via(parent[v], v)}")
                        # What else it calls: the evidence for finding its pointer in the source.
                        also = sorted({pretty(nodes.get(w, w))[:80] for w in edges.get(v, ())
                                       if w not in ind})
                        if also:
                            print(f"                calls: {'; '.join(also[:14])}"
                                  f"{f'; +{len(also) - 14} more' if len(also) > 14 else ''}")
                        print("                path: " + " > ".join(
                            pretty(nodes.get(x, x)).split("(")[0][-44:] for x in steps))
            else:
                print(f"        indirect call sites: {len(callers)} function(s) reachable make one, "
                      f"{len(on_chain)} of them on the worst chain; callee frames are not charged (0 B)"
                      + ("" if not on_chain else ": " + "; ".join(pretty(nodes.get(v, v)).split("(")[0][-50:] for v in on_chain[:8])))
            if known_hit:
                print(f"        known finding (<= {kf['max_total']} B, not failing the job): {kf['reason']}")
            for msg in stale:
                print(f"        FAIL {t['name']}: {msg}")
            if kf and not stale and not ok and not known_hit:
                print(f"        FAIL: deeper than the known finding's {kf['max_total']} B: a new finding")
            for i, x in enumerate(path):
                print(f"        {cost[x]:6d}  {cycle_label.get(x) or pretty(nodes.get(x, x))[:100]}"
                      f"{via(path[i - 1], x, members) if i else ''}")
        return rc, reach

    plain = [w for w in walked if w[0].get("indirect") != "bounded"]
    strict = [w for w in walked if w[0].get("indirect") == "bounded"]
    reach = set()
    for batch, ev, st in ((plain, edges, False), (strict, bounded_edges, True)):
        if batch:
            r, rr = analyse(batch, ev, st)
            rc |= r
            reach |= rr

    for x in sorted(reach & set(problem)):
        rc = 1
        print(f"FAIL frame: {problem[x]}: {pretty(nodes[x])[:100]}")
        if x in reached_from:
            print(f"        reached from: {reached_from[x]}")

    for x in sorted(frames):
        b = frames[x][0]
        label = pretty(nodes.get(x, x))
        if b > ceiling and ours(nodes.get(x, "")) and not allowed(x):
            rc = 1
            print(f"FAIL frame: {b} B > {ceiling} B ceiling, no allowlist entry: {label[:100]}")
    return rc


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--ci-dir", required=True, help="tree of .ci files from -fcallgraph-info=su, walked recursively (build/esp-idf/main)")
    ap.add_argument("--table", default=os.path.join(REPO, "tools", "ci", "task_stacks.json"))
    ap.add_argument("--src-root", default=REPO, help="tree whose src/ and main/ are scanned for task sites")
    ap.add_argument("--project-root", default=None,
                    help="the checkout the .ci files were compiled from: project code is what was "
                         "compiled from its src/ and main/ (default: --src-root)")
    ap.add_argument("--main", default="main/esp_main_eth.cpp",
                    help="the esp_main variant linked into the image the .ci files came from")
    ap.add_argument("--with", dest="features", action="append", default=[],
                    help="a build feature this image has (heap_trace); repeatable")
    a = ap.parse_args()
    return run(a.ci_dir, a.table, a.src_root, a.main, tuple(a.features), a.project_root)


if __name__ == "__main__":
    sys.exit(main())
