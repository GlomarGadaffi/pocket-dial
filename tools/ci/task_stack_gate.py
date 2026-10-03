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
and when the number of task-creation sites (xTaskCreate*, including Static
and WithCaps, pd::createTaskPreferPsram, std::thread/jthread) in a
source file differs from the number of table entries for that file (a new
task that nobody budgeted fails closed). Line numbers in the table are
references only, so unrelated edits don't break the gate.

The numbers only mean something on Xtensa .ci files from the ESP build
(BigDog's gate runs it that way; GitHub CI runs the self-test only). Host
x86-64 frames differ. Static depth is an upper bound over direct calls; it
can't see indirect calls. The runtime stackHwm_* (#451) stays ground truth.

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

Project code is what GCC compiled from <project-root>/src or
<project-root>/main: it writes the absolute source path into every label.
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
frameless node is still unknown, not zero.
"""

import argparse
import collections
import json
import os
import re
import sys

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(REPO, "tests", "tools"))
from check_parser_callgraph import find_cycles, load_graph, pretty  # noqa: E402

CREATE_RE = re.compile(r"\b(?:xTaskCreate\w*|pd::createTaskPreferPsram)\s*\("
                       r"|\bstd::j?thread\s*(?:\w+\s*)?[({]")


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


def project_prefixes(root):
    """Path prefixes of this repo's own sources: <root>/src/ and <root>/main/."""
    roots = {os.path.abspath(root), os.path.realpath(root)}
    return tuple(sorted(r.replace(os.sep, "/").rstrip("/") + "/" + d + "/"
                        for r in roots for d in ("src", "main")))


def is_project(label, prefixes):
    """True when a node's location line (GCC's absolute source path) is under a
    project prefix. Edge-only nodes have no location and are never project."""
    parts = re.split(r"\\+n", label)
    return len(parts) > 1 and os.path.normpath(parts[1]).replace(os.sep, "/").startswith(prefixes)


ALIAS_RE = re.compile(r"([CD])1E")   # Itanium C1/D1 right before the nested name's end


def alias_body(title, edges, frames):
    """The C2/D2 title that this C1/D1 title is an alias of, or None. Only when the
    alias calls it and it has a frame, so an unknown function never reads as 0 B.
    D0 (the deleting destructor) is a function of its own and never matches."""
    for m in ALIAS_RE.finditer(title):
        body = title[:m.start()] + m.group(1) + "2E" + title[m.end():]
        if body in frames and body in edges.get(title, ()):
            return body
    return None


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


def run(ci_dir, table_path, src_root, main_variant, features=(), project_root=None):
    table = json.load(open(table_path, encoding="utf-8"))
    margin = table["margin_bytes"]
    ceiling = table["frame_ceiling_bytes"]
    allow = table.get("frame_allowlist", {})
    tasks = table["tasks"]
    nodes, edges, frames = load_graph(ci_dir)
    prefixes = project_prefixes(project_root or src_root)

    def ours(label):
        return is_project(label, prefixes)

    for vs in list(edges.values()):
        for w in vs:
            nodes.setdefault(w, w)   # a callee seen only as an edge target
    lib = [(re.compile(k), b) for k, b in sorted(table.get("library_defaults", {}).items())]

    def allowed(x):
        return any(k in pretty(nodes.get(x, x)) for k in allow)

    size, problem = {}, {}
    for v in nodes:
        label = pretty(nodes[v])
        if v in frames:
            size[v] = frames[v][0]
            if frames[v][1] != "static" and not allowed(v):
                problem[v] = f"{frames[v][1]} frame, no allowlist entry"
        elif alias_body(v, edges, frames):
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
    rc = 0

    # .ci files compiled in another checkout have none of our paths in them, and
    # "nothing of ours to cap" would then pass any frame: fail closed.
    if not any(ours(nodes[x]) for x in frames):
        rc = 1
        root = os.path.abspath(project_root or src_root).replace(os.sep, "/")
        print(f"FAIL project root: no function with frame data is under {root}/src/ or {root}/main/ "
              f"(--project-root: the checkout the .ci files were compiled from)")

    want = collections.Counter(t["file"] for t in tasks)
    have = count_sites(src_root)
    for f in sorted(set(want) | set(have)):
        if want[f] != have.get(f, 0):
            rc = 1
            print(f"FAIL table: {f} has {have.get(f, 0)} task-creation site(s), "
                  f"task_stacks.json lists {want[f]}")

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

    # Recursion: every cycle a walked task reaches needs a row with a bound and a reason.
    reach_of = [reachable(hits, edges) for _, hits in walked]
    reach = set().union(*reach_of)
    sub = {v: {w for w in edges.get(v, ()) if w in reach} for v in sorted(reach)}
    cycles = sorted(sorted(c) for c in find_cycles(nodes, sub))
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
        by = ",".join(sorted({t["name"] for (t, _), r in zip(walked, reach_of) if any(m in r for m in c)}))
        matched = [k for k in sorted(rows) if any(k in n for n in names)]
        for k in matched:
            row_cycles[k] += 1
        depth = 1
        if not matched:
            rc = 1
            print(f"FAIL recursion: cycle of {len(c)} function(s) reachable from {by} has no "
                  f"recursion_allowlist row (a depth bound and a reason): {shown}")
        elif len(matched) > 1:
            rc = 1
            print(f"FAIL recursion: cycle of {len(c)} function(s) reachable from {by} matches "
                  f"{len(matched)} recursion_allowlist rows (ambiguous): {', '.join(repr(k) for k in matched)}")
        elif matched[0] not in bad:
            depth = rows[matched[0]]["depth"]
        trip = heaviest_round(c, edges, size)
        if trip is None:
            trip = sum(size[m] for m in c)      # too many cycles to list: charge every member
        cycle_cost[rep] = depth * trip
        cycle_label[rep] = f"recursion x{depth} of {trip} B, {len(c)} function(s): {names[0][:50]}"
        if len(matched) == 1 and matched[0] not in bad:
            print(f"ok   recursion: {len(c)} function(s), depth {depth} x {trip} B a level "
                  f"= {cycle_cost[rep]} B charged ({by}): {shown}")
    for k in sorted(row_cycles):
        if row_cycles[k] > 1:
            rc = 1
            print(f"FAIL recursion_allowlist row '{k}' matches {row_cycles[k]} cycles (ambiguous): "
                  f"a row names one cycle")

    cost = collections.ChainMap(cycle_cost, size)

    def succ(u):
        out = {unit.get(w, w) for s in members.get(u, (u,)) for w in edges.get(s, ())}
        return sorted(out - {u})

    memo = {}
    for t, hits in walked:
        total, path = max((worst_chain(unit.get(h, h), succ, cost, memo) for h in hits),
                          key=lambda r: r[0])
        ok = total + margin <= t["bytes"]
        rc |= 0 if ok else 1
        print(f"{'ok  ' if ok else 'FAIL'} {t['name']}: {total} B + {margin} margin "
              f"{'<=' if ok else '>'} {t['bytes']} B ({t['file']}:{t['line']})")
        for x in path:
            print(f"        {cost[x]:6d}  {cycle_label.get(x) or pretty(nodes.get(x, x))[:100]}")

    for x in sorted(reach & set(problem)):
        rc = 1
        print(f"FAIL frame: {problem[x]}: {pretty(nodes[x])[:100]}")

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
