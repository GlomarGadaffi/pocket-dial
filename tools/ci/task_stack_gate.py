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
    match and no allowlist entry;
and when the number of task-creation sites (xTaskCreate*, including Static
and WithCaps, pd::createTaskPreferPsram, std::thread/jthread) in a
source file differs from the number of table entries for that file (a new
task that nobody budgeted fails closed). Line numbers in the table are
references only, so unrelated edits don't break the gate.

The numbers only mean something on Xtensa .ci files from the ESP build
(BigDog's gate runs it that way; GitHub CI runs the self-test only). Host
x86-64 frames differ. Static depth is an upper bound over direct calls; it
can't see indirect calls. The runtime stackHwm_* (#451) stays ground truth.

Determinism: edges are walked in sorted order, and a result computed while a
cycle was cut is never cached, so PYTHONHASHSEED can't change the report.

Usage:
  python3 tools/ci/task_stack_gate.py --ci-dir DIR [--table FILE] [--src-root DIR] [--with FEATURE ...]

DIR is walked recursively. Point it at build/esp-idf/main (the project
component's .ci files), not build/ or build/esp-idf: is_project() keys on
/src/ in a frame's location, which also matches IDF's lwip/src and
wpa_supplicant/src, and build/ holds the bootloader's .ci files too.
"""

import argparse
import collections
import json
import os
import re
import sys

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(REPO, "tests", "tools"))
from check_parser_callgraph import load_graph, pretty, is_project  # noqa: E402

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


def worst_chain(v, edges, size, memo, path, seen):
    """(bytes, [nodes]) of the deepest direct-call chain from v, plus whether a
    cycle was cut below v. Cut results are not memoised (#457 determinism)."""
    seen.add(v)
    if v in memo:
        return memo[v], False
    if v in path:
        return (0, []), True
    path.add(v)
    best, cut = (0, []), False
    for w in sorted(edges.get(v, ())):
        r, c = worst_chain(w, edges, size, memo, path, seen)
        cut |= c
        if r[0] > best[0]:
            best = r
    path.discard(v)
    res = (size[v] + best[0], [v] + best[1])
    if not cut:
        memo[v] = res
    # ponytail: uncached cut subtrees are re-walked, exponential on dense
    # cycles; if that bites, collapse SCCs first (Tarjan in T-7) and walk the DAG.
    return res, cut


def find_entry(nodes, pattern):
    """Nodes whose function name matches the table's entry regex."""
    rx = re.compile(pattern)
    return sorted(t for t in nodes if rx.search(pretty(nodes[t])))


MAIN_VARIANT_RE = re.compile(r"^main/esp_main[^/]*\.cpp$")


def run(ci_dir, table_path, src_root, main_variant, features=()):
    table = json.load(open(table_path, encoding="utf-8"))
    margin = table["margin_bytes"]
    ceiling = table["frame_ceiling_bytes"]
    allow = table.get("frame_allowlist", {})
    tasks = table["tasks"]
    nodes, edges, frames = load_graph(ci_dir)
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
        elif is_project(nodes[v]):
            size[v] = 0
            problem[v] = "project function with no frame data (partial --ci-dir?)"
        else:
            size[v] = next((b for rx, b in lib if rx.search(label)), None)
            if size[v] is None:
                size[v] = 0
                if not allowed(v):
                    problem[v] = "library callee with no frame data, no library_defaults match"
    print(f"call graph: {len(nodes)} functions, {len(frames)} frames with stack data; "
          f"margin {margin} B, frame ceiling {ceiling} B")
    rc = 0

    want = collections.Counter(t["file"] for t in tasks)
    have = count_sites(src_root)
    for f in sorted(set(want) | set(have)):
        if want[f] != have.get(f, 0):
            rc = 1
            print(f"FAIL table: {f} has {have.get(f, 0)} task-creation site(s), "
                  f"task_stacks.json lists {want[f]}")

    memo, seen = {}, set()
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
        total, path = max((worst_chain(h, edges, size, memo, set(), seen)[0] for h in hits),
                          key=lambda r: r[0])
        ok = total + margin <= t["bytes"]
        rc |= 0 if ok else 1
        print(f"{'ok  ' if ok else 'FAIL'} {t['name']}: {total} B + {margin} margin "
              f"{'<=' if ok else '>'} {t['bytes']} B ({t['file']}:{t['line']})")
        for x in path:
            print(f"        {size[x]:6d}  {pretty(nodes.get(x, x))[:100]}")

    for x in sorted(seen & set(problem)):
        rc = 1
        print(f"FAIL frame: {problem[x]}: {pretty(nodes[x])[:100]}")

    for x in sorted(frames):
        b = frames[x][0]
        label = pretty(nodes.get(x, x))
        if b > ceiling and is_project(nodes.get(x, "")) and not allowed(x):
            rc = 1
            print(f"FAIL frame: {b} B > {ceiling} B ceiling, no allowlist entry: {label[:100]}")
    return rc


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--ci-dir", required=True, help="tree of .ci files from -fcallgraph-info=su, walked recursively (build/esp-idf/main)")
    ap.add_argument("--table", default=os.path.join(REPO, "tools", "ci", "task_stacks.json"))
    ap.add_argument("--src-root", default=REPO, help="tree whose src/ and main/ are scanned for task sites")
    ap.add_argument("--main", default="main/esp_main_eth.cpp",
                    help="the esp_main variant linked into the image the .ci files came from")
    ap.add_argument("--with", dest="features", action="append", default=[],
                    help="a build feature this image has (heap_trace); repeatable")
    a = ap.parse_args()
    return run(a.ci_dir, a.table, a.src_root, a.main, tuple(a.features))


if __name__ == "__main__":
    sys.exit(main())
