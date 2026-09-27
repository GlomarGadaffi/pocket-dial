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
  * a single project frame exceeds frame_ceiling without an allowlist entry;
and when the number of xTaskCreate*/createTaskPreferPsram call sites in a
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
  python3 tools/ci/task_stack_gate.py --ci-dir DIR [--table FILE] [--src-root DIR]
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

CREATE_RE = re.compile(r"\b(?:xTaskCreate(?:PinnedToCore)?|pd::createTaskPreferPsram)\s*\(")


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


def worst_chain(v, edges, frames, memo, path):
    """(bytes, [nodes]) of the deepest direct-call chain from v, plus whether a
    cycle was cut below v. Cut results are not memoised (#457 determinism)."""
    if v in memo:
        return memo[v], False
    if v in path:
        return (0, []), True
    path.add(v)
    best, cut = (0, []), False
    for w in sorted(edges.get(v, ())):
        r, c = worst_chain(w, edges, frames, memo, path)
        cut |= c
        if r[0] > best[0]:
            best = r
    path.discard(v)
    res = (frames.get(v, (0,))[0] + best[0], [v] + best[1])
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


def run(ci_dir, table_path, src_root, main_variant):
    table = json.load(open(table_path, encoding="utf-8"))
    margin = table["margin_bytes"]
    ceiling = table["frame_ceiling_bytes"]
    allow = table.get("frame_allowlist", {})
    tasks = table["tasks"]
    nodes, edges, frames = load_graph(ci_dir)
    print(f"call graph: {len(nodes)} functions, {len(frames)} frames with stack data; "
          f"margin {margin} B, frame ceiling {ceiling} B")
    rc = 0

    want = collections.Counter(t["file"] for t in tasks if t.get("counted", True))
    have = count_sites(src_root)
    for f in sorted(set(want) | set(have)):
        if want[f] != have.get(f, 0):
            rc = 1
            print(f"FAIL table: {f} has {have.get(f, 0)} task-creation site(s), "
                  f"task_stacks.json lists {want[f]}")

    memo = {}
    for t in sorted(tasks, key=lambda t: (t["name"], t["file"], t["line"])):
        # One image links one esp_main variant; the others' tasks aren't in it.
        if t["entry"] is None or (MAIN_VARIANT_RE.match(t["file"]) and t["file"] != main_variant):
            continue
        hits = find_entry(nodes, t["entry"])
        if not hits:
            rc = 1
            print(f"FAIL {t['name']}: entry '{t['entry']}' not in call graph ({t['file']}:{t['line']})")
            continue
        total, path = max((worst_chain(h, edges, frames, memo, set())[0] for h in hits),
                          key=lambda r: r[0])
        ok = total + margin <= t["bytes"]
        rc |= 0 if ok else 1
        print(f"{'ok  ' if ok else 'FAIL'} {t['name']}: {total} B + {margin} margin "
              f"{'<=' if ok else '>'} {t['bytes']} B ({t['file']}:{t['line']})")
        for x in path:
            print(f"        {frames.get(x, (0,))[0]:6d}  {pretty(nodes.get(x, x))[:100]}")

    for x in sorted(frames):
        b = frames[x][0]
        label = pretty(nodes.get(x, x))
        if b > ceiling and is_project(nodes.get(x, "")) and not any(k in label for k in allow):
            rc = 1
            print(f"FAIL frame: {b} B > {ceiling} B ceiling, no allowlist entry: {label[:100]}")
    return rc


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--ci-dir", required=True, help="directory of .ci files from -fcallgraph-info=su")
    ap.add_argument("--table", default=os.path.join(REPO, "tools", "ci", "task_stacks.json"))
    ap.add_argument("--src-root", default=REPO, help="tree whose src/ and main/ are scanned for task sites")
    ap.add_argument("--main", default="main/esp_main_eth.cpp",
                    help="the esp_main variant linked into the image the .ci files came from")
    a = ap.parse_args()
    return run(a.ci_dir, a.table, a.src_root, a.main)


if __name__ == "__main__":
    sys.exit(main())
