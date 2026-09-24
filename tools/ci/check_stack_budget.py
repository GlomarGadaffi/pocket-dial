#!/usr/bin/env python3
"""CI gate: worst-case static stack depth per task vs its stack (issue #457).

    check_stack_budget.py <objdump> <SipServer.elf> [--budget tools/ci/stack_budget.json]
                          [--demangle <c++filt>]

For every task in the budget file, walks the whole ELF from the task's entry
(tools/ci/elfstack.py -- deterministic, SCC-condensed) and FAILS (exit 1) when:
  * the worst chain exceeds stack - margin;
  * a function reachable from any task has a frame over frameCeiling and is not
    on frameAllowlist (each entry needs a reason);
  * a configured root symbol does not exist in the ELF (renamed or inlined away:
    coverage must not disappear silently).
Exit 2 on unusable input. The report prints each task's worst chain, so a
regression names its path. Byte-identical output for any PYTHONHASHSEED.
"""

import argparse
import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import elfstack  # noqa: E402


def load_budget(path):
    with open(path, encoding="utf-8") as f:
        b = json.load(f)
    for k in ("frameCeiling", "defaultMargin", "tasks"):
        if k not in b:
            raise ValueError(f"budget file lacks {k!r}")
    for t in b["tasks"]:
        for k in ("name", "root", "stack"):
            if k not in t:
                raise ValueError(f"task entry lacks {k!r}: {t}")
    for a in b.get("frameAllowlist", []):
        if not a.get("symbol") or not a.get("reason"):
            raise ValueError(f"allowlist entries need a symbol AND a reason: {a}")
    return b


def make_demangler(tool):
    if not tool:
        return lambda s: s
    cache = {}

    def dm(s):
        if s not in cache:
            try:
                cache[s] = subprocess.run([tool, s], capture_output=True, text=True).stdout.strip() or s
            except OSError:
                cache[s] = s
        return cache[s]
    return dm


def run(graph, budget, demangle=lambda s: s):
    """Returns (report_lines, failures). Pure given the graph, so it is unit-tested."""
    lines, failures = [], []
    ceiling = budget["frameCeiling"]
    allow = {a["symbol"]: a["reason"] for a in budget.get("frameAllowlist", [])}
    reachable_comps = set()
    for t in budget["tasks"]:
        root = graph.resolve(t["root"])
        margin = t.get("margin", budget["defaultMargin"])
        limit = t["stack"] - margin
        if root is None:
            failures.append(f"{t['name']}: root symbol {t['root']} not found in the ELF "
                            f"(renamed or inlined away? update tools/ci/stack_budget.json)")
            lines.append(f"== {t['name']}: ROOT MISSING ({t['root']})")
            continue
        depth, chain = graph.deepest(root)
        verdict = "OK" if depth <= limit else "OVER"
        lines.append(f"== {t['name']}: {depth} B worst static chain / {t['stack']} B stack "
                     f"(limit {limit} = stack - {margin} margin) -> {verdict}")
        lines.extend(graph.format_chain(chain, demangle))
        if depth > limit:
            failures.append(f"{t['name']}: worst chain {depth} B > {limit} B "
                            f"({t['stack']} B stack - {margin} B margin)")
        reachable_comps |= graph.reachable(root)

    big = []
    for c in sorted(reachable_comps):
        for f in graph.comps[c]:
            fr = graph.frame(f)
            if fr > ceiling:
                big.append((fr, f))
    lines.append(f"== single frames over {ceiling} B reachable from the tasks above: {len(big)}")
    for fr, f in sorted(big, key=lambda x: (-x[0], x[1])):
        reason = allow.get(f)
        tag = f"allowlisted: {reason}" if reason else "NOT ALLOWLISTED"
        lines.append(f"   {fr:5d}  {demangle(f)}  [{tag}]")
        if not reason:
            failures.append(f"frame of {fr} B > {ceiling} B ceiling: {f} "
                            f"(shrink it, or allowlist it with a reason)")
    for a in sorted(allow):
        if graph.resolve(a) is None:
            lines.append(f"   note: allowlisted {a} is no longer in the ELF -- drop the entry")
    for n in budget.get("notCovered", []):
        lines.append(f"   not covered: {n}")
    return lines, failures


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("objdump")
    ap.add_argument("elf")
    ap.add_argument("--budget", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "stack_budget.json"))
    ap.add_argument("--demangle", default=None, help="c++filt for readable chains")
    a = ap.parse_args(argv)
    try:
        budget = load_budget(a.budget)
        graph = elfstack.Graph.from_elf(a.objdump, a.elf)
    except (OSError, ValueError, subprocess.CalledProcessError) as e:
        print(f"::error::stack budget check could not run: {e}")
        return 2
    lines, failures = run(graph, budget, make_demangler(a.demangle))
    print("\n".join(lines))
    if failures:
        for f in failures:
            print(f"::error::{f}")
        print(f"STACK BUDGET: FAIL ({len(failures)})")
        return 1
    print("STACK BUDGET: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
