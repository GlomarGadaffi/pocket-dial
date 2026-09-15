#!/usr/bin/env python3
"""Recursion / unbounded-frame guard for the SIP signalling parser (T-7).

Compiles the SIP translation units with GCC's -fcallgraph-info=su and
-fstack-usage, then fails if:

  * any call cycle exists among project functions (direct or mutual
    recursion), or
  * any function has a non-static (dynamic / alloca / VLA) stack frame.

Why this exists: on an RTOS the call stack is the scarce resource, and a
parser whose depth is a function of attacker-chosen input structure is a
stack-exhaustion primitive. The UNISOC T612 VoLTE RCE (CWE-674) was an SDP
a=acap decoder implemented as C recursion. pocket-dial's SDP/SIP parsers are
flat loops by design (SipMessage::checkSdp and friends); this script pins that
so it survives future edits. It complements, and does not replace, the runtime
caps in SdpLimits and the stack watchpoint / stack protector in
sdkconfig.defaults.

Usage (Linux / WSL, GCC >= 10):

    python3 tests/tools/check_parser_callgraph.py            # SIP TUs, default
    python3 tests/tools/check_parser_callgraph.py --all      # every src/ TU
    python3 tests/tools/check_parser_callgraph.py --report   # also print the
                                                             # deepest static
                                                             # chains

Exit status 0 = clean, 1 = a cycle or dynamic frame was found, 2 = a TU
failed to compile (the offending compiler output is echoed).

The graph cannot see through indirect calls (std::function, virtual
dispatch, the RequestsHandler handler table); it also ignores cycles that
live entirely inside the standard library (libstdc++'s
uniform_int_distribution::operator() is self-recursive by design and is the
only one on this code base). Project-code recursion through an indirect edge
is what the runtime caps are for.
"""

import argparse
import collections
import glob
import os
import re
import subprocess
import sys
import tempfile

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
SRC = os.path.join(REPO, "src")

# The translation units on the inbound-signalling path. --all widens this to
# every .cpp under src/ that compiles on the host.
SIP_TUS = [
    "SIP/SipMessage.cpp",
    "SIP/SipSdpMessage.cpp",
    "SIP/Sdp.cpp",
    "SIP/SdpOfferAnswer.cpp",
    "SIP/SipStatus.cpp",
    "SIP/RequestsHandler.cpp",
    "SIP/Session.cpp",
    "SIP/ParkOrbit.cpp",
    "SIP/BlfSubscriptions.cpp",
    "SIP/RegisterBeeper.cpp",
    "SIP/Registrar.cpp",
    "SIP/TransactionLayer.cpp",
    "SIP/SipClient.cpp",
    "SIP/MediaBridge.cpp",
    "Helpers/SipDigest.cpp",
]

NODE_RE = re.compile(r'node:\s*\{\s*title:\s*"([^"]+)"\s*label:\s*"([^"]*)"')
EDGE_RE = re.compile(r'edge:\s*\{\s*sourcename:\s*"([^"]+)"\s*targetname:\s*"([^"]+)"')
SU_RE = re.compile(r"(\d+) bytes \((static|dynamic|bounded)\)")


def compile_tus(tus, outdir):
    """Compile each TU with call-graph + stack-usage output. Returns failures."""
    failures = []
    for tu in tus:
        name = os.path.splitext(os.path.basename(tu))[0]
        cmd = [
            "g++", "-std=c++17", "-O2", "-c",
            "-fcallgraph-info=su", "-fstack-usage",
            "-I" + os.path.join(SRC, "SIP"), "-I" + os.path.join(SRC, "Helpers"),
            os.path.join(SRC, tu), "-o", os.path.join(outdir, name + ".o"),
        ]
        r = subprocess.run(cmd, cwd=outdir, capture_output=True, text=True)
        if r.returncode != 0:
            failures.append((tu, r.stderr))
    return failures


def load_graph(outdir):
    nodes, edges, frames = {}, collections.defaultdict(set), {}
    for ci in glob.glob(os.path.join(outdir, "*.ci")):
        txt = open(ci, encoding="utf-8", errors="ignore").read()
        for m in NODE_RE.finditer(txt):
            title, label = m.group(1), m.group(2)
            nodes[title] = label
            s = SU_RE.search(label)
            if s:
                frames[title] = (int(s.group(1)), s.group(2))
        for m in EDGE_RE.finditer(txt):
            edges[m.group(1)].add(m.group(2))
    return nodes, edges, frames


def pretty(label):
    return re.split(r"\\+n", label)[0]


def is_project(label):
    """A node is project code when its location line points under src/."""
    parts = re.split(r"\\+n", label)
    return len(parts) > 1 and (os.sep + "src" + os.sep in parts[1] or "/src/" in parts[1])


def find_cycles(nodes, edges):
    """Tarjan SCC; returns SCCs of size > 1 plus self-loops."""
    sys.setrecursionlimit(1_000_000)
    index, low, stack, on, sccs = {}, {}, [], set(), []
    counter = [0]

    def strong(v):
        index[v] = low[v] = counter[0]
        counter[0] += 1
        stack.append(v)
        on.add(v)
        for w in edges.get(v, ()):
            if w not in index:
                strong(w)
                low[v] = min(low[v], low[w])
            elif w in on:
                low[v] = min(low[v], index[w])
        if low[v] == index[v]:
            comp = []
            while True:
                w = stack.pop()
                on.discard(w)
                comp.append(w)
                if w == v:
                    break
            if len(comp) > 1 or v in edges.get(v, ()):
                sccs.append(comp)

    for v in list(edges):
        if v not in index:
            strong(v)
    return sccs


def deepest_chains(nodes, edges, frames, roots):
    memo = {}

    def depth(v, seen):
        if v in memo:
            return memo[v]
        if v in seen:
            return (0, [])
        best = (0, [])
        for w in edges.get(v, ()):
            d = depth(w, seen | {v})
            if d[0] > best[0]:
                best = d
        r = (frames.get(v, (0,))[0] + best[0], [v] + best[1])
        memo[v] = r
        return r

    out = []
    for want in roots:
        for t in nodes:
            if want in pretty(nodes[t]):
                out.append((want, depth(t, frozenset())))
                break
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--all", action="store_true", help="scan every src/**/*.cpp, not just the SIP path")
    ap.add_argument("--report", action="store_true", help="print frame sizes and the deepest static chains")
    args = ap.parse_args()

    tus = SIP_TUS
    if args.all:
        tus = [os.path.relpath(p, SRC) for p in glob.glob(os.path.join(SRC, "**", "*.cpp"), recursive=True)]

    with tempfile.TemporaryDirectory() as outdir:
        failures = compile_tus(tus, outdir)
        if failures:
            for tu, err in failures:
                print(f"FAILED to compile {tu}:\n{err[:2000]}")
            return 2
        nodes, edges, frames = load_graph(outdir)

    print(f"call graph: {len(nodes)} functions, {sum(len(e) for e in edges.values())} edges, "
          f"{len(frames)} frames with stack-usage data")

    rc = 0
    project_cycles = [c for c in find_cycles(nodes, edges) if any(is_project(nodes.get(x, "")) for x in c)]
    if project_cycles:
        rc = 1
        print(f"RECURSION FOUND: {len(project_cycles)} cycle(s) through project code")
        for c in project_cycles:
            print("  cycle: " + " -> ".join(pretty(nodes.get(x, x))[:90] for x in c))
    else:
        print("no recursion cycles through project code")

    dynamic = [(t, frames[t]) for t in frames if frames[t][1] != "static" and is_project(nodes[t])]
    if dynamic:
        rc = 1
        print(f"DYNAMIC STACK FRAMES: {len(dynamic)} (alloca/VLA/variable-size)")
        for t, (b, kind) in dynamic:
            print(f"  {b:6d} {kind:8s} {pretty(nodes[t])[:100]}")
    else:
        print("no dynamic stack frames in project code")

    if args.report:
        print("\nlargest project frames (host x86-64 bytes; Xtensa differs but ranks the same):")
        proj = [(t, frames[t]) for t in frames if is_project(nodes[t])]
        for t, (b, kind) in sorted(proj, key=lambda x: -x[1][0])[:12]:
            print(f"  {b:6d} {kind:8s} {pretty(nodes[t])[:100]}")
        roots = ["RequestsHandler::handle(", "SipMessage::checkSdp", "SipMessage::filterAudioCodecs",
                 "SipSdpMessage::ensureParsed", "SipMessage::getSdpDirection",
                 "sdp::parse(", "sdp::buildAnswer(", "sdp::validateAnswer("]
        print("\ndeepest static call chains from the parser entry points:")
        for want, (total, path) in deepest_chains(nodes, edges, frames, roots):
            print(f"  {want}: {total} bytes over {len(path)} frames")
            for x in path[:10]:
                print(f"      {frames.get(x, (0,))[0]:6d}  {pretty(nodes[x])[:96]}")

    return rc


if __name__ == "__main__":
    sys.exit(main())
