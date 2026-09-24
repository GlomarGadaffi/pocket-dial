#!/usr/bin/env python3
"""Worst-case static stack chains from an Xtensa (windowed ABI) ELF (issue #457).

Frames: the N of each function's first `entry a1, N` -- the windowed ABI
reserves a function's WHOLE frame at entry, on every call, whichever branches
run afterwards (why a 2.5 KB temporary used only on a first call costs 2.5 KB
on every call).

Edges: direct call0/4/8/12, plus ESP-IDF's -mlongcalls form `l32r aN, <lit>` +
`callx8 aN`, resolved by reading the literal word out of the image. A target
is accepted only if it is exactly a function's start address (never objdump's
nearest-symbol label). NOT followed, and counted per function: true indirect
calls (vtables, function pointers, std::function) and calls to non-start
addresses.

Deterministic by construction (#457's added requirement): strongly-connected
components (recursion) are condensed with an iterative Tarjan over sorted
edges; an SCC weighs the SUM of its members' frames (one pass -- real
recursion depth is not static, so SCCs are flagged); longest paths are then
computed on the DAG. No result is ever cached under a cycle cut, and no set
iteration order reaches the output.

Static numbers are UPPER BOUNDS over direct paths; the runtime stackHwm_* on
hardware (#451) is the ground truth.

CLI:  elfstack.py <objdump> <elf> <root> [<through> ...]
      env SKIP=<regex>: callees never descended into (terminal paths).
"""

import os
import re
import struct
import subprocess
import sys

FUNC = re.compile(r"^([0-9a-f]+) <(.+)>:$")
ENTRY = re.compile(r"\sentry\s+a1,\s*(0x[0-9a-f]+|\d+)")
CALL = re.compile(r"\scall(?:0|4|8|12)\s+([0-9a-f]+)\b")
CALLX = re.compile(r"\scallx(?:0|4|8|12)\s+a(\d+)")
L32R = re.compile(r"\sl32r\s+a(\d+),\s*([0-9a-f]+)\b")
# Any other instruction whose first operand is a register overwrites it, so
# forget what l32r put there (coarse, but only ever loses an edge).
WRITES = re.compile(r"\s(?!s32i|s16i|s8i|beq|bne|blt|bge|bltu|bgeu|bany|bnone|ball|bnall|bbc|bbs|beqz|bnez|bltz|bgez|j\b|jx|ret|retw|call|entry|l32r)[a-z0-9.]+\s+a(\d+),")

# Terminal paths the task never returns from -- excluded from "worst chain".
DEFAULT_SKIP = (r"__assert_func|abort|panic|_Unwind_|__cxa_throw|__cxa_rethrow|__throw_|"
                r"__cxa_allocate_exception|_ZSt9terminate|__cxa_call_terminate|esp_system_abort")


def elf_word_reader(elf_path):
    """word_at(addr) over the ELF's loaded PROGBITS sections (ELF32 LE)."""
    img = open(elf_path, "rb").read()
    shoff = struct.unpack_from("<I", img, 0x20)[0]
    shentsize, shnum = struct.unpack_from("<HH", img, 0x2E)
    secs = []
    for i in range(shnum):
        _n, typ, _f, addr, off, size = struct.unpack_from("<IIIIII", img, shoff + i * shentsize)
        if typ == 1 and addr:
            secs.append((addr, addr + size, off))

    def word_at(a):
        for lo, hi, off in secs:
            if lo <= a <= hi - 4:
                return struct.unpack_from("<I", img, off + a - lo)[0]
        return None
    return word_at


class Graph:
    def __init__(self, dis_lines, word_at, skip=DEFAULT_SKIP):
        skip_re = re.compile(skip) if skip else None
        self.frames, self.indirect, self.unresolved = {}, {}, {}
        calls, name_at = {}, {}
        cur, lit = None, {}
        for line in dis_lines:
            m = FUNC.match(line)
            if m:
                addr, cur = int(m.group(1), 16), m.group(2)
                name_at.setdefault(addr, cur)
                self.frames.setdefault(cur, None)
                calls.setdefault(cur, set())
                self.indirect.setdefault(cur, 0)
                self.unresolved.setdefault(cur, 0)
                lit = {}
                continue
            if cur is None:
                continue
            if self.frames[cur] is None:
                e = ENTRY.search(line)
                if e:
                    self.frames[cur] = int(e.group(1), 0)
            c = CALL.search(line)
            if c:
                calls[cur].add(int(c.group(1), 16))
                continue
            x = CALLX.search(line)
            if x:
                tgt = lit.get(x.group(1))
                if tgt is not None:
                    calls[cur].add(tgt)
                else:
                    self.indirect[cur] += 1
                continue
            lr = L32R.search(line)
            if lr:
                v = word_at(int(lr.group(2), 16))
                if v is not None:
                    lit[lr.group(1)] = v
                continue
            w = WRITES.search(line)
            if w:
                lit.pop(w.group(1), None)

        self.selfrec, self.edges = set(), {}
        for f, targets in calls.items():
            out = set()
            for a in targets:
                g = name_at.get(a)
                if g is None:
                    self.unresolved[f] += 1
                elif g == f:
                    self.selfrec.add(f)
                elif not (skip_re and skip_re.search(g)):
                    out.add(g)
            self.edges[f] = sorted(out)
        self._condense()

    @classmethod
    def from_elf(cls, objdump, elf, skip=DEFAULT_SKIP):
        p = subprocess.run([objdump, "-d", "--no-show-raw-insn", elf],
                           capture_output=True, text=True, errors="replace", check=True)
        return cls(p.stdout.splitlines(), elf_word_reader(elf), skip)

    def frame(self, f):
        return self.frames.get(f) or 0

    def _condense(self):
        edges = self.edges
        index, low, onstk, stk = {}, {}, set(), []
        self.comp_of, self.comps = {}, []
        counter = 0
        for s in sorted(self.frames):
            if s in index:
                continue
            work = [(s, 0)]
            while work:
                v, i = work.pop()
                if i == 0:
                    index[v] = low[v] = counter
                    counter += 1
                    stk.append(v)
                    onstk.add(v)
                succ = edges.get(v, [])
                pushed = False
                while i < len(succ):
                    w = succ[i]
                    i += 1
                    if w not in index:
                        work.append((v, i))
                        work.append((w, 0))
                        pushed = True
                        break
                    if w in onstk:
                        low[v] = min(low[v], index[w])
                if pushed:
                    continue
                if low[v] == index[v]:
                    members = []
                    while True:
                        w = stk.pop()
                        onstk.discard(w)
                        self.comp_of[w] = len(self.comps)
                        members.append(w)
                        if w == v:
                            break
                    self.comps.append(sorted(members))
                if work:
                    u = work[-1][0]
                    low[u] = min(low[u], low[v])
        # Tarjan emits sinks first: comp ids are a reverse topological order.
        self.weight = [sum(self.frame(m) for m in c) for c in self.comps]
        self.csucc = [sorted({self.comp_of[g] for m in c for g in edges.get(m, [])
                              if self.comp_of[g] != i})
                      for i, c in enumerate(self.comps)]
        self.down, self.nxt = [0] * len(self.comps), [None] * len(self.comps)
        for c in range(len(self.comps)):
            best, bn = 0, None
            for s in self.csucc[c]:
                if self.down[s] > best:
                    best, bn = self.down[s], s
            self.down[c], self.nxt[c] = self.weight[c] + best, bn

    # ── queries ──────────────────────────────────────────────────────────────
    def resolve(self, name):
        """Exact symbol, or None. Gates use exact mangled names so a rename is a
        loud failure, not a silently different root."""
        return name if name in self.frames else None

    def search(self, pattern):
        return sorted(f for f in self.frames if pattern in f)

    def down_chain(self, c):
        out = []
        while c is not None:
            out.append(c)
            c = self.nxt[c]
        return out

    def deepest(self, root):
        rc = self.comp_of[root]
        return self.down[rc], self.down_chain(rc)

    def reachable(self, root):
        seen, todo = set(), [self.comp_of[root]]
        while todo:
            c = todo.pop()
            if c in seen:
                continue
            seen.add(c)
            todo.extend(self.csucc[c])
        return seen

    def through(self, root, target_fn):
        """Deepest chain from root that passes through target_fn, or None."""
        rc, tc = self.comp_of[root], self.comp_of[target_fn]
        up, pred = {rc: self.weight[rc]}, {rc: None}
        for c in range(rc, -1, -1):          # topological order from rc
            if c not in up:
                continue
            for s in self.csucc[c]:
                v = up[c] + self.weight[s]
                if v > up.get(s, -1):
                    up[s], pred[s] = v, c
        if tc not in up:
            return None
        path, c = [], tc
        while c is not None:
            path.append(c)
            c = pred[c]
        return up[tc] + self.down[tc] - self.weight[tc], list(reversed(path))[:-1] + self.down_chain(tc)

    def format_chain(self, chain, demangle=lambda s: s):
        lines = []
        for c in chain:
            mem = self.comps[c]
            if len(mem) == 1:
                f = mem[0]
                notes = []
                if self.indirect.get(f):
                    notes.append(f"{self.indirect[f]} indirect")
                if self.unresolved.get(f):
                    notes.append(f"{self.unresolved[f]} unresolved")
                if f in self.selfrec:
                    notes.append("SELF-RECURSIVE")
                tail = f"  [{', '.join(notes)} not followed]" if notes else ""
                lines.append(f"   {self.frame(f):5d}  {demangle(f)}{tail}")
            else:
                names = ", ".join(demangle(m) for m in mem[:4]) + (" ..." if len(mem) > 4 else "")
                lines.append(f"   {self.weight[c]:5d}  [RECURSION: {len(mem)} functions, one pass counted] {names}")
        return lines


def main(argv):
    if len(argv) < 4:
        sys.exit(__doc__)
    objdump, elf, root_pat = argv[1], argv[2], argv[3]
    g = Graph.from_elf(objdump, elf, os.environ.get("SKIP", DEFAULT_SKIP))
    roots = g.search(root_pat)
    if not roots:
        sys.exit(f"no function matches {root_pat!r}")
    root = min(roots, key=len)
    d, ch = g.deepest(root)
    print(f"== deepest chain from {root}: {d} B static, {len(ch)} frames")
    print("\n".join(g.format_chain(ch)))
    for t in argv[4:]:
        best = None
        for tf in g.search(t):
            r = g.through(root, tf)
            if r and (best is None or r[0] > best[0]):
                best = r
        if best:
            print(f"== deepest chain through {t}: {best[0]} B static, {len(best[1])} frames")
            print("\n".join(g.format_chain(best[1])))
        else:
            print(f"== {t}: not reachable from {root} by direct calls")


if __name__ == "__main__":
    main(sys.argv)
