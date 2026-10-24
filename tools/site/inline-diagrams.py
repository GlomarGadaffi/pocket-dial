"""Splice the rendered SVGs in tools/site/svg/ into docs/index.html.

Each diagram sits in the page as <figure class="dg"><div><svg ... id="m_<key>">.
This replaces every such figure in place, by id, so it can be re-run on the
committed page. A new key in diagrams.json needs its figure placed once by hand
(copy a neighbour's <figure> and change the id); after that it is kept in step.
"""
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
S = os.path.join(HERE, 'svg')
PAGE = os.path.join(HERE, '..', '..', 'docs', 'index.html')
# Sequence and wide flowcharts keep a minimum width; the column scrolls instead.
MINW = {'callflow': 720, 'callfail': 640, 'media': 720, 'emergency': 720, 'learn': 650}


def svg(n, minw=None):
    s = open(os.path.join(S, n + '.svg'), encoding='utf-8').read()
    vb = re.search(r'viewBox="([^"]+)"', s).group(1).split()
    w = float(vb[2])
    s = re.sub(r'style="max-width: [0-9.]+px;" ', '', s, count=1)
    s = re.sub(r' width="100%"', f' width="{w:.0f}"', s, count=1)
    if minw:
        s = re.sub(r'<svg ', f'<svg style="min-width:{minw}px" ', s, count=1)
    return f'<figure class="dg"><div>{s}</div></figure>'


h = open(PAGE, encoding='utf-8', newline='').read()
missing = []
for f in sorted(os.listdir(S)):
    if not f.endswith('.svg'):
        continue
    key = f[:-4]
    pat = re.compile(r'<figure class="dg"><div><svg [^>]*id="m_' + re.escape(key) + r'".*?</svg></div></figure>', re.S)
    fig = svg(key, MINW.get(key))
    h, n = pat.subn(lambda _m: fig, h)
    if n == 1:
        print(key, 'replaced')
    else:
        print(key, f'NOT FOUND ({n} matches, need exactly 1): place its <figure> by hand first' if n == 0
              else f'AMBIGUOUS ({n} matches, need exactly 1): remove the duplicate figures')
        missing.append(key)
if missing:
    sys.exit(f'{PAGE} not written; fix: ' + ', '.join(missing))
open(PAGE, 'w', encoding='utf-8', newline='').write(h)
