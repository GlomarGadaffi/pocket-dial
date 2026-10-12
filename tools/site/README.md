# Site diagrams

The landing page (`docs/index.html`) inlines the README's Mermaid diagrams
as pre-rendered SVG so the page stays a single file with no runtime script.

To regenerate after the README diagrams change:

```sh
# 1. edit tools/site/diagrams.json (same sources as README.md; topology and
#    learn are rendered top-to-bottom for the narrow column, and the hardware
#    subgraphs are declared ESP32-first so the S3 boards land on top)
# 2. render with headless Chromium (needs playwright + mermaid from jsdelivr)
cd tools/site && node render-diagrams.mjs
# 3. splice the SVGs into a fresh copy of the page
git checkout docs/index.html && python3 inline-diagrams.py
```
