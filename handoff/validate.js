// Usage: node validate.js <file.md> [more.md ...]
// Renders every ```mermaid block with the real mermaid library in headless Chromium,
// checks relative links resolve, and checks code fences are balanced.
// Prints one JSON object per file; exit 1 if anything fails.
const { chromium } = require('playwright');
const fs = require('fs');
const path = require('path');
const MERMAID = path.join(__dirname, '..', 'node_modules', 'mermaid', 'dist', 'mermaid.min.js');

(async () => {
  const files = process.argv.slice(2);
  const blocks = [];
  for (const f of files) {
    const text = fs.readFileSync(f, 'utf8');
    const re = /^```mermaid[^\n]*\n([\s\S]*?)^```/gm;
    let m, i = 0;
    while ((m = re.exec(text))) blocks.push({ file: f, index: i++, src: m[1] });
  }
  const browser = await chromium.launch({ executablePath: '/opt/pw-browsers/chromium-1194/chrome-linux/chrome' });
  const page = await browser.newPage();
  await page.setContent('<div id="o"></div>');
  await page.addScriptTag({ path: MERMAID });
  const mm = {};
  for (const b of blocks) {
    const r = await page.evaluate(async (src) => {
      try {
        mermaid.initialize({ startOnLoad: false });
        await mermaid.render('g' + Math.random().toString(36).slice(2), src);
        return { ok: true };
      } catch (e) { return { ok: false, error: String(e.message || e).slice(0, 300) }; }
    }, b.src);
    (mm[b.file] = mm[b.file] || []).push({ index: b.index, ...r });
  }
  await browser.close();

  let failed = false;
  for (const f of files) {
    const text = fs.readFileSync(f, 'utf8');
    const badLinks = [];
    const linkRe = /\]\(([^)\s]+)(?:\s+"[^"]*")?\)/g;
    let m;
    while ((m = linkRe.exec(text))) {
      const t = m[1];
      if (/^(https?:|mailto:|#)/.test(t)) continue;
      const p = t.split('#')[0];
      if (!p) continue;
      const abs = path.resolve(path.dirname(f), p);
      if (!fs.existsSync(abs)) badLinks.push(t);
    }
    const fences = (text.match(/^```/gm) || []).length;
    const fenceOk = fences % 2 === 0;
    const mermaid = mm[f] || [];
    const ok = fenceOk && badLinks.length === 0 && mermaid.every(x => x.ok);
    if (!ok) failed = true;
    console.log(JSON.stringify({ file: f, ok, mermaid, badLinks, fenceOk }));
  }
  process.exit(failed ? 1 : 0);
})().catch(e => { console.error(e); process.exit(2); });
