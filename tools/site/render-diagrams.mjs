import { chromium } from 'playwright';
import fs from 'fs';
const d = JSON.parse(fs.readFileSync(new URL('diagrams.json', import.meta.url),'utf8'));
// mermaid-config.json: "base" is the shared config, any other key is merged over it for that diagram only.
const cfg = JSON.parse(fs.readFileSync(new URL('mermaid-config.json', import.meta.url),'utf8'));
const b = await chromium.launch({ executablePath: '/opt/pw-browsers/chromium' });
const p = await b.newPage({ viewport:{width:1000,height:800} });
await p.setContent('<!doctype html><html><body></body></html>');
await p.addScriptTag({ url: 'https://cdn.jsdelivr.net/npm/mermaid@11.4.1/dist/mermaid.min.js' });
for (const [k,src] of Object.entries(d)) {
  const svg = await p.evaluate(async ([k,src,cfg]) => {
    const c = JSON.parse(JSON.stringify(cfg.base)); const o = cfg[k] || {};
    for (const kk of Object.keys(o)) c[kk] = typeof o[kk] === 'object' ? Object.assign({}, c[kk] || {}, o[kk]) : o[kk];
    mermaid.initialize(c);
    return (await mermaid.render('m_'+k, src)).svg;
  }, [k,src,cfg]);
  fs.writeFileSync(new URL(`svg/${k}.svg`, import.meta.url), svg);
  console.log(k, svg.length);
}
await b.close();
