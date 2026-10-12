import { chromium } from 'playwright';
import fs from 'fs';
const d = JSON.parse(fs.readFileSync(new URL('diagrams.json', import.meta.url),'utf8'));
const b = await chromium.launch({ executablePath: '/opt/pw-browsers/chromium' });
const p = await b.newPage({ viewport:{width:1000,height:800} });
await p.setContent('<!doctype html><html><body></body></html>');
await p.addScriptTag({ url: 'https://cdn.jsdelivr.net/npm/mermaid@11.4.1/dist/mermaid.min.js' });
await p.evaluate(() => mermaid.initialize({ startOnLoad:false, theme:'neutral', fontFamily:'ui-monospace,"SF Mono","Cascadia Code",Consolas,"Liberation Mono",monospace', fontSize:13,
  flowchart:{ useMaxWidth:true, htmlLabels:false, padding:8 }, sequence:{ useMaxWidth:true, mirrorActors:false }, themeVariables:{ fontFamily:'ui-monospace,Consolas,monospace' } }));
for (const [k,src] of Object.entries(d)) {
  const svg = await p.evaluate(async ([k,src]) => (await mermaid.render('m_'+k, src)).svg, [k,src]);
  fs.writeFileSync(new URL(`svg/${k}.svg`, import.meta.url), svg);
  console.log(k, svg.length);
}
await b.close();
