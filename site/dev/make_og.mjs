#!/usr/bin/env node
// Social preview image (1200x630 PNG) in the site's own type and colours, with counts from the built db.json.
//   node site/dev/make_og.mjs [--db build/assets/db.json] [--out site/src/og.png]
// Needs Playwright: PLAYWRIGHT_MODULE and PLAYWRIGHT_EXECUTABLE work as in check.mjs.
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath, pathToFileURL} from 'node:url';
const here=path.dirname(fileURLToPath(import.meta.url));
const args=Object.fromEntries(process.argv.slice(2).reduce((a,v,i,all)=>v.startsWith('--')?[...a,[v.slice(2),all[i+1]]]:a,[]));
const site=path.resolve(here,'..');
const dbPath=path.resolve(args.db||path.join(site,'..','build','assets','db.json'));
const out=path.resolve(args.out||path.join(site,'src','og.png'));
const db=JSON.parse(fs.readFileSync(dbPath,'utf8'));
const fmt=n=>new Intl.NumberFormat('en-US').format(n);
const font=f=>`data:font/woff2;base64,${fs.readFileSync(path.join(site,'src','assets','fonts',f)).toString('base64')}`;
const SEV=[['critical','#6e1c4a','Critical'],['high','#c03a2b','High'],['medium','#de8a25','Medium'],['low','#efc76a','Low'],['info','#94a3b9','Info'],['gas','#c4ccd9','Gas'],['unknown','#5b6680','Unknown']];
const sev=db.severity||{};
const max=Math.max(...SEV.map(([k])=>sev[k]||0),1);
const html=`<!doctype html><html><head><meta charset="utf-8"><style>
@font-face{font-family:"Martian Mono";src:url(${font('martian-mono-latin.woff2')}) format("woff2");font-weight:100 800;font-stretch:75% 112.5%}
@font-face{font-family:"Archivo";src:url(${font('archivo-latin.woff2')}) format("woff2");font-weight:100 900;font-stretch:62% 125%}
*{box-sizing:border-box;margin:0;padding:0}
html,body{width:1200px;height:630px;overflow:hidden}
body{background:#eef0f4;color:#0e1626;font-family:Archivo,sans-serif;position:relative}
.strip{display:flex;height:10px}.strip i{display:block;height:100%}
.in{padding:44px 60px 0;display:grid;grid-template-columns:1fr 360px;gap:56px}
.wm{display:flex;align-items:center;gap:14px;font-family:"Martian Mono";font-stretch:80%;font-weight:700;font-size:26px;letter-spacing:-0.02em}
.wm svg{width:34px;height:34px}
h1{margin-top:34px;font-family:"Martian Mono";font-stretch:75%;font-weight:700;font-size:58px;line-height:1.02;letter-spacing:-0.035em;max-width:15ch}
.figs{display:grid;grid-template-columns:repeat(3,auto);justify-content:start;margin-top:38px;border-top:3px solid #0e1626}
.figs div{padding:14px 30px 0 0;margin-right:30px;border-right:1px solid #d2d8e2}
.figs div:last-child{border-right:0;margin-right:0}
.figs b{display:block;font-family:"Martian Mono";font-stretch:75%;font-weight:650;font-size:46px;line-height:1;letter-spacing:-0.02em}
.figs span{display:block;white-space:nowrap;margin-top:8px;font-size:20px;color:#364257}
.card{align-self:start;margin-top:6px;background:#fbfcfe;border:1px solid #a3adbf;border-top:5px solid #0e1626;padding:20px 22px 14px}
.card h2{font-family:"Martian Mono";font-stretch:87.5%;font-size:17px;font-weight:700}
.card p.sub{color:#586378;font-size:15px;margin-top:2px}
table{width:100%;border-collapse:collapse;margin-top:12px}
td{padding:8px 0;border-top:1px solid #d2d8e2;font-size:17px;vertical-align:middle}
td.l{width:98px;white-space:nowrap}td.l i{display:inline-block;width:13px;height:13px;margin-right:9px;vertical-align:-1px}
td.b span{display:block;height:9px;background:#e3e7ee}td.b span i{display:block;height:100%}
td.n{text-align:right;font-family:"Martian Mono";font-stretch:87.5%;font-size:15px;padding-left:12px;width:80px}
.foot{position:absolute;left:0;right:0;bottom:0;height:62px;padding:0 60px;display:flex;align-items:center;justify-content:space-between;background:#0e1626;color:#eef0f4;font-family:"Martian Mono";font-stretch:87.5%;font-size:19px;font-weight:600}
.foot span:last-child{color:#c9d0de;font-weight:500}
</style></head><body>
<div class="strip">${SEV.map(([k,c])=>`<i style="background:${c};flex-grow:${sev[k]||1}"></i>`).join('')}</div>
<div class="in"><div>
<div class="wm"><svg viewBox="0 0 24 24"><rect x="1" y="14" width="3" height="9" fill="#5b6680"/><rect x="5" y="10" width="3" height="13" fill="#efc76a"/><rect x="9" y="5" width="3" height="18" fill="#c03a2b"/><rect x="13" y="8" width="3" height="15" fill="#6e1c4a"/><rect x="17" y="12" width="3" height="11" fill="#de8a25"/><rect x="21" y="16" width="2" height="7" fill="#94a3b9"/></svg>Web3 Audit Database</div>
<h1>The open database of Web3 audit findings.</h1>
<div class="figs"><div><b>${fmt(db.finding_records)}</b><span>findings</span></div><div><b>${fmt(db.audits)}</b><span>audits</span></div><div><b>${fmt(db.publishers)}</b><span>firms and platforms</span></div></div>
</div>
<div class="card"><h2>Findings by severity</h2><p class="sub">Every finding links to its original report</p><table>${SEV.map(([k,c,l])=>`<tr><td class="l"><i style="background:${c}"></i>${l}</td><td class="b"><span><i style="width:${(100*(sev[k]||0)/max).toFixed(2)}%;background:${c}"></i></span></td><td class="n">${fmt(sev[k]||0)}</td></tr>`).join('')}</table></div>
</div>
<div class="foot"><span>Search it. Download it. Give it to your AI agent.</span><span>Data as of ${db.as_of}</span></div>
</body></html>`;
const {chromium}=await import(process.env.PLAYWRIGHT_MODULE?pathToFileURL(process.env.PLAYWRIGHT_MODULE).href:'playwright');
const browser=await chromium.launch(process.env.PLAYWRIGHT_EXECUTABLE?{executablePath:process.env.PLAYWRIGHT_EXECUTABLE}:{});
try{
 const page=await browser.newPage({viewport:{width:1200,height:630},deviceScaleFactor:1});
 await page.setContent(html,{waitUntil:'load'});
 await page.evaluate(()=>document.fonts.ready);
 await page.screenshot({path:out,clip:{x:0,y:0,width:1200,height:630}});
 // Home-screen icon: the favicon mark at 180x180.
 const icon=path.join(site,'src','assets','icon-180.png');
 const svg=fs.readFileSync(path.join(site,'src','assets','mark.svg'),'utf8');
 await page.setViewportSize({width:180,height:180});
 await page.setContent(`<html><body style="margin:0;background:#15222c">${svg.replace('<svg ','<svg width="180" height="180" ')}</body></html>`);
 await page.screenshot({path:icon,clip:{x:0,y:0,width:180,height:180}});
}finally{await browser.close();}
console.log(JSON.stringify({out,bytes:fs.statSync(out).size,icon:'src/assets/icon-180.png'}));
