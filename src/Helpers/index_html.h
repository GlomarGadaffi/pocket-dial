#ifndef INDEX_HTML_H
#define INDEX_HTML_H

#include <cstddef>

// The dashboard page's HTML+CSS+JS, as a table of independent const char[]
// parts rather than one big literal. Two separate reasons, both real:
//
//  1. MSVC (the host dev build's compiler) enforces the C++ standard's
//     documented minimum string-literal limits, and this page's combined
//     HTML+CSS+JS is past both of them: (a) each individual raw string
//     literal TOKEN is capped -- measured exactly 16384 bytes on this
//     toolset (cl 19.44); MSVC's own docs cite 16380 single-byte chars
//     before concatenation -- and (b) the TOTAL of a run of ADJACENT
//     string-literal tokens (nothing but whitespace/comments between them)
//     is separately capped at 65535 bytes. C2026 "string too big" fires on
//     whichever limit is hit first. Keep every PD_HTML_N part below ~16 KB
//     (limit (a)) or that one part alone will trip it again.
//  2. This header is also compiled into the ESP32 firmware (HttpServer.cpp
//     is linked into main/), where RAM is scarce -- see the README's
//     SIP_CONSTRAINED mode. Each PD_HTML_N[] below is a genuinely SEPARATE
//     `static const char[]` -- never concatenated, not even via `+` -- so
//     every one sits in .rodata (flash) at zero RAM cost, exactly like a
//     single literal would; limit (b) above never applies because nothing
//     here is adjacent. HttpServer::sendHtml() is the only place that ever
//     materializes the full page as one std::string (via CGA_INDEX_HTML_
//     PARTS below), same as it already did with the old single literal.
struct HtmlPart { const char* data; size_t size; };

static const char PD_HTML_0[] =
R"html0(<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Pocket-Dial Switchboard</title>
<style>
:root{
  /* patch-bay palette (design brief) */
  --void:#14100C; --face:#221B15; --face-raised:#2B231C;
  --groove-light:rgba(255,255,255,.05); --groove-dark:rgba(0,0,0,.55);
  --brass:#B08D52; --brass-bright:#D4AF6A; --brass-lo:rgba(176,141,82,.5); --brass-hi:#D4AF6A; --brass-dim:rgba(176,141,82,.28);
  --paper:#EAE1C8; --paper-dim:#A99A7B;
  --idle:#55A374; --active:#D9772E; --ringing:#E8C43D; --parked:#6C93B4; --alert:#C15C52;
  --cord-a:#9078A8; --cord-b:#7C8A4C; --cord-c:#4E8A8C;
  /* semantic aliases so the existing form/table/modal/chip rules below (unchanged
     in structure from the brass/amber theme) retint to the patch-bay palette
     without every individual rule needing to be rewritten */
  --field:var(--void); --field2:var(--void); --panel:var(--face); --panel2:var(--face);
  --ink:var(--paper); --ink-dim:var(--paper-dim);
  --line:var(--brass-dim); --line-hi:var(--brass-lo);
  --amber:var(--ringing); --amber-glow:#f0d466;
  --lamp-off:#3a332a; --green:var(--idle); --red:var(--alert);
  --bake:var(--face-raised); --bake2:var(--face-raised);
  --shadow:0 2px 4px rgba(0,0,0,.5);
  --mono:ui-monospace,"SF Mono","Cascadia Code","Consolas","Liberation Mono",monospace;
  --sans:-apple-system,BlinkMacSystemFont,"Segoe UI","Avenir Next",Roboto,sans-serif;
}
*{margin:0;padding:0;box-sizing:border-box}
html,body{background:var(--void);color:var(--paper);font-family:var(--sans);font-size:15px;-webkit-text-size-adjust:100%}
body{min-height:100vh}
a{color:var(--brass-bright)}
button{font-family:inherit;cursor:pointer}
:focus-visible{outline:2px solid var(--brass-bright);outline-offset:2px}

/* ── HEADER / RACK RAIL ── */
#rail{
  position:sticky;top:0;z-index:40;
  display:flex;flex-wrap:wrap;align-items:center;gap:1.25rem 1.75rem;
  padding:.9rem 1.5rem;
  background:var(--face);
  box-shadow:inset 0 -1px 0 var(--groove-light),0 6px 16px rgba(0,0,0,.45);
}
.wordmark{display:flex;flex-direction:column;margin-right:.25rem}
.wordmark b{font-family:var(--mono);font-size:1.05rem;letter-spacing:.02em;color:var(--paper)}
.wordmark .sub{font-size:.6rem;letter-spacing:.14em;text-transform:uppercase;color:var(--brass);margin-top:2px}
.rail-stats{display:flex;flex-wrap:wrap;gap:1.2rem;align-items:center;flex:1}
.stat{display:flex;flex-direction:column;gap:1px;line-height:1.1}
.stat .k{font-size:.6rem;letter-spacing:.1em;color:var(--paper-dim);text-transform:uppercase}
.stat .v{font-family:var(--mono);font-size:.9rem;color:var(--paper);display:flex;align-items:center;gap:.4rem}
#dot{width:8px;height:8px;border-radius:50%;background:var(--lamp-off);flex-shrink:0}
#dot.on{background:var(--idle);box-shadow:0 0 6px var(--idle)}
#dot.warn{background:var(--ringing);box-shadow:0 0 6px var(--ringing)}
.recon{display:none;color:var(--ringing);font-size:.65rem;font-family:var(--mono)}
.recon.show{display:inline}
.spark{display:flex;align-items:center;gap:.5rem}
.spark svg{display:block}
.spark polyline{fill:none;stroke:var(--brass-bright);stroke-width:1.5}

/* dual admin badge: left half = REAL web-session state, right half (separated
   by a hairline) = a static note about the unrelated DTMF phone-menu channel.
   Never blended into one sentence — see docs/patch-bay design notes. */
.admin-badge{
  display:flex;align-items:stretch;gap:0;
  border-radius:8px;border:1px solid var(--brass-dim);
  background:var(--face-raised);font-family:var(--mono);font-size:.72rem;overflow:hidden;
}
.admin-badge .seg{display:flex;align-items:center;gap:.45rem;padding:.4rem .7rem}
.admin-badge .seg.dtmf{color:var(--paper-dim);border-left:1px solid var(--brass-dim);cursor:help}
.admin-badge .dot{width:7px;height:7px;border-radius:50%;flex-shrink:0}
.admin-badge.closed .seg.session .dot{background:var(--paper-dim)}
.admin-badge.open .seg.session .dot{background:var(--idle);box-shadow:0 0 6px var(--idle)}

.header-actions{display:flex;gap:.5rem;flex-wrap:wrap}
.rbtn{
  background:var(--face-raised);border:1px solid var(--brass-lo);color:var(--paper);
  padding:.45rem .8rem;border-radius:4px;font-size:.78rem;font-family:var(--mono);
  box-shadow:inset 0 1px 0 var(--groove-light),inset 0 -2px 3px rgba(0,0,0,.4);
  transition:filter .15s;
}
.rbtn:hover{filter:brightness(1.2)}
.rbtn:active{transform:translateY(1px)}

/* ── LAYOUT ── */
main{max-width:1180px;margin:0 auto;padding:0 0 1.5rem}

/* ── PATCH BAY (carries the visual weight) ── */
.patch-bay{padding:1.75rem 1.5rem 0}
.bay-face{
  position:relative;background:var(--face);border-radius:16px;
  padding:2.25rem 1.75rem 1.75rem;
  box-shadow:inset 0 2px 0 var(--groove-light),inset 0 -4px 10px rgba(0,0,0,.5),0 12px 34px rgba(0,0,0,.4);
}
.bay-title{
  font-size:.68rem;letter-spacing:.12em;text-transform:uppercase;color:var(--brass-bright);
  margin:0 0 1.5rem;font-weight:700;display:flex;justify-content:space-between;align-items:baseline;
}
.bay-title .count{color:var(--paper-dim);font-family:var(--mono);letter-spacing:normal;text-transform:none;font-weight:400}
#cords{position:absolute;inset:0;width:100%;height:100%;pointer-events:none}
.cord{fill:none;stroke-width:3;stroke-linecap:round;opacity:.85}
.cord-a{stroke:var(--cord-a)} .cord-b{stroke:var(--cord-b)} .cord-c{stroke:var(--cord-c)}
#jacks{display:flex;flex-wrap:wrap;gap:1.6rem 1.4rem;position:relative;z-index:1}
.jack{display:flex;flex-direction:column;align-items:center;gap:.4rem;background:none;border:none;padding:.2rem;color:inherit;user-select:none}
.jack .ring{
  width:50px;height:50px;border-radius:50%;border:3px solid var(--brass);
  background:radial-gradient(circle at 35% 28%,rgba(0,0,0,.55),rgba(0,0,0,0) 60%),var(--face-raised);
  display:flex;align-items:center;justify-content:center;position:relative;transition:border-color .2s;
}
.jack .led{width:11px;height:11px;border-radius:50%;background:var(--lamp-off)}
.jack .badge-dnd{position:absolute;top:-4px;right:-4px;font-size:7px;font-family:var(--mono);letter-spacing:.5px;
  background:var(--void);color:var(--ringing);border:1px solid var(--ringing);border-radius:3px;padding:0 3px}
.jack .label{font-family:var(--mono);font-weight:600;font-size:.85rem;background:var(--face-raised);color:var(--paper);
  padding:.1rem .45rem;border-radius:2px;border:1px solid rgba(0,0,0,.4)}
.jack .sublabel{font-size:.6rem;color:var(--paper-dim);font-family:var(--mono)}
.jack.state-idle .ring{border-color:var(--idle)} .jack.state-idle .led{background:var(--idle);box-shadow:0 0 8px var(--idle)}
.jack.state-active .ring{border-color:var(--active)} .jack.state-active .led{background:var(--active);box-shadow:0 0 10px var(--active)}
.jack.state-ringing .ring{border-color:var(--ringing)} .jack.state-ringing .led{background:var(--ringing);animation:pulse 1s ease-in-out infinite}
.jack.state-parked .ring{border-color:var(--parked)} .jack.state-parked .led{background:var(--parked);box-shadow:0 0 8px var(--parked)}
.jack.state-alert .ring{border-color:var(--alert)} .jack.state-alert .led{background:var(--alert);box-shadow:0 0 8px var(--alert);animation:pulse 1.4s ease-in-out infinite}
.jack.state-unreg{opacity:.45} .jack.state-unreg .ring{border-color:#4a4136}
@keyframes pulse{0%,100%{opacity:1;transform:scale(1)}50%{opacity:.35;transform:scale(.82)}}
.legend{display:flex;flex-wrap:wrap;gap:1.1rem;margin-top:1.75rem;padding-top:.9rem;border-top:1px solid var(--brass-dim)}
.legend .item{display:flex;align-items:center;gap:.4rem;font-size:.65rem;color:var(--paper-dim);font-family:var(--mono)}
.legend .swatch{width:9px;height:9px;border-radius:50%}

/* ── RACK MODULES (flat, not elevated cards — the bay carries the weight) ── */
.rack-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:1.1rem;padding:1.25rem 1.5rem}
.module{background:var(--face);border-radius:6px;padding:1.1rem 1.3rem 1.3rem;
  box-shadow:inset 0 1px 0 var(--groove-light),inset 0 -2px 5px rgba(0,0,0,.4)}
.module.full{grid-column:1/-1}
.module>h2{font-size:.68rem;letter-spacing:.1em;text-transform:uppercase;color:var(--brass-bright);
  margin:0 0 .9rem;padding-bottom:.55rem;border-bottom:1px solid var(--brass-dim);font-weight:700;
  display:flex;align-items:center;gap:8px}
.module>h2 .badge{margin-left:auto;font-size:.68rem;color:var(--paper-dim);border:1px solid var(--line-hi);border-radius:10px;padding:1px 8px;letter-spacing:1px;text-transform:none}
.module .body{padding-top:.2rem}

/* ── TABLES ── */
table{width:100%;border-collapse:collapse;font-size:13px}
th{text-align:left;font-family:var(--mono);font-size:10px;letter-spacing:1px;text-transform:uppercase;color:var(--paper-dim);padding:6px 8px;border-bottom:1px solid var(--line)}
td{padding:6px 8px;border-bottom:1px solid rgba(176,141,82,.08);font-family:var(--mono)}
tr:last-child td{border-bottom:none}
tbody tr:hover{background:rgba(176,141,82,.06)}
.empty-row td{color:var(--ink-dim);font-family:var(--sans);text-align:center;padding:14px}
.chip{display:inline-block;font-size:10px;font-family:var(--mono);padding:1px 7px;border-radius:9px;border:1px solid;letter-spacing:.5px}
.chip.answered{color:var(--idle);border-color:var(--idle)}
.chip.busy{color:var(--ringing);border-color:var(--ringing)}
.chip.cancelled{color:var(--paper-dim);border-color:var(--line-hi)}
.chip.unavailable,.chip.failed{color:var(--alert);border-color:var(--alert)}
.chip.stub{color:var(--paper-dim);border-color:var(--line-hi)}
.chip.pending{color:var(--ringing);border-color:var(--ringing)}
.chip.live{color:var(--idle);border-color:var(--idle)}
.arrow{color:var(--brass)}

/* ── FORMS / CONTROLS ── */
.field{display:flex;flex-direction:column;gap:3px;margin-bottom:8px}
.field label{font-size:11px;color:var(--brass);letter-spacing:.5px}
input[type=text],input[type=password],input[type=file],select{
  background:var(--void);border:1px solid var(--line-hi);border-radius:4px;color:var(--ink);
  font-family:var(--mono);font-size:13px;padding:7px 9px;outline:none;width:100%;
}
input:focus,select:focus{border-color:var(--brass);box-shadow:0 0 0 2px rgba(176,141,82,.18)}
.btn{
  background:var(--face-raised);color:var(--paper);border:1px solid var(--brass-lo);border-radius:4px;
  padding:7px 14px;font-size:13px;font-family:var(--mono);box-shadow:var(--shadow);transition:filter .15s;
}
.btn:hover{filter:brightness(1.2)}
.btn:active{transform:translateY(1px)}
.btn.primary{background:linear-gradient(180deg,#7a5a1e,#5a4116);color:#fff;border-color:var(--brass)}
.btn.danger{border-color:var(--alert);color:#F0D3CE}
.btn.danger:hover{filter:brightness(1.3)}
.btn:disabled{opacity:.4;cursor:not-allowed;filter:grayscale(.6)}
.row{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
.note{font-size:11px;color:var(--ink-dim);margin:4px 0}
.msg{font-size:12px;font-family:var(--mono);min-height:16px;margin-top:4px}
.ok{color:var(--idle)}.err{color:var(--alert)}.warn{color:var(--ringing)}

.toggle{position:relative;display:inline-block;width:46px;height:24px;flex-shrink:0}
.toggle input{opacity:0;width:0;height:0}
.toggle .track{position:absolute;inset:0;background:var(--void);border:1px solid var(--line-hi);border-radius:24px;transition:.15s}
.toggle .knob{position:absolute;top:2px;left:2px;width:18px;height:18px;border-radius:50%;background:var(--ink-dim);transition:.15s}
.toggle input:checked+.track{background:rgba(232,196,61,.22);border-color:var(--ringing)}
.toggle input:checked+.track .knob{transform:translateX(22px);background:var(--ringing);box-shadow:0 0 6px var(--ringing)}

.grid2{display:grid;grid-template-columns:1fr 1fr;gap:14px}
.subhead{font-family:var(--mono);font-size:11px;letter-spacing:1px;text-transform:uppercase;color:var(--brass);margin-bottom:8px}

/* ── MODAL / PANEL OVERLAY ── */
.overlay{display:none;position:fixed;inset:0;z-index:60;background:rgba(0,0,0,.66);backdrop-filter:blur(2px);
)html0";

static const char PD_HTML_1[] =
R"html1(  align-items:flex-start;justify-content:center;padding:24px 14px;overflow:auto}
.overlay.show{display:flex}
.modal{width:100%;max-width:480px;background:var(--face);border:1px solid var(--brass-lo);border-radius:8px;box-shadow:0 10px 40px rgba(0,0,0,.7)}
.modal.wide{max-width:780px}
.modal h3{font-family:var(--mono);font-size:13px;letter-spacing:1px;color:var(--brass-hi);
  padding:11px 14px;border-bottom:1px solid var(--line);display:flex;align-items:center;gap:8px}
.modal h3 .x{margin-left:auto;cursor:pointer;color:var(--ink-dim);font-size:18px;line-height:1}
.modal h3 .x:hover{color:var(--alert)}
.modal .mbody{padding:14px;max-height:74vh;overflow:auto}
.modal h3 .badge{margin-left:8px;font-size:11px;color:var(--paper-dim);border:1px solid var(--line-hi);
  border-radius:10px;padding:1px 8px;letter-spacing:1px;text-transform:none}
.dp-rule{display:flex;align-items:center;gap:8px;padding:6px 0;border-bottom:1px solid var(--line)}
.dp-rule .pat{font-family:var(--mono);color:var(--brass-hi);min-width:104px}
.dp-rule .act{font-size:11px;color:var(--ink-dim);flex:1}
.hr{border:none;border-top:1px dashed var(--line-hi);margin:12px 0}
.danger-zone{border-top:1px dashed var(--alert);margin-top:12px;padding-top:10px}
.danger-zone .subhead{color:var(--alert)}

#jd-lamp{display:inline-block;width:12px;height:12px;border-radius:50%;background:var(--lamp-off);vertical-align:middle;margin-right:6px}
.kv{display:flex;justify-content:space-between;font-family:var(--mono);font-size:13px;padding:3px 0}
.kv .k{color:var(--paper-dim)}
.fwd-row{display:grid;grid-template-columns:78px 1fr auto;gap:8px;align-items:center;margin-bottom:7px}
.fwd-row label{font-size:11px;color:var(--brass);font-family:var(--mono)}
.did-row{display:grid;grid-template-columns:1fr 110px auto;gap:8px;align-items:center;margin-top:8px}

.wifi-net{display:flex;justify-content:space-between;align-items:center;padding:7px 9px;border:1px solid transparent;border-radius:4px;cursor:pointer}
.wifi-net:hover{background:rgba(176,141,82,.08);border-color:var(--line-hi)}
.wifi-ssid{color:var(--ink);font-family:var(--mono)}
.wifi-meta{font-size:11px;color:var(--ink-dim);font-family:var(--mono)}

#ota-prog{display:none;height:14px;border:1px solid var(--line-hi);border-radius:4px;background:var(--void);position:relative;margin:8px 0;overflow:hidden}
#ota-bar{height:100%;width:0;background:var(--brass);transition:width .15s}
#ota-pct{position:absolute;inset:0;text-align:center;font-size:10px;line-height:14px;font-family:var(--mono);color:#fff;text-shadow:0 0 3px #000}

#toast{position:fixed;left:50%;bottom:18px;transform:translateX(-50%) translateY(80px);
  background:var(--face-raised);border:1px solid var(--brass-lo);border-radius:6px;color:var(--ink);
  padding:9px 16px;font-size:13px;font-family:var(--mono);z-index:90;opacity:0;
  transition:transform .25s,opacity .25s;box-shadow:0 6px 20px rgba(0,0,0,.6);max-width:90vw}
#toast.show{transform:translateX(-50%) translateY(0);opacity:1}

.trace-screen{height:260px;overflow-y:auto;background:#08070a;border:1px solid var(--line-hi);border-radius:4px;
  padding:8px 10px;font-family:var(--mono);font-size:11px;line-height:1.5;color:var(--idle);
  white-space:pre-wrap;word-break:break-all}
.trace-screen .trc-hdr{color:var(--brass)} .trace-screen .trc-hdr.out{color:var(--ringing)}
.trace-screen .trc-empty{color:var(--ink-dim);font-family:var(--sans)}
.trace-screen .trc-pkt{margin-bottom:8px;padding-bottom:8px;border-bottom:1px dashed var(--line)}
.trace-screen .trc-pkt:last-child{border-bottom:none;margin-bottom:0}
.trace-screen .trc-cmd{color:var(--idle);opacity:.8;margin:2px 0 6px}

.term-line{display:flex;align-items:center;gap:6px;margin-top:8px;font-family:var(--mono);font-size:12px}
.term-prompt{color:var(--idle);flex-shrink:0}
.term-input{flex:1;min-width:0;background:transparent;border:none;border-bottom:1px solid var(--line-hi);
  color:var(--idle);font-family:var(--mono);font-size:12px;padding:3px 0}
.term-input:focus{outline:none;border-bottom-color:var(--ringing)}

/* interconnect test-dial */
.slot-row{display:flex;justify-content:space-between;align-items:center;gap:.75rem;padding:.5rem 0;border-bottom:1px dashed var(--brass-dim)}
.slot-row:last-child{border-bottom:none}
.test-result{font-size:.65rem;color:var(--paper-dim);font-family:var(--mono);min-width:9ch;text-align:right}

footer{padding:1rem 1.5rem 2rem;color:var(--paper-dim);font-size:.65rem;font-family:var(--mono)}

@media (max-width:720px){
  .grid2{grid-template-columns:1fr}
  .rail-stats{width:100%;justify-content:space-between}
  .fwd-row{grid-template-columns:64px 1fr}
  .fwd-row .btn{grid-column:2}
  .did-row{grid-template-columns:1fr}
  .patch-bay{padding:1.25rem .9rem 0}
  .rack-grid{padding:1rem .9rem}
}
@media (prefers-reduced-motion:reduce){
  .jack .led{animation:none!important}
  *{transition:none!important}
}
</style>
</head>
<body>

<!-- ══ HEADER / RACK RAIL ══ -->
<div id="rail">
  <div class="wordmark">
    <b>POCKET&middot;DIAL</b><span class="sub">Switchboard</span>
  </div>
  <div class="rail-stats">
    <div class="stat"><span class="k">Status</span><span class="v"><span id="dot"></span><span id="online-txt">connecting&hellip;</span><span class="recon" id="recon">&nbsp;reconnecting&hellip;</span></span></div>
    <div class="stat"><span class="k">Uptime</span><span class="v" id="s-uptime">--:--:--</span></div>
    <div class="stat"><span class="k">Address</span><span class="v" id="s-ip">0.0.0.0:5060</span></div>
    <div class="stat"><span class="k">Jacks</span><span class="v" id="s-jacks">0/32</span></div>
    <div class="stat"><span class="k">Calls</span><span class="v" id="s-calls">0</span></div>
    <div class="stat">
      <span class="k">Packets</span>
      <span class="v spark">
        <svg width="70" height="20" viewBox="0 0 70 20"><polyline id="sparkline" points=""></polyline></svg>
        <span id="s-pkts">0</span>
      </span>
    </div>
  </div>
  <!-- Two independent facts, kept visually separate on purpose: the LEFT
       segment is this browser's real web-admin session (from /api/admin/status);
       the RIGHT segment is a static note about the DTMF *PIN#code phone menu,
       which is a completely separate command channel gated from extension 1001
       — it does not open, extend, or relate to the web session at all. -->
  <div class="admin-badge closed" id="admin-badge">
    <span class="seg session"><span class="dot"></span><span id="admin-text">SESSION: LOGGED OUT</span></span>
    <span class="seg dtmf" title="Independent of this web session: dialing *PIN#code from extension 1001 runs a one-shot phone-keypad command (NTP resync, WiFi topology switch, factory reset). It never opens or extends a web login.">DTMF admin menu: 1001 · phone-only</span>
  </div>
  <div class="header-actions">
    <button class="rbtn" onclick="refreshNow()" title="Refresh (F5)">&#8635; Refresh</button>
    <button class="rbtn" onclick="openModal('dialplan-modal')" title="Dial Plan (F2)">&#9776; Dial Plan</button>
    <button class="rbtn" onclick="openModal('groups-modal')" title="Ring Groups &amp; Forwarding (F3)">&#9778; Groups</button>
    <button class="rbtn" onclick="openModal('cdr-modal')" title="Call Log (F4)">&#9779; Call Log</button>
    <button class="rbtn" onclick="openModal('trace-modal')" title="SIP Trace (F8)">&#9780; Trace</button>
    <button class="rbtn" onclick="openModal('wifi-modal');scanWifi()" title="WiFi (F9)">&#9783; WiFi</button>
    <button class="rbtn" onclick="openModal('admin-modal')" title="Admin">&#9919; Admin</button>
    <button class="rbtn" onclick="openTelephonyModal()" title="Telephone Interconnect">&#9742; Interconnect</button>
    <button class="rbtn" onclick="openModal('help-modal')" title="Help (F1)">? Help</button>
  </div>
</div>

<main>

  <!-- ══ PATCH BAY ══ -->
  <section class="patch-bay">
    <div class="bay-face" id="board-wrap">
      <div class="bay-title"><span>Jack Board</span><span class="count" id="board-cap">0 shown / 32 total</span></div>
      <svg id="cords"></svg>
      <div id="jacks"></div>
      <div class="legend">
        <span class="item"><span class="swatch" style="background:var(--idle)"></span>idle</span>
        <span class="item"><span class="swatch" style="background:var(--ringing)"></span>ringing</span>
        <span class="item"><span class="swatch" style="background:var(--active)"></span>active</span>
        <span class="item"><span class="swatch" style="background:var(--parked)"></span>parked</span>
        <span class="item"><span class="swatch" style="background:var(--alert)"></span>alert</span>
        <span class="item"><span class="swatch" style="background:var(--cord-a)"></span>cord = ring-group membership</span>
      </div>
    </div>
  </section>

</main>

<!-- ══ DIAL PLAN MODAL ══
     The dial plan is the ONLY way to reach an outside trunk: there is no
     hardcoded "9" prefix and no unregistered-destination fallback, so with an
     empty table every outside number answers 404 without ever leaving the box.
     First match wins, and the table is evaluated AFTER every reserved virtual
     extension, so no rule can shadow 777/999/440/888/555/70x/*8. -->
<div class="overlay" id="dialplan-modal">
  <div class="modal wide">
    <h3>&#9776; Dial Plan <span class="badge" id="dp-count">0</span><span class="x" onclick="closeModal('dialplan-modal')">&times;</span></h3>
    <div class="mbody">
      <div class="note">
        Ordered rules, first match wins. <b>X</b> matches one digit; a trailing <b>*</b> matches any
        remaining digits. Rules are evaluated after the reserved feature extensions, so a catch-all
        can never shadow the echo test or a park orbit.
      </div>
      <div id="dp-list"><div class="note">Loading rules&hellip;</div></div>
      <hr class="hr">
      <div class="subhead">New / Edit Rule</div>
      <div class="grid2">
        <div>
          <div class="field"><label>Pattern</label><input type="text" id="dp-pattern" placeholder="e.g. 9XXXXXXXXXX"></div>
          <div class="field"><label>Action</label>
            <select id="dp-action" onchange="dpActionChanged()">
              <option value="trunk">Trunk (outside line)</option>
              <option value="group">Ring group</option>
              <option value="page">Page zone</option>
              <option value="park">Park orbit</option>
            </select>
          </div>
        </div>
        <div>
          <div class="field"><label id="dp-target-label">Prepend after stripping</label><input type="text" id="dp-target" placeholder="e.g. 1"></div>
          <div class="field" id="dp-strip-field"><label>Strip leading digits</label><input type="text" id="dp-strip" inputmode="numeric" placeholder="e.g. 1" value="0"></div>
        </div>
      </div>
      <div class="row">
        <button class="btn primary" onclick="saveDialRule()">Save Rule</button>
        <span class="note">Dialing <b>9</b> then <b>3057673260</b> with strip 1 / prepend 1 sends <b>13057673260</b>.</span>
      </div>
      <div class="msg" id="dp-msg"></div>
      <p class="note">
        <b>Prepend nothing:</b> leave Prepend blank on a trunk rule to send the dialed digits with only
        the strip applied &mdash; dialing <b>9</b> then <b>3057673260</b> with strip 1 and no prepend
        sends <b>3057673260</b>. <b>Deleting:</b> use the Delete button on a rule above.
      </p>
    </div>
  </div>
</div>

<!-- ══ RING GROUPS & FORWARDING MODAL ══ -->
<div class="overlay" id="groups-modal">
  <div class="modal wide">
    <h3>&#9778; Ring Groups &amp; Forwarding<span class="x" onclick="closeModal('groups-modal')">&times;</span></h3>
    <div class="mbody">
        <div class="grid2">
          <div>
            <div class="subhead">Ring / Hunt Groups</div>
            <p class="note" style="margin-top:0">Cords on the jack board show live membership.</p>
            <div id="groups-list"></div>
            <hr class="hr">
            <div class="subhead">New / Edit Group</div>
)html1";

static const char PD_HTML_2[] =
R"html2(            <div class="field"><label>Group extension</label><input type="text" id="grp-ext" inputmode="numeric" placeholder="e.g. 600"></div>
            <div class="field"><label>Members (comma separated)</label><input type="text" id="grp-members" placeholder="101,102,103"></div>
            <div class="field"><label>Mode</label>
              <select id="grp-mode"><option value="ringall">Ring all</option><option value="hunt">Hunt</option></select>
            </div>
            <div class="row">
              <button class="btn primary" onclick="saveGroup()">Save Group</button>
              <span class="note">Empty members deletes the group.</span>
            </div>
            <div class="msg" id="grp-msg"></div>
            <p class="note">Routing an outside line? That lives under <b>Dial Plan</b>.</p>
          </div>
          <div>
            <div class="subhead">Per-Extension Forwarding</div>
            <div id="fwd-list"></div>
            <hr class="hr">
            <div class="subhead">Set Forward</div>
            <div class="field"><label>Extension</label><input type="text" id="fwd-ext" inputmode="numeric" placeholder="e.g. 101"></div>
            <div class="field"><label>Trigger</label>
              <select id="fwd-trigger"><option value="always">Always</option><option value="busy">Busy</option><option value="noanswer">No answer</option></select>
            </div>
            <div class="field"><label>Target (blank clears)</label><input type="text" id="fwd-target" inputmode="numeric" placeholder="e.g. 102"></div>
            <button class="btn primary" onclick="saveForward()">Save Forward</button>
            <div class="msg" id="fwd-msg"></div>
          </div>
        </div>
    </div>
  </div>
</div>

<!-- ══ CALL LOG MODAL ══ -->
<div class="overlay" id="cdr-modal">
  <div class="modal wide">
    <h3>&#9779; Call Log <span class="badge" id="cdr-count">0</span><span class="x" onclick="closeModal('cdr-modal')">&times;</span></h3>
    <div class="mbody" style="padding:0">
        <table>
          <thead><tr><th>Caller</th><th></th><th>Callee</th><th>Result</th><th>Duration</th><th>Age</th></tr></thead>
          <tbody id="cdr-tbody"><tr class="empty-row"><td colspan="6">No calls recorded yet</td></tr></tbody>
        </table>
    </div>
  </div>
</div>

<!-- ══ SIP TRACE MODAL ══ -->
<div class="overlay" id="trace-modal">
  <div class="modal wide">
    <h3>&#9780; SIP Trace <span class="badge" id="trace-count">off</span><span class="x" onclick="closeModal('trace-modal')">&times;</span></h3>
    <div class="mbody">
        <div class="row" style="justify-content:space-between;margin-bottom:8px">
          <label class="toggle"><input type="checkbox" id="trace-toggle" onchange="toggleTrace()"><span class="track"><span class="knob"></span></span></label>
          <span class="note" style="margin:0">Flip the switch, or type <b>trace on</b> / <b>trace off</b> below. Downloadable as a full .pcap via <a href="/api/pcap">/api/pcap</a>.</span>
        </div>
        <div class="trace-screen" id="trace-screen"><div class="trc-empty">Trace is off.</div></div>
        <div class="term-line">
          <span class="term-prompt">pd&gt;</span>
          <input type="text" id="term-input" class="term-input" autocomplete="off" autocapitalize="off" spellcheck="false"
                 placeholder="trace on | trace off | help" onkeydown="if(event.key==='Enter')termExec()">
        </div>
    </div>
  </div>
</div>

<!-- ══ JACK DETAIL MODAL ══ -->
<div class="overlay" id="jack-modal">
  <div class="modal">
    <h3><span id="jd-lamp"></span><span>Jack <span id="jd-num">--</span></span><span class="x" onclick="closeModal('jack-modal')">&times;</span></h3>
    <div class="mbody">
      <div class="kv"><span class="k">State</span><span id="jd-state">&mdash;</span></div>
      <div class="kv"><span class="k">Peer</span><span id="jd-peer">&mdash;</span></div>
      <div class="kv"><span class="k">Duration</span><span id="jd-dur">&mdash;</span></div>
      <div class="kv"><span class="k">Address</span><span id="jd-addr">&mdash;</span></div>
      <hr class="hr">
      <div class="row" style="justify-content:space-between">
        <span class="subhead" style="margin:0">Do Not Disturb</span>
        <label class="toggle"><input type="checkbox" id="jd-dnd" onchange="toggleDnd()"><span class="track"><span class="knob"></span></span></label>
      </div>
      <hr class="hr">
      <div class="subhead">Call Forwarding</div>
      <div class="fwd-row"><label>Always</label><input type="text" id="jd-fwd-always" inputmode="numeric" placeholder="target ext"><button class="btn" onclick="jdSaveFwd('always')">Set</button></div>
      <div class="fwd-row"><label>Busy</label><input type="text" id="jd-fwd-busy" inputmode="numeric" placeholder="target ext"><button class="btn" onclick="jdSaveFwd('busy')">Set</button></div>
      <div class="fwd-row"><label>No answer</label><input type="text" id="jd-fwd-noanswer" inputmode="numeric" placeholder="target ext"><button class="btn" onclick="jdSaveFwd('noanswer')">Set</button></div>
      <div class="msg" id="jd-msg"></div>
      <div class="danger-zone">
        <div class="subhead">Danger Zone</div>
        <button class="btn danger" onclick="killJack()">&#9888; Force Disconnect</button>
      </div>
    </div>
  </div>
</div>

<!-- ══ ADMIN MODAL ══ -->
<div class="overlay" id="admin-modal">
  <div class="modal">
    <h3>&#9919; Admin / Security &amp; Firmware<span class="x" onclick="closeModal('admin-modal')">&times;</span></h3>
    <div class="mbody">
      <div class="subhead">Operator Authentication</div>
      <div id="admin-loading" class="note">Querying admin status&hellip;</div>
      <div id="admin-login" style="display:none">
        <div class="note">Ships with a default login &mdash; admin / admin &mdash; until you set a real one below.</div>
        <div class="field"><label>Username</label><input type="text" id="adm-user" autocomplete="username"></div>
        <div class="field"><label>Password</label><input type="password" id="adm-pass" autocomplete="current-password"></div>
        <button class="btn primary" onclick="adminLogin()">Login</button>
      </div>
      <div id="admin-setup" style="display:none">
        <div class="msg warn">&#9888; Still on the default login. Set a real username, password, and (optional) DTMF admin PIN before doing anything else.</div>
        <div class="field"><label>New username</label><input type="text" id="adm-setup-user" autocomplete="username" value="admin"></div>
        <div class="field"><label>New password (min 8 chars)</label><input type="password" id="adm-setup-pass" autocomplete="new-password"></div>
        <div class="field"><label>DTMF admin PIN (4-16 digits, optional &mdash; phone-keypad admin menu stays disabled without one)</label><input type="password" id="adm-setup-dtmfpin" inputmode="numeric" autocomplete="off"></div>
        <button class="btn primary" onclick="adminCompleteSetup()">Complete Setup</button>
      </div>
      <div id="admin-loggedin" style="display:none">
        <div class="msg ok">&#9679; Logged in &mdash; admin controls unlocked.</div>
        <div class="row">
          <button class="btn" onclick="toggleChangeCredential()">Change Password</button>
          <button class="btn" onclick="toggleChangeDtmfPin()">Change DTMF PIN</button>
          <button class="btn danger" onclick="adminLogout()">Logout</button>
        </div>
        <div id="admin-changecred" style="display:none;margin-top:8px">
          <div class="field"><label>Username</label><input type="text" id="adm-changeuser" autocomplete="username"></div>
          <div class="field"><label>New password (min 8 chars)</label><input type="password" id="adm-changepass" autocomplete="new-password"></div>
          <button class="btn primary" onclick="adminChangeCredential()">Save</button>
        </div>
        <div id="admin-changedtmfpin" style="display:none;margin-top:8px">
          <div class="field"><label>New DTMF PIN (4-16 digits)</label><input type="password" id="adm-changedtmfpin-val" inputmode="numeric" autocomplete="off"></div>
          <button class="btn primary" onclick="adminChangeDtmfPin()">Save</button>
        </div>
      </div>
      <div class="msg" id="admin-msg"></div>

      <hr class="hr">
      <div class="subhead">&#128246; Wi-Fi Access Point Security</div>
      <div class="note">
        This device&rsquo;s own access point carries the dashboard, SIP signalling and
        call audio. Left open, anyone in radio range can join and record calls.
        Turning WPA2 on encrypts all three at once &mdash; the single most effective
        hardening available here.
      </div>
      <div class="msg warn" id="ap-break-note">
        Switching this on is a <strong>breaking change</strong>: every phone already
        associated with this access point must be re-joined using the passphrase
        below. Nothing changes until the access point next comes up.
      </div>
      <div class="kv"><span class="k">Current mode</span><span id="ap-mode">&mdash;</span></div>
      <div class="field">
        <label for="ap-psk">Access point passphrase (8&ndash;63 characters)</label>
        <input type="text" id="ap-psk" autocomplete="off" spellcheck="false">
      </div>
      <div class="row">
        <label class="note" for="ap-secure"><input type="checkbox" id="ap-secure"> Require WPA2 on the access point</label>
      </div>
      <div class="row">
        <button class="btn primary" onclick="saveApSecurity()">Save</button>
        <button class="btn" onclick="regenApPsk()">Generate new passphrase</button>
      </div>
      <div class="msg" id="ap-msg"></div>

      <hr class="hr">
      <div class="subhead">&#9990; Extension Registration &amp; Onboarding</div>
      <div class="note">
        Controls what a phone must prove before it can register as an extension.
        <strong>Open</strong> accepts any endpoint with no credential &mdash; convenient
        for a lab, but on a shared link anyone can register as any extension and tear
        down calls. <strong>Learn</strong> adopts unknown phones on first contact and
        locks each to its extension; run it briefly to onboard a fleet, then move on.
        <strong>Secure</strong> digest-challenges every registration.
      </div>
      <div class="kv"><span class="k">Current mode</span><span id="reg-mode-cur">&mdash;</span></div>
      <div class="field">
        <label for="reg-mode">Registration mode</label>
        <select id="reg-mode">
          <option value="open">Open &mdash; no credential required</option>
          <option value="learn">Learn &mdash; adopt new phones (temporary)</option>
          <option value="secure">Secure &mdash; digest auth required</option>
        </select>
      </div>
      <button class="btn primary" onclick="saveRegistrarMode()">Apply mode</button>
      <div class="msg" id="reg-msg"></div>

      <div class="subhead" style="margin-top:10px">Adopted extensions</div>
      <div class="note" id="reg-roster-note">
        Phones seen while in Learn mode. <strong>Secure</strong> locks one to its
        extension and starts enforcing digest auth for it; <strong>Forget</strong> drops
        the record so the phone is re-adopted on its next registration.
      </div>
      <table id="reg-roster">
        <thead><tr><th>Extension</th><th>MAC</th><th>State</th><th></th></tr></thead>
        <tbody id="reg-roster-body"></tbody>
      </table>

      <hr class="hr">
      <div class="subhead">&#8593; Firmware Update (OTA)</div>
      <div class="kv"><span class="k">OTA support</span><span id="ota-supported">&mdash;</span></div>
      <div class="kv"><span class="k">Running</span><span id="ota-running">&mdash;</span></div>
      <div class="kv"><span class="k">Boot / Next</span><span id="ota-parts">&mdash;</span></div>
)html2";

static const char PD_HTML_3[] =
R"html3(      <div class="msg" id="ota-state-msg"></div>
      <div class="note" id="ota-gate-note" style="display:none">Admin login required to update firmware.</div>
      <div class="field"><label>Firmware image (.bin)</label><input type="file" id="ota-file" accept=".bin"></div>
      <div id="ota-prog"><div id="ota-bar"></div><div id="ota-pct">0%</div></div>
      <div class="row">
        <button class="btn primary" id="ota-upload-btn" onclick="otaUpload()">&#8593; Upload</button>
        <button class="btn danger" id="ota-reboot-btn" onclick="otaReboot()">&#8635; Reboot device</button>
      </div>
      <div class="msg" id="ota-msg"></div>
    </div>
  </div>
</div>

<!-- ══ WIFI MODAL ══ -->
<div class="overlay" id="wifi-modal">
  <div class="modal">
    <h3>&#9783; WiFi &amp; Network<span class="x" onclick="closeModal('wifi-modal')">&times;</span></h3>
    <div class="mbody">
      <div class="row"><button class="btn" onclick="scanWifi()">&#8635; Scan</button><span class="note" id="wifi-status">Ready</span></div>
      <div id="wifi-list" style="margin-top:8px"><div class="note">Press Scan to discover networks&hellip;</div></div>
      <div class="note" id="wifi-admin-note" style="display:none">&#9919; Admin login required for the controls below.</div>
      <div id="wifi-connect" style="display:none">
        <hr class="hr">
        <div class="field"><label>SSID: <span id="wifi-ssid" style="color:var(--ink)"></span></label><input type="password" id="wifi-pw" placeholder="Network key"></div>
        <div class="row">
          <button class="btn primary" id="wifi-connect-btn" onclick="connectWifi()">&#9889; Connect</button>
          <button class="btn" onclick="cancelWifiConnect()">Cancel</button>
        </div>
      </div>
      <hr class="hr">
      <div class="subhead">Standalone AP Mode</div>
      <button class="btn" id="wifi-ap-btn" onclick="startApMode()">&#9889; Host Standalone AP</button>
      <div class="note">Persists across reboots. Unconfigured devices auto-switch to Standalone ~5 min after power-on.</div>
      <button class="btn" onclick="holdConfigMode()" style="margin-top:6px">&#9208; I'm Configuring (hold setup)</button>
      <div class="danger-zone">
        <div class="subhead">Danger Zone</div>
        <button class="btn danger" id="wifi-reset-btn" onclick="factoryReset()">&#9888; Factory Reset</button>
      </div>
    </div>
  </div>
</div>

<!-- ══ TELEPHONE INTERCONNECT MODAL ══ -->
<div class="overlay" id="telephony-modal">
  <div class="modal">
    <h3>&#9742; Telephone Interconnect<span class="x" onclick="closeModal('telephony-modal')">&times;</span></h3>
    <div class="mbody">
      <div class="note">
        Bridges calls to an outside telephone network through a carrier's call-control
        API. Configure a slot with the carrier's credentials, then Activate it to choose
        which slot the device uses. A slot with no working backend yet is labelled
        &ldquo;not yet connected&rdquo; below &mdash; it stores what you enter, but nothing
        actually dials out through it until that provider is implemented. Test Dial places
        a real probe call through the active slot's live provider connection.
      </div>
      <div class="kv"><span class="k">Active slot</span><span id="tapi-active-summary">&mdash;</span></div>

      <div class="subhead">Carrier API Slots</div>
      <table id="tapi-slots">
        <thead><tr><th>Slot</th><th>Status</th><th>Base URL</th><th>Route DN</th><th></th></tr></thead>
        <tbody id="tapi-slots-body"></tbody>
      </table>

      <hr class="hr">
      <div class="subhead" id="tapi-edit-title">Configure Slot 1</div>
      <div class="field"><label>Base URL / FQDN</label><input type="text" id="tapi-baseurl" autocomplete="off" spellcheck="false" placeholder="https://api.example.com"></div>
      <div class="field"><label>Client ID</label><input type="text" id="tapi-clientid" autocomplete="off" spellcheck="false"></div>
      <div class="field"><label>API Key / Secret</label><input type="password" id="tapi-secret" autocomplete="off" placeholder="leave blank to keep existing"></div>
      <div class="field"><label>Route Point / Source DN</label><input type="text" id="tapi-routedn" autocomplete="off" spellcheck="false" placeholder="e.g. +15551234567"></div>
      <div class="row"><label class="note" for="tapi-enabled" style="margin:0"><input type="checkbox" id="tapi-enabled"> Enabled &mdash; needs an https:// base URL to take effect</label></div>
      <div class="row">
        <button class="btn primary" onclick="saveTelephonySlot()">Save Slot</button>
        <button class="btn" onclick="activateTelephonySlot(tapiSelected)">Activate This Slot</button>
        <button class="btn" id="tapi-test-btn" onclick="testTelephonySlot(tapiSelected)">&#9742; Test Dial</button>
      </div>
      <div class="msg" id="tapi-msg"></div>
      <div class="row" style="justify-content:flex-end"><span class="test-result" id="tapi-test-result"></span></div>

      <hr class="hr">
      <div class="subhead">DID &rarr; Extension Routing</div>
      <div class="note">
        Currently only one route point is supported: the DID you enter here
        must exactly match the Route Point / Source DN configured above in
        the active Carrier API slot &mdash; that's the only inbound number
        this device ever sees. Rows for other DIDs are stored but will never
        match until multi-route support is added; an unmatched call falls
        through to ring-all, same as if no mapping existed.
      </div>
      <table id="did-table">
        <thead><tr><th>DID</th><th>Extension</th><th></th></tr></thead>
        <tbody id="did-table-body"></tbody>
      </table>
      <div class="did-row">
        <input type="text" id="did-new-did" autocomplete="off" spellcheck="false" placeholder="Must match Route Point DN above">
        <input type="text" id="did-new-ext" inputmode="numeric" placeholder="Extension">
        <button class="btn primary" onclick="addDidMapping()">Add</button>
      </div>
      <div class="msg" id="did-msg"></div>
    </div>
  </div>
</div>

<!-- ══ HELP MODAL ══ -->
<div class="overlay" id="help-modal">
  <div class="modal">
    <h3>&#9737; Switchboard Help<span class="x" onclick="closeModal('help-modal')">&times;</span></h3>
    <div class="mbody" style="line-height:1.7;font-size:13px">
      <p style="color:var(--brass);font-family:var(--mono)">POCKET&middot;DIAL &mdash; patch-bay switchboard</p>
      <hr class="hr">
      <p><b>The board.</b> Each ring is an extension jack. <span style="color:var(--idle)">Green</span> = idle/registered, <span style="color:var(--ringing)">yellow</span> = ringing, <span style="color:var(--active)">orange</span> = active call, <span style="color:var(--parked)">blue</span> = parked, <span style="color:var(--alert)">red</span> = alert. A dim ring = not yet seen. A small DND tag marks Do Not Disturb.</p>
      <p style="margin-top:8px"><b>Cords.</b> A cord is a ring group, drawn between its member jacks — it never represents a single call. A lit jack is a call; tap it to see who with (peer and duration show in its panel).</p>
      <p style="margin-top:8px"><b>Tap a jack</b> to open its panel: state, peer, duration, address, DND toggle, the three call-forward triggers, and a force-disconnect.</p>
      <p style="margin-top:8px"><b>Admin badge.</b> The header badge's left half is this browser's real web login session. Its right half is an unrelated note: dialing <code>*PIN#code</code> from extension 1001 is a separate phone-keypad command channel (NTP resync, WiFi topology switch, factory reset) that never opens or extends the web session.</p>
      <hr class="hr">
      <p style="color:var(--brass);font-family:var(--mono)">Shortcuts</p>
      <p><span style="font-family:var(--mono);color:var(--brass-hi)">F1</span> Help &nbsp; <span style="font-family:var(--mono);color:var(--brass-hi)">F5</span> Refresh &nbsp; <span style="font-family:var(--mono);color:var(--brass-hi)">F9</span> WiFi &nbsp; <span style="font-family:var(--mono);color:var(--brass-hi)">Esc</span> Close</p>
    </div>
  </div>
</div>

<div id="toast"></div>

<footer>pocket-dial &middot; patch-bay switchboard</footer>

<script>
"use strict";
var statusData={ip:"0.0.0.0",port:5060,uptime:0,clients:[],sessions:[],dnd:[],forwards:[],groups:[],dialplan:[],parkedCalls:[],packetsProcessed:0};
var adminState={provisioned:false,needsSetup:true,authenticated:false,sessionRemainingSec:0};
var otaUploading=false;
var selectedSSID="";
var selectedJack=null;
var failCount=0;
var POOL=32;
var tapiSlots=[];
var tapiSelected=0;
var tapiTestState={};
/* Per-session CSRF token. The literal below is replaced by the server when it
   renders this page (HttpServer::sendHtml); an unauthenticated load leaves it
   empty and adminLogin() fills it in from the login response. It is deliberately
   NOT a cookie: the browser would attach a cookie to a same-site request on its
   own, so only a value our own script has to read and echo back proves the
   request came from this page rather than from someone else's. */
var PD_CSRF="__PD_CSRF__";

/* ── helpers ── */
function $(id){return document.getElementById(id);}
function esc(s){return String(s==null?"":s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;").replace(/'/g,"&#39;");}
function cssEsc(s){return String(s==null?"":s).replace(/["\\]/g,"\\$&");}
function toast(msg,cls){var t=$("toast");t.textContent=msg;t.className=cls?("show "+cls):"show";clearTimeout(t._t);t._t=setTimeout(function(){t.className="";},2600);}
function fmtUptime(sec){sec=Math.floor(sec||0);var h=Math.floor(sec/3600),m=Math.floor(sec%3600/60),s=sec%60;function p(n){return(n<10?"0":"")+n;}return p(h)+":"+p(m)+":"+p(s);}
function setMsg(id,txt,cls){var e=$(id);if(e){e.textContent=txt||"";e.className="msg"+(cls?" "+cls:"");}}

/* ── modals ── */
function openModal(id){$(id).classList.add("show");}
function closeModal(id){$(id).classList.remove("show");}
document.addEventListener("click",function(e){if(e.target.classList&&e.target.classList.contains("overlay"))e.target.classList.remove("show");});

/* ── extension classification from /api/status ──
   One entry per extension ever seen this poll, merged from clients (registration),
   dnd, sessions (call state + who with), and parkedCalls (self-park model: an
   extension parks itself, so parkedExt === parker == the same caller). */
function buildIndex(d){
  var idx={};
  function ensure(n){n=String(n);if(!idx[n])idx[n]={num:n,addr:"",reg:false,dnd:false,sessionState:"",peer:"",duration:"",parked:false,parkedBy:"",orbit:""};return idx[n];}
  (d.clients||[]).forEach(function(c){var e=ensure(c.number);e.reg=true;e.addr=c.address||"";});
  (d.dnd||[]).forEach(function(n){ensure(n).dnd=true;});
  (d.sessions||[]).forEach(function(s){
    var a=ensure(s.caller),b=ensure(s.callee);
    a.sessionState=s.state||"";a.peer=String(s.callee);a.duration=s.duration||"";
    b.sessionState=s.state||"";b.peer=String(s.caller);b.duration=s.duration||"";
  });
  (d.parkedCalls||[]).forEach(function(p){
    var e=ensure(p.parkedExt);e.parked=true;e.parkedBy=p.parker;e.orbit=p.orbit;
  });
  return idx;
}
/* State priority: parked, then the live session state, then registration.
   sessionStateToString() (RequestsHandler.cpp) emits exactly: Invited, Connected,
   Busy, Unavailable, Cancel, Bye, Unknown (Unknown covers the Held enum value,
   which has no case of its own there). Busy/Cancel/Bye are ordinary call-teardown
   states that must NOT override the base idle/unreg classification for this
   extension — otherwise a jack flashes "active" for one poll tick right after
   every normal hangup. Unavailable is the one exception: it only ever appears
   when a destination genuinely could not be reached, never on a normal hangup,
)html3";

static const char PD_HTML_4[] =
R"html4(   so it is surfaced as "alert" rather than silently folded back to idle. */
function jackStateOf(e){
  if(e.parked)return "parked";
  var st=e.sessionState;
  if(st==="Invited")return "ringing";
  if(st==="Connected"||st==="Unknown")return "active";
  if(st==="Unavailable")return "alert";
  if(e.reg)return "idle";
  return "unreg";
}
function jackSublabel(e,state){
  if(state==="active")return e.duration||"active";
  if(state==="ringing")return "ringing";
  if(state==="parked")return "park\u00b7"+(e.orbit||"");
  if(state==="alert")return "unavail";
  if(state==="idle")return "reg";
  return "\u2014";
}

/* ── render patch bay ── */
function renderBoard(d){
  var idx=buildIndex(d);
  var nums=Object.keys(idx).sort(function(a,b){return (parseInt(a,10)||0)-(parseInt(b,10)||0);});
  var board=$("jacks");
  var html="";
  nums.forEach(function(n){
    var e=idx[n];var state=jackStateOf(e);
    html+='<button class="jack state-'+state+'" data-ext="'+esc(n)+'" onclick="openJack(\''+esc(n)+'\')">'
      +'<span class="ring"><span class="led"></span>'+(e.dnd?'<span class="badge-dnd">DND</span>':'')+'</span>'
      +'<span class="label">'+esc(n)+'</span>'
      +'<span class="sublabel">'+esc(jackSublabel(e,state))+'</span></button>';
  });
  if(!nums.length)html='<div class="note" style="text-align:center;padding:24px">No extensions seen yet. Register a phone to light a jack.</div>';
  board.innerHTML=html;
  $("board-cap").textContent=nums.length+" shown / "+POOL+" total";
  requestAnimationFrame(function(){drawCords(d);});
}

/* ── SVG patch-cords: ring-group MEMBERSHIP only, never a per-call state.
   Members of one group are chained pairwise (member[i] -> member[i+1]); the
   group's own "extension" is a virtual pilot number, not a physical jack, so
   it is never a cord endpoint. Colors cycle mauve/olive/teal by group index. */
function drawCords(d){
  var svg=$("cords");var wrap=$("board-wrap");
  if(!svg||!wrap){return;}
  var wr=wrap.getBoundingClientRect();
  svg.setAttribute("width",wr.width);svg.setAttribute("height",wr.height);
  svg.setAttribute("viewBox","0 0 "+wr.width+" "+wr.height);
  var parts=[];
  var colors=["cord-a","cord-b","cord-c"];
  (d.groups||[]).forEach(function(g,gi){
    var members=String(g.members||"").split(",").map(function(s){return s.trim();}).filter(Boolean);
    var pts=[];
    members.forEach(function(m){
      var el=document.querySelector('.jack[data-ext="'+cssEsc(m)+'"] .ring');
      if(!el)return;
      var r=el.getBoundingClientRect();
      pts.push({x:r.left+r.width/2-wr.left,y:r.top+r.height/2-wr.top});
    });
    var cls=colors[gi%3];
    for(var i=0;i<pts.length-1;i++){
      var a=pts[i],b=pts[i+1];
      var midX=(a.x+b.x)/2,sag=30;
      parts.push('<path class="cord '+cls+'" d="M '+a.x+' '+a.y+' Q '+midX+' '+(Math.max(a.y,b.y)+sag)+' '+b.x+' '+b.y+'"/>');
    }
  });
  svg.innerHTML=parts.join("");
}

/* ── jack detail panel ── */
var JACK_STATE_LABEL={idle:"IDLE / REGISTERED",active:"ACTIVE CALL",ringing:"RINGING",parked:"PARKED",alert:"ALERT \u2014 UNAVAILABLE",unreg:"IDLE / UNREGISTERED"};
var JACK_STATE_COLOR={idle:"var(--idle)",active:"var(--active)",ringing:"var(--ringing)",parked:"var(--parked)",alert:"var(--alert)",unreg:"var(--lamp-off)"};
function openJack(ext){
  selectedJack=ext;
  var idx=buildIndex(statusData);
  var e=idx[ext]||{num:ext,addr:"",reg:false,dnd:false,sessionState:"",peer:"",duration:"",parked:false};
  var state=jackStateOf(e);
  $("jd-num").textContent=ext;
  var lamp=$("jd-lamp");
  var col=JACK_STATE_COLOR[state];
  lamp.style.background=col;
  lamp.style.boxShadow=(state==="unreg")?"none":("0 0 8px "+col);
  $("jd-state").textContent=JACK_STATE_LABEL[state]+(e.dnd?" \u00b7 DND":"");
  $("jd-peer").textContent=e.peer||"\u2014";
  $("jd-dur").textContent=e.duration||"\u2014";
  $("jd-addr").textContent=e.addr||"\u2014";
  $("jd-dnd").checked=!!e.dnd;
  var fwd=(statusData.forwards||[]).filter(function(f){return String(f.extension)===String(ext);})[0]||{};
  $("jd-fwd-always").value=fwd.always||"";
  $("jd-fwd-busy").value=fwd.busy||"";
  $("jd-fwd-noanswer").value=fwd.noanswer||"";
  setMsg("jd-msg","");
  openModal("jack-modal");
}
function gateCheck(){if(!adminState.authenticated||adminState.needsSetup){toast(adminState.authenticated?"Complete admin setup first":"Admin login required","err");openModal("admin-modal");return false;}return true;}

function toggleDnd(){
  if(!selectedJack)return;
  if(!gateCheck()){$("jd-dnd").checked=!$("jd-dnd").checked;return;}
  var on=$("jd-dnd").checked;
  post("/api/dnd","extension="+encodeURIComponent(selectedJack)+"&on="+(on?"1":"0"))
    .then(function(){setMsg("jd-msg","DND "+(on?"enabled":"disabled")+" for "+selectedJack,"ok");fetchStatus();})
    .catch(function(err){setMsg("jd-msg",err.message,"err");$("jd-dnd").checked=!on;});
}
function jdSaveFwd(trigger){
  if(!selectedJack||!gateCheck())return;
  var t=$("jd-fwd-"+trigger).value.trim();
  post("/api/forward","extension="+encodeURIComponent(selectedJack)+"&trigger="+trigger+"&target="+encodeURIComponent(t))
    .then(function(){setMsg("jd-msg",trigger+" forward "+(t?("→ "+t):"cleared"),"ok");fetchStatus();})
    .catch(function(err){setMsg("jd-msg",err.message,"err");});
}
function killJack(){
  if(!selectedJack||!gateCheck())return;
  if(!confirm("Force-disconnect extension "+selectedJack+"?"))return;
  post("/api/kill","extension="+encodeURIComponent(selectedJack))
    .then(function(){setMsg("jd-msg","Disconnect signal sent.","ok");toast("Disconnected "+selectedJack,"ok");fetchStatus();})
    .catch(function(err){setMsg("jd-msg",err.message,"err");});
}

/* ── groups & forwarding panels ── */
function renderGroups(d){
  var list=$("groups-list");var g=d.groups||[];
  if(!g.length){list.innerHTML='<div class="note">No groups defined.</div>';}
  else{
    list.innerHTML=g.map(function(x){
      return '<div class="kv"><span><b style="color:var(--brass-hi)">'+esc(x.extension)+'</b> '
        +'<span style="color:var(--ink-dim)">['+esc(x.mode)+']</span></span>'
        +'<span style="color:var(--ink-dim);font-size:11px">'+esc(x.members||"")+'</span></div>';
    }).join("");
  }
  var fl=$("fwd-list");var f=(d.forwards||[]).filter(function(x){return x.always||x.busy||x.noanswer;});
  if(!f.length){fl.innerHTML='<div class="note">No active forwards.</div>';}
  else{
    fl.innerHTML=f.map(function(x){
      var bits=[];if(x.always)bits.push("always→"+esc(x.always));if(x.busy)bits.push("busy→"+esc(x.busy));if(x.noanswer)bits.push("na→"+esc(x.noanswer));
      return '<div class="kv"><span><b style="color:var(--brass-hi)">'+esc(x.extension)+'</b></span>'
        +'<span style="color:var(--ink-dim);font-size:11px">'+bits.join("  ")+'</span></div>';
    }).join("");
  }
}
function saveGroup(){
  if(!gateCheck())return;
  var ext=$("grp-ext").value.trim();
  if(!ext){setMsg("grp-msg","Group extension required.","err");return;}
  var members=$("grp-members").value.trim();
  var mode=$("grp-mode").value;
  post("/api/group","extension="+encodeURIComponent(ext)+"&members="+encodeURIComponent(members)+"&mode="+mode)
    .then(function(){setMsg("grp-msg",members?("Group "+ext+" saved."):("Group "+ext+" deleted."),"ok");fetchStatus();})
    .catch(function(err){setMsg("grp-msg",err.message,"err");});
}
/* ── Dial plan ──
   The only route to an outside trunk. Rendered from /api/status's dialplan[],
   written through POST /api/dialplan. An empty target is the API's delete
   signal, so "strip N, prepend nothing" is NOT expressible — the trunk form
   below therefore requires a prepend value. */
function dpActionChanged(){
  var trunk=$("dp-action").value==="trunk";
  $("dp-strip-field").style.display=trunk?"":"none";
  $("dp-target-label").textContent=trunk?"Prepend after stripping":"Target extension";
  $("dp-target").placeholder=trunk?"e.g. 1":"e.g. 600";
}
function dpDescribe(r){
  if(r.action!=="trunk")return r.action+" → "+esc(r.target||"");
  var strip=Number(r.stripDigits||0);
  return "trunk → strip "+strip+", "+(r.target?("prepend "+esc(r.target)):"prepend nothing");
}
function renderDialplan(d){
  var rules=d.dialplan||[];
  $("dp-count").textContent=rules.length;
  var list=$("dp-list");
  if(!rules.length){
    list.innerHTML='<div class="note">No rules. Every outside number answers 404 until a trunk rule exists.</div>';
    return;
  }
  list.innerHTML=rules.map(function(r,i){
    return '<div class="dp-rule"><span class="pat">'+esc(r.pattern)+'</span>'
      +'<span class="act">'+dpDescribe(r)+'</span>'
      +'<button class="btn" onclick="deleteDialRule('+i+')">Delete</button></div>';
  }).join("");
}
function saveDialRule(){
  if(!gateCheck())return;
  var pattern=$("dp-pattern").value.trim();
  if(!pattern){setMsg("dp-msg","Pattern required.","err");return;}
  var action=$("dp-action").value;
  var target=$("dp-target").value.trim();
  /* A trunk rule MAY have an empty target: that is "strip N, prepend nothing".
     Every other action needs a destination. The request still names an action,
     which is what distinguishes an upsert from a delete. */
  if(!target&&action!=="trunk"){setMsg("dp-msg","Target required for a "+action+" rule.","err");return;}
  var body="pattern="+encodeURIComponent(pattern)+"&action="+action+"&target="+encodeURIComponent(target);
  if(action==="trunk"){
    var strip=$("dp-strip").value.trim()||"0";
    if(!/^\d{1,3}$/.test(strip)){setMsg("dp-msg","Strip must be a small non-negative integer.","err");return;}
    body+="&stripDigits="+strip;
  }
  post("/api/dialplan",body)
    .then(function(){setMsg("dp-msg","Rule "+pattern+" saved.","ok");fetchStatus();})
    .catch(function(err){setMsg("dp-msg",err.message,"err");});
}
function deleteDialRule(i){
  if(!gateCheck())return;
  var r=(statusData.dialplan||[])[i];
  if(!r)return;
  post("/api/dialplan","pattern="+encodeURIComponent(r.pattern)+"&target=")
    .then(function(){setMsg("dp-msg","Rule "+r.pattern+" deleted.","ok");fetchStatus();})
    .catch(function(err){setMsg("dp-msg",err.message,"err");});
}
function saveForward(){
  if(!gateCheck())return;
  var ext=$("fwd-ext").value.trim();
  if(!ext){setMsg("fwd-msg","Extension required.","err");return;}
  var trigger=$("fwd-trigger").value;
  var target=$("fwd-target").value.trim();
  post("/api/forward","extension="+encodeURIComponent(ext)+"&trigger="+trigger+"&target="+encodeURIComponent(target))
    .then(function(){setMsg("fwd-msg",target?(trigger+" → "+target):(trigger+" cleared"),"ok");fetchStatus();})
    .catch(function(err){setMsg("fwd-msg",err.message,"err");});
}

/* ── CDR table ── */
function renderCdr(records){
  var tb=$("cdr-tbody");
  $("cdr-count").textContent=records.length;
  if(!records.length){tb.innerHTML='<tr class="empty-row"><td colspan="6">No calls recorded yet</td></tr>';return;}
  tb.innerHTML=records.map(function(r){
    var res=String(r.result||"").toLowerCase();
    var dur=fmtDur(r.duration);
    return '<tr><td style="color:var(--brass-hi)">'+esc(r.caller)+'</td>'
      +'<td class="arrow">&rarr;</td>'
      +'<td style="color:var(--brass-hi)">'+esc(r.callee)+'</td>'
      +'<td><span class="chip '+esc(res)+'">'+esc(r.result)+'</span></td>'
      +'<td>'+dur+'</td>'
      +'<td style="color:var(--ink-dim)">'+fmtAge(r.ageSec)+'</td></tr>';
  }).join("");
}
function fmtDur(s){s=Math.floor(s||0);var m=Math.floor(s/60),sec=s%60;return m+":"+(sec<10?"0":"")+sec;}
function fmtAge(s){s=Math.floor(s||0);if(s<60)return s+"s ago";if(s<3600)return Math.floor(s/60)+"m ago";return Math.floor(s/3600)+"h ago";}

/* ── live SIP trace (Issue #32): polls /api/trace while on ──
   Started/stopped either by the checkbox or by the `trace on`/`trace off`
   terminal commands below — both paths funnel through startTrace()/
   stopTrace() so there is exactly one live-update mechanism (1.5 s polling
   of the existing /api/trace ring), not a second one bolted on for the
   command surface. */
var traceOn=false,traceTimer=null,traceSeen={};
function toggleTrace(){
  if($("trace-toggle").checked&&!gateCheck()){$("trace-toggle").checked=false;return;}
)html4";

static const char PD_HTML_5[] =
R"html5(  if($("trace-toggle").checked)startTrace();else stopTrace();
}
function startTrace(cmdEcho){
  traceOn=true;$("trace-toggle").checked=true;
  traceSeen={};$("trace-screen").innerHTML="";$("trace-count").textContent="0 shown";
  if(cmdEcho){termEcho(cmdEcho);termEcho("trace on — streaming.");}
  pollTrace();traceTimer=setInterval(pollTrace,1500);
}
function stopTrace(cmdEcho){
  traceOn=false;$("trace-toggle").checked=false;
  if(traceTimer){clearInterval(traceTimer);traceTimer=null;}
  $("trace-count").textContent="off";
  $("trace-screen").innerHTML='<div class="trc-empty">Trace is off.</div>';
  if(cmdEcho){termEcho(cmdEcho);termEcho("trace off.");}
}
function pollTrace(){
  fetch("/api/trace",{credentials:"same-origin"}).then(function(r){
    if(r.status===401){handleAuthExpired();stopTrace();throw new Error("session expired");}
    if(!r.ok)throw new Error("HTTP "+r.status);
    return r.json();
  }).then(renderTraceAppend).catch(function(){});
}
function renderTraceAppend(records){
  var screen=$("trace-screen");var added=0;
  (records||[]).forEach(function(r){
    if(traceSeen[r.seq])return;
    traceSeen[r.seq]=true;added++;
    var div=document.createElement("div");div.className="trc-pkt";
    var out=r.dir==="out";
    div.innerHTML='<div class="trc-hdr'+(out?" out":"")+'">'+(out?"&#8594; OUT &rarr; ":"&#8592; IN &larr; ")
      +esc(r.peer)+' &middot; #'+r.seq+'</div>'+esc(r.text);
    screen.appendChild(div);
  });
  while(screen.children.length>200){screen.removeChild(screen.children[0]);}
  if(added>0)screen.scrollTop=screen.scrollHeight;
  var shown=screen.querySelectorAll(".trc-pkt").length;
  $("trace-count").textContent=shown+" shown";
}
function termEcho(line){
  var screen=$("trace-screen");
  var empty=screen.querySelector(".trc-empty");if(empty)empty.remove();
  var div=document.createElement("div");div.className="trc-cmd";div.textContent=line;
  screen.appendChild(div);
  while(screen.children.length>200){screen.removeChild(screen.children[0]);}
  screen.scrollTop=screen.scrollHeight;
}
function termExec(){
  var input=$("term-input");var raw=input.value;input.value="";
  if(!raw.trim())return;
  var line="pd> "+raw;
  var cmd=raw.trim().toLowerCase().replace(/\s+/g," ");
  if(cmd==="trace on"){
    if(traceOn){termEcho(line);termEcho("trace already on.");return;}
    if(!gateCheck()){termEcho(line);termEcho("session required — log in above first.");return;}
    startTrace(line);
  }else if(cmd==="trace off"){
    if(!traceOn){termEcho(line);termEcho("trace already off.");return;}
    stopTrace(line);
  }else if(cmd==="help"||cmd==="?"){
    termEcho(line);termEcho("commands: trace on, trace off, help");
  }else{
    termEcho(line);termEcho("unknown command: "+raw);
  }
}

/* ── networking ── */
function httpMethod(method,url,body){
  return fetch(url,{method:method,credentials:"same-origin",headers:{"Content-Type":"application/x-www-form-urlencoded","X-CSRF":PD_CSRF},body:body})
    .then(function(r){
      if(r.status===401){handleAuthExpired();throw new Error("session expired — please log in");}
      if(r.status===403){throw new Error("rejected (cross-origin or stale security token — reload the page)");}
      if(!r.ok){throw new Error("HTTP "+r.status);}
      return r.text();
    });
}
function post(url,body){return httpMethod("POST",url,body);}
function put(url,body){return httpMethod("PUT",url,body);}
function del(url,body){return httpMethod("DELETE",url,body);}
function fetchStatus(){
  fetch("/api/status").then(function(r){return r.json();}).then(function(d){
    statusData=d;failCount=0;setOnline(true);updateRail(d);renderBoard(d);renderGroups(d);renderDialplan(d);pushPacketSample(d.packetsProcessed||0);
  }).catch(function(){failCount++;if(failCount>=2)setOnline(false);});
}
function fetchCdr(){
  fetch("/api/cdr").then(function(r){return r.json();}).then(renderCdr).catch(function(){});
}
function setOnline(ok){
  var dot=$("dot"),txt=$("online-txt"),rec=$("recon");
  if(ok){dot.className="on";txt.textContent="online";rec.className="recon";}
  else{dot.className="warn";txt.textContent="offline";rec.className="recon show";}
}
function updateRail(d){
  $("s-uptime").textContent=fmtUptime(d.uptime);
  $("s-ip").textContent=(d.ip||"0.0.0.0")+":"+(d.port||5060);
  $("s-jacks").textContent=((d.clients||[]).length)+"/"+POOL;
  $("s-calls").textContent=(d.sessions||[]).length;
  $("s-pkts").textContent=(d.packetsProcessed||0).toLocaleString();
}
function refreshNow(){fetchStatus();fetchCdr();toast("Refreshed","ok");}

/* ── packet sparkline: rolling per-poll THROUGHPUT (delta of the cumulative
   packetsProcessed counter), not the raw cumulative value — a raw counter only
   ever climbs, which would draw a flat rising line instead of a live pulse. */
var pktHistory=new Array(24).fill(0);
var lastPkts=null;
function pushPacketSample(current){
  var delta=0;
  if(lastPkts!=null){delta=current-lastPkts;if(delta<0)delta=0;}
  lastPkts=current;
  pktHistory.shift();pktHistory.push(delta);
  drawSparkline();
}
function drawSparkline(){
  var max=Math.max.apply(null,pktHistory.concat([1]));
  var w=70,h=20;
  var pts=pktHistory.map(function(v,i){return (i/(pktHistory.length-1))*w+","+(h-(v/max)*h);}).join(" ");
  var el=$("sparkline");if(el)el.setAttribute("points",pts);
}

/* redraw cords on resize (debounced) */
var rsTimer=null;
window.addEventListener("resize",function(){clearTimeout(rsTimer);rsTimer=setTimeout(function(){drawCords(statusData);},120);});

/* ════ ADMIN / AUTH ════ */
function fetchAdminStatus(){
  return fetch("/api/admin/status",{credentials:"same-origin"}).then(function(r){return r.json();}).then(function(d){
    adminState.provisioned=!!d.provisioned;adminState.needsSetup=!!d.needsSetup;adminState.authenticated=!!d.authenticated;
    adminState.sessionRemainingSec=d.sessionRemainingSec||0;
    renderAdminPanel();renderAdminBadge();applyAuthGating();
    if(adminState.authenticated&&!adminState.needsSetup){fetchApSecurity();fetchRegistrar();}
  }).catch(function(){});
}
function renderAdminPanel(){
  $("admin-loading").style.display="none";
  $("admin-login").style.display="none";$("admin-setup").style.display="none";
  $("admin-loggedin").style.display="none";
  if(!adminState.authenticated)$("admin-login").style.display="block";
  else if(adminState.needsSetup)$("admin-setup").style.display="block";
  else $("admin-loggedin").style.display="block";
}
/* Header badge: LEFT segment only ever reflects this real /api/admin/status
   session (authenticated + sessionRemainingSec). The RIGHT segment (the DTMF
   note) is static markup, never touched here — it must not appear to react to
   this session's state, since the two are genuinely unrelated systems. */
function renderAdminBadge(){
  var badge=$("admin-badge"),txt=$("admin-text");
  if(adminState.authenticated){
    badge.className="admin-badge open";
    var sec=Math.max(0,adminState.sessionRemainingSec|0);
    var m=Math.floor(sec/60),s=sec%60;
    txt.textContent="SESSION: LOGGED IN \u00b7 "+(m<10?"0":"")+m+":"+(s<10?"0":"")+s;
  }else{
    badge.className="admin-badge closed";
    txt.textContent="SESSION: LOGGED OUT";
  }
}
function controlsUnlocked(){return adminState.authenticated&&!adminState.needsSetup;}
function applyAuthGating(){
  var unlocked=controlsUnlocked();
  ["wifi-connect-btn","wifi-ap-btn","wifi-reset-btn","ota-upload-btn","ota-reboot-btn"].forEach(function(id){var b=$(id);if(b)b.disabled=!unlocked;});
  var wn=$("wifi-admin-note");if(wn)wn.style.display=unlocked?"none":"block";
  var on=$("ota-gate-note");if(on)on.style.display=unlocked?"none":"block";
  var of=$("ota-file");if(of)of.disabled=!unlocked;
}
function handleAuthExpired(){adminState.authenticated=false;adminState.sessionRemainingSec=0;renderAdminPanel();renderAdminBadge();applyAuthGating();setMsg("admin-msg","Session expired — please log in.","err");}
function adminCompleteSetup(){
  var user=$("adm-setup-user").value,pass=$("adm-setup-pass").value,dtmfPin=$("adm-setup-dtmfpin").value;
  if(!user||!pass||pass.length<8){setMsg("admin-msg","Username and an 8+ character password are required.","err");return;}
  var body="username="+encodeURIComponent(user)+"&password="+encodeURIComponent(pass);
  if(dtmfPin)body+="&dtmfPin="+encodeURIComponent(dtmfPin);
  post("/api/admin/set-credential",body).then(function(){
    $("adm-setup-pass").value="";$("adm-setup-dtmfpin").value="";
    setMsg("admin-msg","Setup complete.","ok");fetchAdminStatus();
  }).catch(function(e){setMsg("admin-msg","Error: "+e.message,"err");});
}
function adminChangeCredential(){
  var user=$("adm-changeuser").value,pass=$("adm-changepass").value;
  if(!user||!pass||pass.length<8){setMsg("admin-msg","Username and an 8+ character password are required.","err");return;}
  post("/api/admin/set-credential","username="+encodeURIComponent(user)+"&password="+encodeURIComponent(pass)).then(function(){
    $("adm-changepass").value="";$("admin-changecred").style.display="none";
    setMsg("admin-msg","Password updated.","ok");
  }).catch(function(e){setMsg("admin-msg","Error: "+e.message,"err");});
}
function adminChangeDtmfPin(){
  var pin=$("adm-changedtmfpin-val").value;
  if(!pin||pin.length<4){setMsg("admin-msg","DTMF PIN must be at least 4 digits.","err");return;}
  post("/api/admin/set-credential","dtmfPin="+encodeURIComponent(pin)).then(function(){
    $("adm-changedtmfpin-val").value="";$("admin-changedtmfpin").style.display="none";
    setMsg("admin-msg","DTMF PIN updated.","ok");
  }).catch(function(e){setMsg("admin-msg","Error: "+e.message,"err");});
}
function parseJsonOr(t){try{return JSON.parse(t);}catch(e){return {};}}
function renderApSecurity(d){
  $("ap-mode").textContent=d.secure?"WPA2 (encrypted)":"Open \u2014 unencrypted";
  $("ap-secure").checked=!!d.secure;
  $("ap-psk").value=d.psk||"";
}
function fetchApSecurity(){
  return fetch("/api/ap-security",{credentials:"same-origin"})
    .then(function(r){if(!r.ok){throw new Error("HTTP "+r.status);}return r.json();})
    .then(renderApSecurity).catch(function(){});
}
function saveApSecurity(){
  var psk=$("ap-psk").value;
  if(psk.length<8||psk.length>63){setMsg("ap-msg","Passphrase must be 8\u201363 characters.","err");return;}
  post("/api/ap-security","secure="+($("ap-secure").checked?"1":"0")+"&psk="+encodeURIComponent(psk))
    .then(function(t){
      renderApSecurity(parseJsonOr(t));
      setMsg("ap-msg","Saved. Takes effect the next time the access point starts.","ok");
    }).catch(function(e){setMsg("ap-msg","Error: "+e.message,"err");});
}
function regenApPsk(){
  post("/api/ap-security","regenerate=1")
    .then(function(t){
      renderApSecurity(parseJsonOr(t));
      setMsg("ap-msg","New passphrase generated \u2014 write it down before restarting the access point.","warn");
    }).catch(function(e){setMsg("ap-msg","Error: "+e.message,"err");});
}
function renderRegistrar(d){
  var mode=(d&&d.mode)||"unknown";
  $("reg-mode-cur").textContent=(d&&d.attached===false)?"\u2014 (SIP engine not attached yet)":mode;
  if(d&&d.attached!==false&&mode!=="unknown"){$("reg-mode").value=mode;}
  var body=$("reg-roster-body");
  body.innerHTML="";
  var devs=(d&&d.devices)||[];
  if(!devs.length){
    var tr=document.createElement("tr");
    var td=document.createElement("td");
    td.colSpan=4;
    td.textContent=(mode==="learn")
      ? "No phones adopted yet \u2014 register one now and it will appear here."
      : "No phones adopted. Switch to Learn mode to onboard them.";
    tr.appendChild(td);body.appendChild(tr);return;
  }
  devs.forEach(function(x){
    var tr=document.createElement("tr");
    var tdE=document.createElement("td");tdE.textContent=x.extension||"\u2014";
    var tdM=document.createElement("td");tdM.textContent=x.mac||"\u2014";
    var tdS=document.createElement("td");
    tdS.textContent=(x.state==="secured"?"secured":"learned")+(x.online?" \u00b7 online":"");
)html5";

static const char PD_HTML_6[] =
R"html6(    var tdA=document.createElement("td");
    if(x.state!=="secured"){
      var b=document.createElement("button");
      b.className="btn";b.textContent="Secure";
      b.onclick=function(){registrarDevice("secure",x.mac);};
      tdA.appendChild(b);
    }
    var f=document.createElement("button");
    f.className="btn danger";f.textContent="Forget";
    f.onclick=function(){registrarDevice("forget",x.mac);};
    tdA.appendChild(f);
    tr.appendChild(tdE);tr.appendChild(tdM);tr.appendChild(tdS);tr.appendChild(tdA);
    body.appendChild(tr);
  });
}
function fetchRegistrar(){
  return fetch("/api/registrar",{credentials:"same-origin"})
    .then(function(r){if(!r.ok){throw new Error("HTTP "+r.status);}return r.json();})
    .then(renderRegistrar).catch(function(){});
}
function saveRegistrarMode(){
  var mode=$("reg-mode").value;
  postRegistrarMode(mode,false);
}
function postRegistrarMode(mode,confirmLockout){
  var body="mode="+encodeURIComponent(mode)+(confirmLockout?"&confirm=LOCKOUT":"");
  post("/api/registrar",body)
    .then(function(t){
      renderRegistrar(parseJsonOr(t));
      setMsg("reg-msg","Registration mode is now "+mode+".","ok");
    })
    .catch(function(e){
      if(/HTTP 409/.test(e.message)){
        if(confirm("No extensions are secured yet.\n\nSwitching to Secure now will reject EVERY phone until each one is adopted and secured.\n\nSwitch anyway?")){
          postRegistrarMode(mode,true);
        }else{
          setMsg("reg-msg","Left unchanged. Use Learn mode to adopt phones first.","warn");
          fetchRegistrar();
        }
        return;
      }
      setMsg("reg-msg","Error: "+e.message,"err");
    });
}
function registrarDevice(action,target){
  post("/api/registrar/device","action="+encodeURIComponent(action)+"&target="+encodeURIComponent(target))
    .then(function(t){
      renderRegistrar(parseJsonOr(t));
      setMsg("reg-msg",(action==="secure"?"Extension secured.":"Device forgotten."),"ok");
    }).catch(function(e){setMsg("reg-msg","Error: "+e.message,"err");});
}
function adminLogin(){
  var user=$("adm-user").value,pass=$("adm-pass").value;
  if(!user||!pass){setMsg("admin-msg","Enter your username and password.","err");return;}
  fetch("/api/admin/login",{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/x-www-form-urlencoded"},
        body:"username="+encodeURIComponent(user)+"&password="+encodeURIComponent(pass)})
    .then(function(r){
      $("adm-pass").value="";
      if(r.status===401){setMsg("admin-msg","Incorrect username or password.","err");return;}
      if(r.status===429){setMsg("admin-msg","Locked — wait a minute.","err");return;}
      if(!r.ok){setMsg("admin-msg","Login failed (HTTP "+r.status+").","err");return;}
      r.json().then(function(d){if(d&&d.csrf){PD_CSRF=d.csrf;}}).catch(function(){});
      setMsg("admin-msg","Logged in.","ok");toast("Admin unlocked","ok");fetchAdminStatus();
    }).catch(function(e){setMsg("admin-msg","Error: "+e.message,"err");});
}
function adminLogout(){
  fetch("/api/admin/logout",{method:"POST",credentials:"same-origin"}).then(function(){setMsg("admin-msg","Logged out.","warn");fetchAdminStatus();}).catch(function(){});
}
function toggleChangeCredential(){var cp=$("admin-changecred");cp.style.display=cp.style.display==="block"?"none":"block";if(cp.style.display==="block")$("adm-changeuser").focus();}
function toggleChangeDtmfPin(){var cp=$("admin-changedtmfpin");cp.style.display=cp.style.display==="block"?"none":"block";if(cp.style.display==="block")$("adm-changedtmfpin-val").focus();}

/* ════ OTA ════ */
function fetchOtaStatus(){
  return fetch("/api/ota/status",{credentials:"same-origin"}).then(function(r){return r.json();}).then(function(d){
    $("ota-supported").textContent=d.otaSupported?"YES":"NO (host build)";
    $("ota-running").textContent=d.running?"IN PROGRESS":"idle";
    $("ota-parts").textContent=(d.boot||"—")+" / "+(d.next||"—");
    var sm=$("ota-state-msg");
    if(d.pendingVerify){sm.textContent="New firmware pending verification.";sm.className="msg warn";}
    else if(d.error){sm.textContent="Last error: "+d.error;sm.className="msg err";}
    else{sm.textContent="";sm.className="msg";}
  }).catch(function(){});
}
function otaUpload(){
  if(otaUploading)return;
  if(!controlsUnlocked()){setMsg("ota-msg","Admin login required.","err");return;}
  var fileEl=$("ota-file");var file=fileEl&&fileEl.files&&fileEl.files[0];
  if(!file){setMsg("ota-msg","Choose a firmware .bin first.","err");return;}
  var prog=$("ota-prog"),bar=$("ota-bar"),pct=$("ota-pct");
  prog.style.display="block";bar.style.width="0%";pct.textContent="0%";
  otaUploading=true;$("ota-upload-btn").disabled=true;
  setMsg("ota-msg","Uploading "+file.name+" ("+file.size.toLocaleString()+" bytes)…","warn");
  var xhr=new XMLHttpRequest();
  xhr.open("POST","/api/ota/upload",true);xhr.withCredentials=true;
  xhr.setRequestHeader("Content-Type","application/octet-stream");
  xhr.setRequestHeader("X-CSRF",PD_CSRF);
  xhr.upload.onprogress=function(e){if(e.lengthComputable){var p=Math.round(e.loaded/e.total*100);bar.style.width=p+"%";pct.textContent=p+"%";}};
  xhr.onload=function(){
    otaUploading=false;applyAuthGating();
    if(xhr.status===200){bar.style.width="100%";pct.textContent="100%";var info={};try{info=JSON.parse(xhr.responseText);}catch(e){}
      setMsg("ota-msg","Upload complete ("+(info.bytes||file.size)+" bytes). Reboot to apply.","ok");fetchOtaStatus();
      if(info.rebootRequired&&confirm("Firmware uploaded. Reboot now to apply?"))otaReboot(true);
    }else if(xhr.status===401){handleAuthExpired();setMsg("ota-msg","Session expired — please log in.","err");}
    else if(xhr.status===501){setMsg("ota-msg","OTA only available on device (not host build).","err");}
    else setMsg("ota-msg","Upload failed (HTTP "+xhr.status+").","err");
  };
  xhr.onerror=function(){otaUploading=false;applyAuthGating();setMsg("ota-msg","Upload failed — network error.","err");};
  xhr.send(file);
}
function otaReboot(skip){
  if(!controlsUnlocked()){setMsg("ota-msg","Admin login required.","err");return;}
  if(!skip&&!confirm("Reboot the device now? Any active calls will drop."))return;
  setMsg("ota-msg","Rebooting device…","warn");
  fetch("/api/ota/reboot",{method:"POST",credentials:"same-origin"})
    .then(function(r){if(r.status===401){handleAuthExpired();return;}setMsg("ota-msg","Reboot signal sent. Restarting…","ok");})
    .catch(function(){setMsg("ota-msg","Reboot signal sent. Restarting…","ok");});
}

/* ════ WIFI ════ */
function scanWifi(){
  var st=$("wifi-status");st.textContent="Scanning…";st.style.color="var(--ringing)";
  fetch("/api/wifi/scan").then(function(r){return r.json();}).then(function(d){
    var nets=d.networks||[];st.textContent="Found "+nets.length+" networks";st.style.color="var(--idle)";
    renderWifi(nets);
  }).catch(function(e){st.textContent="Scan failed: "+e.message;st.style.color="var(--alert)";});
}
function renderWifi(nets){
  var list=$("wifi-list");list.innerHTML="";
  if(!nets.length){list.innerHTML='<div class="note">No networks found.</div>';return;}
  nets.forEach(function(n){
    var ssid=String(n.ssid==null?"":n.ssid);var rssi=Number(n.rssi)||0;var enc=n.encryption||"OPEN";
    var bars=rssi>-50?"▂▄▆█":rssi>-65?"▂▄▆ ":rssi>-75?"▂▄  ":"▂   ";
    var row=document.createElement("div");row.className="wifi-net";
    row.addEventListener("click",function(){selectWifi(ssid);});
    var s=document.createElement("span");s.className="wifi-ssid";s.textContent=ssid;
    var m=document.createElement("span");m.className="wifi-meta";m.textContent=bars+" "+rssi+"dBm ["+enc+"]";
    row.appendChild(s);row.appendChild(m);list.appendChild(row);
  });
}
function selectWifi(ssid){selectedSSID=ssid;$("wifi-ssid").textContent=ssid;$("wifi-connect").style.display="block";$("wifi-pw").value="";$("wifi-pw").focus();}
function cancelWifiConnect(){$("wifi-connect").style.display="none";selectedSSID="";}
function connectWifi(){
  var st=$("wifi-status");st.textContent="Connecting to "+selectedSSID+"…";st.style.color="var(--ringing)";
  post("/api/wifi/connect","ssid="+encodeURIComponent(selectedSSID)+"&password="+encodeURIComponent($("wifi-pw").value))
    .then(function(){st.textContent="Connected to "+selectedSSID+"!";st.style.color="var(--idle)";cancelWifiConnect();toast("WiFi connected","ok");})
    .catch(function(e){st.textContent="Failed: "+e.message;st.style.color="var(--alert)";});
}
function startApMode(){
  var st=$("wifi-status");st.textContent="Enabling AP Mode…";st.style.color="var(--ringing)";
  fetch("/api/wifi/mode_ap",{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/x-www-form-urlencoded"}})
    .then(function(r){if(r.status===401){handleAuthExpired();throw new Error("session expired");}return r.json();})
    .then(function(){st.textContent="AP mode set! Rebooting…";st.style.color="var(--idle)";})
    .catch(function(e){st.textContent="Failed: "+e.message;st.style.color="var(--alert)";});
}
function holdConfigMode(){
  fetch("/api/configuring",{method:"POST"}).then(function(r){return r.json();})
    .then(function(d){toast(d.message||"Setup mode held.","ok");}).catch(function(e){toast("Error: "+e.message,"err");});
}
function factoryReset(){
  if(!confirm("Factory reset erases saved Wi-Fi config and reboots into captive-portal setup. Continue?"))return;
  var st=$("wifi-status");st.textContent="Factory resetting…";st.style.color="var(--alert)";
  fetch("/api/factory-reset",{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/x-www-form-urlencoded"},body:"confirm=ERASE"})
    .then(function(r){if(r.status===401){handleAuthExpired();throw new Error("session expired");}return r.json();})
    .then(function(d){toast(d.message||"Rebooting…","warn");}).catch(function(e){toast("Error: "+e.message,"err");});
}

/* ════ TELEPHONE INTERCONNECT ════
   Carrier API credential slots (GET/PUT /api/telephony-config[/n], POST
   /api/telephony-config/n/activate, POST /api/telephony-config/n/test) and
   DID→extension routing (GET/PUT/DELETE /api/did-mapping). */
var PD_RESERVED_EXT={"777":1,"999":1,"555":1,"888":1,"440":1};
function isDialTokenSafeJs(s){return !!s&&/^[A-Za-z0-9#*]+$/.test(s);}
function openTelephonyModal(){
  if(!gateCheck())return;
  openModal("telephony-modal");
  fetchTelephonyConfig();fetchDidMappings();
}
function tapiStatusChip(s){
  var configured=!!(s.baseUrl||s.clientId||s.secretSet||s.routeDn||s.enabled);
  if(!configured)return '<span class="chip stub">Not configured</span>';
  if(!s.implemented)return '<span class="chip pending">Configured — not yet connected</span>';
  return s.active?'<span class="chip live">Active</span>':'<span class="chip pending">Configured</span>';
}
function fetchTelephonyConfig(){
  return fetch("/api/telephony-config",{credentials:"same-origin"}).then(function(r){
    if(r.status===401){handleAuthExpired();throw new Error("session expired");}
    if(!r.ok)throw new Error("HTTP "+r.status);
    return r.json();
  }).then(function(d){tapiSlots=d.slots||[];renderTapiSlots();selectTapiSlot(tapiSelected);}).catch(function(){});
}
function renderTapiSlots(){
  var body=$("tapi-slots-body");body.innerHTML="";
  var activeLabel="None (loopback default)";
  tapiSlots.forEach(function(s,i){
    if(s.active)activeLabel="Slot "+(i+1)+(s.implemented?"":" (not yet connected)");
    var tr=document.createElement("tr");
    var tdN=document.createElement("td");tdN.textContent="Slot "+(i+1);
    var tdS=document.createElement("td");tdS.innerHTML=tapiStatusChip(s);
    var tdU=document.createElement("td");tdU.textContent=s.baseUrl||"—";
    var tdR=document.createElement("td");tdR.textContent=s.routeDn||"—";
    var tdA=document.createElement("td");
    var eb=document.createElement("button");eb.className="btn";eb.textContent="Edit";
)html6";

static const char PD_HTML_7[] =
R"html7(    eb.onclick=function(){selectTapiSlot(i);};
    tdA.appendChild(eb);
    if(!s.active){
      var ab=document.createElement("button");ab.className="btn";ab.textContent="Activate";ab.style.marginLeft="4px";
      ab.onclick=function(){activateTelephonySlot(i);};
      tdA.appendChild(ab);
    }
    tr.appendChild(tdN);tr.appendChild(tdS);tr.appendChild(tdU);tr.appendChild(tdR);tr.appendChild(tdA);
    body.appendChild(tr);
  });
  $("tapi-active-summary").textContent=activeLabel;
}
function selectTapiSlot(i){
  tapiSelected=i;
  var s=tapiSlots[i]||{};
  $("tapi-edit-title").textContent="Configure Slot "+(i+1)+(s.active?" (active)":"");
  $("tapi-baseurl").value=s.baseUrl||"";
  $("tapi-clientid").value=s.clientId||"";
  $("tapi-secret").value="";
  $("tapi-secret").placeholder=s.secretSet?"leave blank to keep existing":"";
  $("tapi-routedn").value=s.routeDn||"";
  $("tapi-enabled").checked=!!s.enabled;
  var testBtn=$("tapi-test-btn");
  if(testBtn)testBtn.style.display=(s.active&&s.implemented)?"":"none";
  renderTapiTestResult(i);
  setMsg("tapi-msg","");
}
function saveTelephonySlot(){
  if(!gateCheck())return;
  var body="enabled="+($("tapi-enabled").checked?"1":"0")
    +"&baseUrl="+encodeURIComponent($("tapi-baseurl").value.trim())
    +"&clientId="+encodeURIComponent($("tapi-clientid").value.trim())
    +"&secret="+encodeURIComponent($("tapi-secret").value)
    +"&routeDn="+encodeURIComponent($("tapi-routedn").value.trim());
  put("/api/telephony-config/"+tapiSelected,body)
    .then(function(){setMsg("tapi-msg","Slot "+(tapiSelected+1)+" saved.","ok");fetchTelephonyConfig();})
    .catch(function(e){setMsg("tapi-msg",e.message,"err");});
}
function activateTelephonySlot(i){
  if(!gateCheck())return;
  post("/api/telephony-config/"+i+"/activate","")
    .then(function(){setMsg("tapi-msg","Slot "+(i+1)+" is now active.","ok");fetchTelephonyConfig();})
    .catch(function(e){setMsg("tapi-msg",e.message,"err");});
}
/* Places a real probe call through the active slot's live provider connection
   (RequestsHandler::testDialSlot) — only offered once a slot is both active and
   implemented, since that's the only condition under which it can do anything. */
function testTelephonySlot(i){
  if(!gateCheck())return;
  var s=tapiSlots[i]||{};
  if(!(s.active&&s.implemented)){setMsg("tapi-msg","Slot "+(i+1)+" must be active and connected before testing.","err");return;}
  var btn=$("tapi-test-btn");var orig=btn.textContent;
  btn.disabled=true;btn.textContent="Dialing…";
  post("/api/telephony-config/"+i+"/test","")
    .then(function(t){
      var d=parseJsonOr(t);
      btn.disabled=false;btn.textContent=orig;
      tapiTestState[i]={ok:!!d.ok,detail:(d.ok?d.participantId:d.error)||"",ts:Date.now()};
      renderTapiTestResult(i);
    })
    .catch(function(e){btn.disabled=false;btn.textContent=orig;setMsg("tapi-msg",e.message,"err");});
}
function renderTapiTestResult(i){
  var el=$("tapi-test-result");if(!el)return;
  var r=tapiTestState[i];
  if(!r){el.textContent="";return;}
  var ageSec=Math.floor((Date.now()-r.ts)/1000);
  var age=ageSec<5?"just now":ageSec<60?ageSec+"s ago":Math.floor(ageSec/60)+"m ago";
  el.textContent="last: "+(r.ok?"OK":"FAIL")+(r.detail?(" \u00b7 "+r.detail):"")+" \u00b7 "+age;
}
function fetchDidMappings(){
  return fetch("/api/did-mapping",{credentials:"same-origin"}).then(function(r){
    if(r.status===401){handleAuthExpired();throw new Error("session expired");}
    if(!r.ok)throw new Error("HTTP "+r.status);
    return r.json();
  }).then(function(d){renderDidMappings(d.mappings||[]);}).catch(function(){});
}
function renderDidMappings(list){
  var body=$("did-table-body");body.innerHTML="";
  if(!list.length){
    var tr=document.createElement("tr");var td=document.createElement("td");
    td.colSpan=3;td.className="note";td.textContent="No DID mappings configured.";
    tr.appendChild(td);body.appendChild(tr);return;
  }
  list.forEach(function(m){
    var tr=document.createElement("tr");
    var tdD=document.createElement("td");tdD.textContent=m.did;
    var tdE=document.createElement("td");tdE.textContent=m.extension;
    var tdA=document.createElement("td");
    var b=document.createElement("button");b.className="btn danger";b.textContent="Remove";
    b.onclick=function(){removeDidMapping(m.did);};
    tdA.appendChild(b);
    tr.appendChild(tdD);tr.appendChild(tdE);tr.appendChild(tdA);
    body.appendChild(tr);
  });
}
function addDidMapping(){
  if(!gateCheck())return;
  var did=$("did-new-did").value.trim();
  var ext=$("did-new-ext").value.trim();
  if(!did||!ext){setMsg("did-msg","DID and extension are both required.","err");return;}
  if(!isDialTokenSafeJs(ext)){setMsg("did-msg","Extension may contain only letters, digits, '#' and '*'.","err");return;}
  if(PD_RESERVED_EXT[ext]){setMsg("did-msg","Cannot map a DID to a virtual/reserved extension ("+ext+").","err");return;}
  put("/api/did-mapping","did="+encodeURIComponent(did)+"&extension="+encodeURIComponent(ext))
    .then(function(){$("did-new-did").value="";$("did-new-ext").value="";setMsg("did-msg","Mapping saved.","ok");fetchDidMappings();})
    .catch(function(e){setMsg("did-msg",e.message,"err");});
}
function removeDidMapping(did){
  if(!gateCheck())return;
  del("/api/did-mapping","did="+encodeURIComponent(did))
    .then(function(){setMsg("did-msg","Mapping removed.","ok");fetchDidMappings();})
    .catch(function(e){setMsg("did-msg",e.message,"err");});
}

/* ── keyboard shortcuts ── */
document.addEventListener("keydown",function(e){
  if(e.key==="F1"){e.preventDefault();openModal("help-modal");}
  else if(e.key==="F2"){e.preventDefault();openModal("dialplan-modal");}
  else if(e.key==="F3"){e.preventDefault();openModal("groups-modal");}
  else if(e.key==="F4"){e.preventDefault();openModal("cdr-modal");}
  else if(e.key==="F5"){e.preventDefault();refreshNow();}
  else if(e.key==="F8"){e.preventDefault();openModal("trace-modal");}
  else if(e.key==="F9"){e.preventDefault();openModal("wifi-modal");scanWifi();}
  else if(e.key==="Escape"){["jack-modal","admin-modal","wifi-modal","telephony-modal","help-modal",
    "dialplan-modal","groups-modal","cdr-modal","trace-modal"].forEach(function(id){closeModal(id);});}
});
["adm-user","adm-pass"].forEach(function(id){var el=$(id);if(el)el.addEventListener("keydown",function(e){if(e.key==="Enter")adminLogin();});});
["adm-setup-user","adm-setup-pass","adm-setup-dtmfpin"].forEach(function(id){var el=$(id);if(el)el.addEventListener("keydown",function(e){if(e.key==="Enter")adminCompleteSetup();});});
["adm-changeuser","adm-changepass"].forEach(function(id){var el=$(id);if(el)el.addEventListener("keydown",function(e){if(e.key==="Enter")adminChangeCredential();});});
(function(){var el=$("adm-changedtmfpin-val");if(el)el.addEventListener("keydown",function(e){if(e.key==="Enter")adminChangeDtmfPin();});})();

/* ── init ── */
fetchStatus();fetchCdr();fetchAdminStatus();fetchOtaStatus();
setInterval(fetchStatus,2000);
setInterval(fetchCdr,5000);
setInterval(fetchAdminStatus,15000);
setInterval(function(){if(!otaUploading)fetchOtaStatus();},15000);
setInterval(function(){if(adminState.authenticated&&adminState.sessionRemainingSec>0){adminState.sessionRemainingSec--;renderAdminBadge();}},1000);
setInterval(function(){if($("telephony-modal").classList.contains("show"))renderTapiTestResult(tapiSelected);},5000);
</script>

</body>
</html>
)html7";

// One HttpServer::sendHtml() assembles these into a single std::string per
// request (as it already did with the old single literal) -- the parts
// themselves stay in flash the whole time. sizeof(PD_HTML_N)-1 drops the
// implicit NUL each array's initializer added, same as strlen() would but
// resolved at compile time.
static const HtmlPart CGA_INDEX_HTML_PARTS[] = {
	{ PD_HTML_0, sizeof(PD_HTML_0) - 1 },
	{ PD_HTML_1, sizeof(PD_HTML_1) - 1 },
	{ PD_HTML_2, sizeof(PD_HTML_2) - 1 },
	{ PD_HTML_3, sizeof(PD_HTML_3) - 1 },
	{ PD_HTML_4, sizeof(PD_HTML_4) - 1 },
	{ PD_HTML_5, sizeof(PD_HTML_5) - 1 },
	{ PD_HTML_6, sizeof(PD_HTML_6) - 1 },
	{ PD_HTML_7, sizeof(PD_HTML_7) - 1 },
};
static constexpr size_t CGA_INDEX_HTML_PART_COUNT =
	sizeof(CGA_INDEX_HTML_PARTS) / sizeof(CGA_INDEX_HTML_PARTS[0]);

#endif // INDEX_HTML_H
