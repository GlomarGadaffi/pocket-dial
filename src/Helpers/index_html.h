#ifndef INDEX_HTML_H
#define INDEX_HTML_H

static const char CGA_INDEX_HTML[] =
R"html0(<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Pocket-Dial Switchboard</title>
<style>
:root{
  --field:#0d0b09; --field2:#141009; --panel:#1a140d; --panel2:#221a10;
  --brass:#c69a4e; --brass-lo:#8a6a32; --brass-hi:#e8c987; --brass-dim:#6e5526;
  --ink:#e8dcc3; --ink-dim:#9a8a6a; --line:#3a2c19; --line-hi:#5a4527;
  --amber:#ffb000; --amber-glow:#ff9c1a; --lamp-off:#2a2117;
  --green:#7bd66a; --red:#e8654a; --bake:#191512; --bake2:#221c16;
  --shadow:0 2px 4px rgba(0,0,0,.5);
  --mono:ui-monospace,"Cascadia Code","Cascadia Mono","Consolas","SF Mono",Menlo,monospace;
  --sans:system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;
}
*{margin:0;padding:0;box-sizing:border-box}
html,body{background:var(--field);color:var(--ink);font-family:var(--sans);font-size:15px;-webkit-text-size-adjust:100%}
body{
  min-height:100vh;
  background:
    radial-gradient(ellipse at 50% -10%, rgba(198,154,78,.10), transparent 55%),
    radial-gradient(ellipse at 50% 120%, rgba(0,0,0,.6), transparent 60%),
    var(--field);
}
a{color:var(--brass)}
button{font-family:inherit}

/* ── OPERATOR RAIL ── */
#rail{
  position:sticky;top:0;z-index:40;
  display:flex;align-items:center;gap:14px;flex-wrap:wrap;
  padding:8px 14px;
  background:linear-gradient(180deg,#2a2013,#1a140c);
  border-bottom:2px solid var(--brass-lo);
  box-shadow:0 2px 8px rgba(0,0,0,.6);
}
.wordmark{display:flex;align-items:baseline;gap:8px}
.wordmark b{
  font-family:var(--mono);font-size:18px;letter-spacing:1px;font-weight:700;
  color:var(--brass-hi);text-shadow:0 1px 0 #000;
}
.wordmark .sub{font-size:11px;color:var(--brass);letter-spacing:3px;text-transform:uppercase}
.rail-stats{display:flex;gap:14px;flex-wrap:wrap;margin-left:auto;align-items:center}
.stat{display:flex;flex-direction:column;line-height:1.1}
.stat .k{font-size:9px;letter-spacing:1px;color:var(--brass-lo);text-transform:uppercase}
.stat .v{font-family:var(--mono);font-size:14px;color:var(--ink)}
#dot{width:10px;height:10px;border-radius:50%;background:var(--lamp-off);box-shadow:0 0 0 2px #000 inset;flex-shrink:0}
#dot.on{background:var(--green);box-shadow:0 0 8px var(--green)}
#dot.warn{background:var(--amber);box-shadow:0 0 8px var(--amber-glow)}
.online-wrap{display:flex;align-items:center;gap:6px;font-size:11px;color:var(--ink-dim)}
.rail-btns{display:flex;gap:6px;flex-wrap:wrap}
.rbtn{
  background:linear-gradient(180deg,#3a2c18,#241a0e);
  color:var(--brass-hi);border:1px solid var(--brass-lo);border-radius:4px;
  padding:5px 10px;font-size:12px;cursor:pointer;font-family:var(--mono);
  box-shadow:var(--shadow);
}
.rbtn:hover{border-color:var(--brass);color:#fff;background:linear-gradient(180deg,#4a3820,#2c2010)}
.rbtn:active{transform:translateY(1px)}

/* ── LAYOUT ── */
main{max-width:1180px;margin:0 auto;padding:14px;display:flex;flex-direction:column;gap:14px}
.card{
  background:linear-gradient(180deg,var(--panel2),var(--panel));
  border:1px solid var(--line);border-radius:8px;
  box-shadow:inset 0 1px 0 rgba(198,154,78,.06),0 4px 12px rgba(0,0,0,.4);
}
.card>h2{
  font-family:var(--mono);font-size:12px;letter-spacing:2px;text-transform:uppercase;
  color:var(--brass);padding:9px 14px;border-bottom:1px solid var(--line);
  display:flex;align-items:center;gap:8px;
}
.card>h2 .badge{
  margin-left:auto;font-size:11px;color:var(--ink-dim);
  border:1px solid var(--line-hi);border-radius:10px;padding:1px 8px;letter-spacing:1px;
}
.card .body{padding:14px}

/* ── JACK BOARD ── */
#board-wrap{position:relative}
#cords{position:absolute;inset:0;width:100%;height:100%;pointer-events:none;z-index:2;overflow:visible}
#jacks{
  position:relative;z-index:1;
  display:grid;grid-template-columns:repeat(auto-fill,minmax(82px,1fr));gap:10px;
}
.jack{
  position:relative;aspect-ratio:1/1.05;
  background:radial-gradient(circle at 50% 38%,#2a221a 0%,var(--bake) 70%),var(--bake);
  border:1px solid #000;border-radius:7px;
  box-shadow:inset 0 1px 0 rgba(255,255,255,.05),inset 0 -3px 6px rgba(0,0,0,.6),var(--shadow);
  display:flex;flex-direction:column;align-items:center;justify-content:center;gap:6px;
  cursor:pointer;user-select:none;transition:border-color .15s,transform .08s;
}
.jack:hover{border-color:var(--brass-lo)}
.jack:active{transform:translateY(1px)}
.jack .lamp{
  width:16px;height:16px;border-radius:50%;
  background:var(--lamp-off);
  box-shadow:inset 0 1px 2px rgba(0,0,0,.8),inset 0 -1px 1px rgba(255,255,255,.06);
}
.jack .num{font-family:var(--mono);font-size:17px;color:var(--ink);letter-spacing:1px}
/* socket hole decoration behind number */
.jack .hole{
  position:absolute;top:8px;width:10px;height:10px;border-radius:50%;
  background:radial-gradient(circle at 50% 35%,#1a1410,#000 75%);
  box-shadow:inset 0 1px 2px #000;
}
/* states */
.jack.empty{opacity:.5}
.jack.empty .num{color:var(--ink-dim)}
.jack.reg .lamp{background:radial-gradient(circle at 50% 35%,#bfe8b0,var(--green));box-shadow:0 0 6px rgba(123,214,106,.6),inset 0 -1px 2px rgba(0,0,0,.4)}
.jack.dnd{border-color:var(--amber)}
.jack.dnd .lamp{background:radial-gradient(circle at 50% 35%,#ffd98a,var(--amber));box-shadow:0 0 6px var(--amber-glow),inset 0 -1px 2px rgba(0,0,0,.4)}
.jack.call{border-color:var(--amber)}
.jack.call .lamp{background:radial-gradient(circle at 50% 35%,#ffe1a0,var(--amber-glow));box-shadow:0 0 10px var(--amber-glow);animation:pulse 1.1s ease-in-out infinite}
@keyframes pulse{0%,100%{opacity:1;transform:scale(1)}50%{opacity:.55;transform:scale(.86)}}
.jack .badge-dnd{position:absolute;top:4px;right:5px;font-size:8px;color:var(--amber);font-family:var(--mono);letter-spacing:1px}

/* ── PATCH CORD label ── */
.cord-label{font-family:var(--mono);font-size:10px;fill:var(--amber);paint-order:stroke;stroke:#000;stroke-width:3px;stroke-linejoin:round}

/* ── TABLES ── */
table{width:100%;border-collapse:collapse;font-size:13px}
th{text-align:left;font-family:var(--mono);font-size:10px;letter-spacing:1px;text-transform:uppercase;color:var(--brass-lo);padding:6px 8px;border-bottom:1px solid var(--line)}
td{padding:6px 8px;border-bottom:1px solid rgba(58,44,25,.5);font-family:var(--mono)}
tr:last-child td{border-bottom:none}
tbody tr:hover{background:rgba(198,154,78,.05)}
.empty-row td{color:var(--ink-dim);font-family:var(--sans);text-align:center;padding:14px}
.chip{display:inline-block;font-size:10px;font-family:var(--mono);padding:1px 7px;border-radius:9px;border:1px solid;letter-spacing:.5px}
.chip.answered{color:var(--green);border-color:var(--green)}
.chip.busy{color:var(--amber);border-color:var(--amber)}
.chip.cancelled{color:var(--ink-dim);border-color:var(--line-hi)}
.chip.unavailable,.chip.failed{color:var(--red);border-color:var(--red)}
.arrow{color:var(--brass)}

/* ── FORMS / CONTROLS ── */
.field{display:flex;flex-direction:column;gap:3px;margin-bottom:8px}
.field label{font-size:11px;color:var(--brass);letter-spacing:.5px}
input[type=text],input[type=password],input[type=file],select{
  background:#0c0a07;border:1px solid var(--line-hi);border-radius:4px;color:var(--ink);
  font-family:var(--mono);font-size:13px;padding:7px 9px;outline:none;width:100%;
}
input:focus,select:focus{border-color:var(--brass);box-shadow:0 0 0 2px rgba(198,154,78,.18)}
.btn{
  background:linear-gradient(180deg,#3a2c18,#241a0e);color:var(--brass-hi);
  border:1px solid var(--brass-lo);border-radius:4px;padding:7px 14px;font-size:13px;
  cursor:pointer;font-family:var(--mono);box-shadow:var(--shadow);
}
.btn:hover{border-color:var(--brass);color:#fff}
.btn:active{transform:translateY(1px)}
.btn.primary{background:linear-gradient(180deg,#7a5a1e,#5a4116);color:#fff;border-color:var(--brass)}
.btn.danger{background:linear-gradient(180deg,#5a2418,#3a160e);color:#f3b9aa;border-color:#7a3424}
.btn.danger:hover{background:linear-gradient(180deg,#7a3020,#4a1c12);color:#fff}
.btn:disabled{opacity:.4;cursor:not-allowed;filter:grayscale(.6)}
.row{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
.note{font-size:11px;color:var(--ink-dim);margin:4px 0}
.msg{font-size:12px;font-family:var(--mono);min-height:16px;margin-top:4px}
.ok{color:var(--green)}.err{color:var(--red)}.warn{color:var(--amber)}

/* toggle switch */
.toggle{position:relative;display:inline-block;width:46px;height:24px;flex-shrink:0}
.toggle input{opacity:0;width:0;height:0}
.toggle .track{position:absolute;inset:0;background:#0c0a07;border:1px solid var(--line-hi);border-radius:24px;transition:.15s}
.toggle .knob{position:absolute;top:2px;left:2px;width:18px;height:18px;border-radius:50%;background:var(--ink-dim);transition:.15s}
.toggle input:checked+.track{background:rgba(255,176,0,.25);border-color:var(--amber)}
.toggle input:checked+.track .knob{transform:translateX(22px);background:var(--amber);box-shadow:0 0 6px var(--amber-glow)}

/* split grid for groups/forwarding & status panels */
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:14px}
.subhead{font-family:var(--mono);font-size:11px;letter-spacing:1px;text-transform:uppercase;color:var(--brass-lo);margin-bottom:8px}

/* ── MODAL / PANEL OVERLAY ── */
.overlay{
  display:none;position:fixed;inset:0;z-index:60;
  background:rgba(0,0,0,.66);backdrop-filter:blur(2px);
  align-items:flex-start;justify-content:center;padding:24px 14px;overflow:auto;
}
.overlay.show{display:flex}
.modal{
  width:100%;max-width:480px;background:linear-gradient(180deg,#221a10,#19130c);
  border:1px solid var(--brass-lo);border-radius:8px;box-shadow:0 10px 40px rgba(0,0,0,.7);
}
.modal h3{
  font-family:var(--mono);font-size:13px;letter-spacing:1px;color:var(--brass-hi);
  padding:11px 14px;border-bottom:1px solid var(--line);display:flex;align-items:center;gap:8px;
}
.modal h3 .x{margin-left:auto;cursor:pointer;color:var(--ink-dim);font-size:18px;line-height:1}
.modal h3 .x:hover{color:var(--red)}
.modal .mbody{padding:14px;max-height:74vh;overflow:auto}
.hr{border:none;border-top:1px dashed var(--line-hi);margin:12px 0}
.danger-zone{border-top:1px dashed #7a3424;margin-top:12px;padding-top:10px}
.danger-zone .subhead{color:var(--red)}

/* jack detail specific */
#jd-lamp{display:inline-block;width:12px;height:12px;border-radius:50%;background:var(--lamp-off);vertical-align:middle;margin-right:6px}
.kv{display:flex;justify-content:space-between;font-family:var(--mono);font-size:13px;padding:3px 0}
.kv .k{color:var(--brass-lo)}
.fwd-row{display:grid;grid-template-columns:78px 1fr auto;gap:8px;align-items:center;margin-bottom:7px}
.fwd-row label{font-size:11px;color:var(--brass);font-family:var(--mono)}

/* wifi list */
.wifi-net{display:flex;justify-content:space-between;align-items:center;padding:7px 9px;border:1px solid transparent;border-radius:4px;cursor:pointer}
.wifi-net:hover{background:rgba(198,154,78,.06);border-color:var(--line-hi)}
.wifi-ssid{color:var(--ink);font-family:var(--mono)}
.wifi-meta{font-size:11px;color:var(--ink-dim);font-family:var(--mono)}

/* OTA progress */
#ota-prog{display:none;height:14px;border:1px solid var(--line-hi);border-radius:4px;background:#0c0a07;position:relative;margin:8px 0;overflow:hidden}
#ota-bar{height:100%;width:0;background:linear-gradient(90deg,var(--brass-lo),var(--amber));transition:width .15s}
#ota-pct{position:absolute;inset:0;text-align:center;font-size:10px;line-height:14px;font-family:var(--mono);color:#fff;text-shadow:0 0 3px #000}

#toast{
  position:fixed;left:50%;bottom:18px;transform:translateX(-50%) translateY(80px);
  background:#241a0e;border:1px solid var(--brass-lo);border-radius:6px;color:var(--ink);
  padding:9px 16px;font-size:13px;font-family:var(--mono);z-index:90;opacity:0;
  transition:transform .25s,opacity .25s;box-shadow:0 6px 20px rgba(0,0,0,.6);max-width:90vw;
}
#toast.show{transform:translateX(-50%) translateY(0);opacity:1}

.recon{display:none;color:var(--amber);font-size:11px;font-family:var(--mono)}
.recon.show{display:inline}

/* live SIP tracer (Issue #32) */
.trace-screen{
  height:260px;overflow-y:auto;background:#08070a;border:1px solid var(--line-hi);border-radius:4px;
  padding:8px 10px;font-family:var(--mono);font-size:11px;line-height:1.5;color:var(--green);
  white-space:pre-wrap;word-break:break-all;
}
.trace-screen .trc-hdr{color:var(--brass);}
.trace-screen .trc-hdr.out{color:var(--amber);}
.trace-screen .trc-empty{color:var(--ink-dim);font-family:var(--sans)}
.trace-screen .trc-pkt{margin-bottom:8px;padding-bottom:8px;border-bottom:1px dashed var(--line)}
.trace-screen .trc-pkt:last-child{border-bottom:none;margin-bottom:0}
.trace-screen .trc-cmd{color:var(--green);opacity:.8;margin:2px 0 6px}

/* trace command interpreter (Issue #32) */
.term-line{display:flex;align-items:center;gap:6px;margin-top:8px;font-family:var(--mono);font-size:12px}
.term-prompt{color:var(--green);flex-shrink:0}
.term-input{flex:1;min-width:0;background:transparent;border:none;border-bottom:1px solid var(--line-hi);
  color:var(--green);font-family:var(--mono);font-size:12px;padding:3px 0}
.term-input:focus{outline:none;border-bottom-color:var(--amber)}

@media (max-width:720px){
  .grid2{grid-template-columns:1fr}
  #jacks{grid-template-columns:repeat(auto-fill,minmax(70px,1fr));gap:8px}
  .rail-stats{width:100%;margin-left:0;justify-content:space-between}
  .fwd-row{grid-template-columns:64px 1fr}
  .fwd-row .btn{grid-column:2}
}
@media (prefers-reduced-motion:reduce){
  .jack.call .lamp{animation:none}
  *{transition:none!important}
}
</style>
</head>
<body>

<!-- ══ OPERATOR RAIL ══ -->
<div id="rail">
  <div class="wordmark">
    <b>POCKET&middot;DIAL</b><span class="sub">Switchboard</span>
  </div>
  <div class="online-wrap"><span id="dot"></span><span id="online-txt">connecting&hellip;</span><span class="recon" id="recon">&nbsp;reconnecting&hellip;</span></div>
  <div class="rail-stats">
    <div class="stat"><span class="k">Uptime</span><span class="v" id="s-uptime">--:--:--</span></div>
    <div class="stat"><span class="k">Address</span><span class="v" id="s-ip">0.0.0.0:5060</span></div>
)html0"
R"html1(    <div class="stat"><span class="k">Jacks</span><span class="v" id="s-jacks">0/32</span></div>
    <div class="stat"><span class="k">Calls</span><span class="v" id="s-calls">0</span></div>
    <div class="stat"><span class="k">Packets</span><span class="v" id="s-pkts">0</span></div>
  </div>
  <div class="rail-btns">
    <button class="rbtn" onclick="refreshNow()" title="Refresh (F5)">&#8635; Refresh</button>
    <button class="rbtn" onclick="openModal('wifi-modal');scanWifi()" title="WiFi (F9)">&#9783; WiFi</button>
    <button class="rbtn" onclick="openModal('admin-modal')" title="Admin">&#9919; Admin</button>
    <button class="rbtn" onclick="cycleTheme()" id="theme-btn" title="Cycle accent">Amber</button>
    <button class="rbtn" onclick="openModal('help-modal')" title="Help (F1)">? Help</button>
  </div>
</div>

<main>

  <!-- ══ JACK BOARD ══ -->
  <section class="card" id="board-card">
    <h2>&#9737; Jack Board <span class="badge" id="board-cap">0 / 32 lit</span></h2>
    <div class="body" id="board-wrap">
      <svg id="cords"></svg>
      <div id="jacks"></div>
    </div>
  </section>

  <!-- ══ GROUPS & FORWARDING ══ -->
  <section class="card">
    <h2>&#9783; Ring Groups &amp; Forwarding</h2>
    <div class="body">
      <div class="grid2">
        <div>
          <div class="subhead">Ring / Hunt Groups</div>
          <div id="groups-list"></div>
          <hr class="hr">
          <div class="subhead">New / Edit Group</div>
          <div class="field"><label>Group extension</label><input type="text" id="grp-ext" inputmode="numeric" placeholder="e.g. 600"></div>
          <div class="field"><label>Members (comma separated)</label><input type="text" id="grp-members" placeholder="101,102,103"></div>
          <div class="field"><label>Mode</label>
            <select id="grp-mode"><option value="ringall">Ring all</option><option value="hunt">Hunt</option></select>
          </div>
          <div class="row">
            <button class="btn primary" onclick="saveGroup()">Save Group</button>
            <span class="note">Empty members deletes the group.</span>
          </div>
          <div class="msg" id="grp-msg"></div>
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
  </section>

  <!-- ══ CALL LOG ══ -->
  <section class="card">
    <h2>&#9742; Call Log <span class="badge" id="cdr-count">0</span></h2>
    <div class="body" style="padding:0">
      <table>
        <thead><tr><th>Caller</th><th></th><th>Callee</th><th>Result</th><th>Duration</th><th>Age</th></tr></thead>
        <tbody id="cdr-tbody"><tr class="empty-row"><td colspan="6">No calls recorded yet</td></tr></tbody>
      </table>
    </div>
  </section>

  <!-- ══ LIVE SIP TRACE ══ -->
  <section class="card">
    <h2>&#9737; SIP Trace <span class="badge" id="trace-count">off</span></h2>
    <div class="body">
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
  </section>

</main>

<!-- ══ JACK DETAIL MODAL ══ -->
<div class="overlay" id="jack-modal">
  <div class="modal">
    <h3><span id="jd-lamp"></span><span>Jack <span id="jd-num">--</span></span><span class="x" onclick="closeModal('jack-modal')">&times;</span></h3>
    <div class="mbody">
      <div class="kv"><span class="k">State</span><span id="jd-state">&mdash;</span></div>
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
      <div id="admin-setpin" style="display:none">
        <div class="note">No admin PIN set. Create one to protect this device.</div>
        <div class="field"><label>New PIN (min 4 chars)</label><input type="password" id="adm-newpin" inputmode="numeric" autocomplete="off"></div>
        <button class="btn primary" onclick="adminSetPin()">&#9919; Set PIN</button>
      </div>
      <div id="admin-login" style="display:none">
        <div class="note">Admin login required to unlock controls.</div>
        <div class="field"><label>PIN</label><input type="password" id="adm-pin" inputmode="numeric" autocomplete="off"></div>
        <button class="btn primary" onclick="adminLogin()">Login</button>
      </div>
      <div id="admin-loggedin" style="display:none">
        <div class="msg ok">&#9679; Logged in &mdash; admin controls unlocked.</div>
        <div class="row">
          <button class="btn" onclick="toggleChangePin()">Change PIN</button>
          <button class="btn" onclick="adminKeepAlive()">&#9201; Keep open (1h)</button>
          <button class="btn danger" onclick="adminLogout()">Logout</button>
        </div>
        <div id="admin-changepin" style="display:none;margin-top:8px">
          <div class="field"><label>New PIN (min 4 chars)</label><input type="password" id="adm-changepin-val" inputmode="numeric" autocomplete="off"></div>
          <button class="btn primary" onclick="adminSetPin('change')">Save</button>
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
)html1" R"html1b(      <div class="kv"><span class="k">Current mode</span><span id="ap-mode">&mdash;</span></div>
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
      <div class="msg" id="ota-state-msg"></div>
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

<!-- ══ HELP MODAL ══ -->
<div class="overlay" id="help-modal">
  <div class="modal">
    <h3>&#9737; Switchboard Help<span class="x" onclick="closeModal('help-modal')">&times;</span></h3>
    <div class="mbody" style="line-height:1.7;font-size:13px">
      <p style="color:var(--brass);font-family:var(--mono)">POCKET&middot;DIAL &mdash; vintage operator switchboard</p>
      <hr class="hr">
      <p><b>The board.</b> Each tile is an extension jack. A lit green lamp = registered. A pulsing amber lamp = in a call (patched with a cord). An amber ring = Do Not Disturb. A dim recessed tile = empty slot.</p>
      <p style="margin-top:8px"><b>Patch-cords.</b> Active calls are drawn as curved operator cords between the two jacks, labelled with state and running duration.</p>
      <p style="margin-top:8px"><b>Tap a jack</b> to open its panel: address, DND toggle, the three call-forward triggers, and a force-disconnect.</p>
      <hr class="hr">
      <p style="color:var(--brass);font-family:var(--mono)">Shortcuts</p>
      <p><span style="font-family:var(--mono);color:var(--brass-hi)">F1</span> Help &nbsp; <span style="font-family:var(--mono);color:var(--brass-hi)">F5</span> Refresh &nbsp; <span style="font-family:var(--mono);color:var(--brass-hi)">F9</span> WiFi &nbsp; <span style="font-family:var(--mono);color:var(--brass-hi)">Esc</span> Close</p>
    </div>
  </div>
</div>

<div id="toast"></div>

<script>
"use strict";
var statusData={ip:"0.0.0.0",port:5060,uptime:0,clients:[],sessions:[],dnd:[],forwards:[],groups:[],packetsProcessed:0};
var adminState={provisioned:false,authenticated:false};
var otaUploading=false;
var selectedSSID="";
var selectedJack=null;
var failCount=0;
var POOL=32;
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
function toast(msg,cls){var t=$("toast");t.textContent=msg;t.className=cls?("show "+cls):"show";clearTimeout(t._t);t._t=setTimeout(function(){t.className="";},2600);}
function fmtUptime(sec){sec=Math.floor(sec||0);var h=Math.floor(sec/3600),m=Math.floor(sec%3600/60),s=sec%60;function p(n){return(n<10?"0":"")+n;}return p(h)+":"+p(m)+":"+p(s);}
function setMsg(id,txt,cls){var e=$(id);if(e){e.textContent=txt||"";e.className="msg"+(cls?" "+cls:"");}}

/* ── modals ── */
function openModal(id){$(id).classList.add("show");}
function closeModal(id){$(id).classList.remove("show");}
document.addEventListener("click",function(e){if(e.target.classList&&e.target.classList.contains("overlay"))e.target.classList.remove("show");});

/* ── theme accent cycling (amber default / phosphor green) ── */
var THEMES=["amber","phosphor","ice"];
var THEME_VARS={
  amber:{amber:"#ffb000",glow:"#ff9c1a"},
  phosphor:{amber:"#5dff8a",glow:"#33ff66"},
  ice:{amber:"#5ec8ff",glow:"#39a9ff"}
};
var themeIdx=0;
function applyTheme(i){
  themeIdx=((i%THEMES.length)+THEMES.length)%THEMES.length;
  var k=THEMES[themeIdx],v=THEME_VARS[k];
)html1b"
R"html2(  document.documentElement.style.setProperty("--amber",v.amber);
  document.documentElement.style.setProperty("--amber-glow",v.glow);
  var b=$("theme-btn");if(b)b.textContent=k.charAt(0).toUpperCase()+k.slice(1);
  try{localStorage.setItem("pd.theme",k);}catch(e){}
}
function cycleTheme(){applyTheme(themeIdx+1);}
function restoreTheme(){var k="amber";try{k=localStorage.getItem("pd.theme")||"amber";}catch(e){}var i=THEMES.indexOf(k);applyTheme(i>=0?i:0);}

/* ── extension classification from /api/status ── */
function buildIndex(d){
  var idx={};
  (d.clients||[]).forEach(function(c){var n=String(c.number);idx[n]={num:n,addr:c.address||"",reg:true,call:false,state:"",dnd:false};});
  (d.dnd||[]).forEach(function(n){n=String(n);if(!idx[n])idx[n]={num:n,addr:"",reg:false,call:false,state:""};idx[n].dnd=true;});
  (d.sessions||[]).forEach(function(s){
    [s.caller,s.callee].forEach(function(n){n=String(n);if(!idx[n])idx[n]={num:n,addr:"",reg:false,dnd:false};idx[n].call=true;idx[n].state=s.state||"";});
  });
  return idx;
}

/* ── render jack board ── */
function renderBoard(d){
  var idx=buildIndex(d);
  var nums=Object.keys(idx).sort(function(a,b){return (parseInt(a,10)||0)-(parseInt(b,10)||0);});
  var board=$("jacks");
  // Build/refresh tiles. We reuse DOM where possible to avoid churn.
  var html="";
  nums.forEach(function(n){
    var e=idx[n];
    var cls="jack";
    if(e.call)cls+=" call";else if(e.reg)cls+=" reg";else cls+=" empty";
    if(e.dnd)cls+=" dnd";
    html+='<div class="'+cls+'" data-ext="'+esc(n)+'" onclick="openJack(\''+esc(n)+'\')">'
      +'<span class="hole"></span>'
      +(e.dnd?'<span class="badge-dnd">DND</span>':'')
      +'<span class="lamp"></span><span class="num">'+esc(n)+'</span></div>';
  });
  if(!nums.length)html='<div class="note" style="grid-column:1/-1;text-align:center;padding:24px">No extensions seen yet. Register a phone to light a jack.</div>';
  board.innerHTML=html;
  var lit=(d.clients||[]).length;
  $("board-cap").textContent=lit+" / "+POOL+" lit";
  // cords drawn after layout settles
  requestAnimationFrame(function(){drawCords(d);});
}

/* ── SVG patch-cords between caller and callee jacks ── */
function drawCords(d){
  var svg=$("cords");var wrap=$("board-wrap");
  if(!svg||!wrap){return;}
  var wr=wrap.getBoundingClientRect();
  svg.setAttribute("width",wr.width);svg.setAttribute("height",wr.height);
  svg.setAttribute("viewBox","0 0 "+wr.width+" "+wr.height);
  var parts=[];
  (d.sessions||[]).forEach(function(s){
    var a=document.querySelector('.jack[data-ext="'+cssEsc(s.caller)+'"]');
    var b=document.querySelector('.jack[data-ext="'+cssEsc(s.callee)+'"]');
    if(!a||!b)return;
    var ra=a.getBoundingClientRect(),rb=b.getBoundingClientRect();
    var x1=ra.left-wr.left+ra.width/2,y1=ra.top-wr.top+8;
    var x2=rb.left-wr.left+rb.width/2,y2=rb.top-wr.top+8;
    var sag=Math.max(40,Math.abs(x2-x1)*0.32)+24;
    var mx=(x1+x2)/2,my=Math.max(y1,y2)+sag;
    var ringing=(s.state||"").toUpperCase()==="RINGING";
    var col=ringing?"var(--amber-glow)":"var(--amber)";
    parts.push('<path d="M'+x1+' '+y1+' Q'+mx+' '+my+' '+x2+' '+y2+'" fill="none" stroke="'+col+'" stroke-width="3" stroke-linecap="round" opacity="0.85"/>');
    parts.push('<circle cx="'+x1+'" cy="'+y1+'" r="4" fill="'+col+'"/><circle cx="'+x2+'" cy="'+y2+'" r="4" fill="'+col+'"/>');
    var lx=mx,ly=my-6;
    parts.push('<text class="cord-label" x="'+lx+'" y="'+ly+'" text-anchor="middle">'+esc((s.state||"")+" "+(s.duration||""))+'</text>');
  });
  svg.innerHTML=parts.join("");
}
function cssEsc(s){return String(s==null?"":s).replace(/["\\]/g,"\\$&");}

/* ── jack detail panel ── */
function openJack(ext){
  selectedJack=ext;
  var idx=buildIndex(statusData);var e=idx[ext]||{num:ext,addr:"",reg:false,call:false,state:"",dnd:false};
  $("jd-num").textContent=ext;
  var lamp=$("jd-lamp");
  lamp.style.boxShadow="none";
  if(e.call){lamp.style.background="var(--amber-glow)";lamp.style.boxShadow="0 0 8px var(--amber-glow)";}
  else if(e.dnd){lamp.style.background="var(--amber)";}
  else if(e.reg){lamp.style.background="var(--green)";lamp.style.boxShadow="0 0 6px var(--green)";}
  else lamp.style.background="var(--lamp-off)";
  $("jd-state").textContent=e.call?("IN CALL — "+(e.state||"")):(e.dnd?"DND":(e.reg?"REGISTERED":"IDLE / UNREGISTERED"));
  $("jd-addr").textContent=e.addr||"—";
  $("jd-dnd").checked=!!e.dnd;
  // prefill forwarding from status
  var fwd=(statusData.forwards||[]).filter(function(f){return String(f.extension)===String(ext);})[0]||{};
  $("jd-fwd-always").value=fwd.always||"";
  $("jd-fwd-busy").value=fwd.busy||"";
  $("jd-fwd-noanswer").value=fwd.noanswer||"";
  setMsg("jd-msg","");
  openModal("jack-modal");
}
function gateCheck(){if(adminState.provisioned&&!adminState.authenticated){toast("Admin login required","err");openModal("admin-modal");return false;}return true;}

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

)html2" R"html2a(
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
  if($("trace-toggle").checked)startTrace();else stopTrace();
}
// `cmdEcho`, if given, is the "pd> trace on" line to show once the screen has
// been cleared for the new session (so it doesn't get wiped by the clear).
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
  // Cap rendered blocks client-side (independent of the server's ring cap) so a
  // long-running trace session doesn't grow the DOM without bound.
  while(screen.children.length>200){screen.removeChild(screen.children[0]);}
  if(added>0)screen.scrollTop=screen.scrollHeight;
  var shown=screen.querySelectorAll(".trc-pkt").length;
  $("trace-count").textContent=shown+" shown";
}

/* ── trace-screen command interpreter (Issue #32): `trace on` / `trace off` ──
   A minimal line interpreter for the terminal input under the trace screen.
   It does not add a new transport — `trace on`/`trace off` just call the same
   startTrace()/stopTrace() the checkbox uses, so packets still arrive via the
   existing /api/trace poll. Command echoes share the trace-screen's own
   200-block client-side cap (renderTraceAppend), so typing commands can't
   grow the DOM unbounded either. */
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
function post(url,body){
  return fetch(url,{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/x-www-form-urlencoded","X-CSRF":PD_CSRF},body:body})
    .then(function(r){
      if(r.status===401){handleAuthExpired();throw new Error("session expired — please log in");}
      if(r.status===403){throw new Error("rejected (cross-origin or stale security token \u2014 reload the page)");}
      if(!r.ok){throw new Error("HTTP "+r.status);}
      return r.text();
    });
}
function fetchStatus(){
  fetch("/api/status").then(function(r){return r.json();}).then(function(d){
    statusData=d;failCount=0;setOnline(true);updateRail(d);renderBoard(d);renderGroups(d);
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

/* redraw cords on resize (debounced) */
var rsTimer=null;
window.addEventListener("resize",function(){clearTimeout(rsTimer);rsTimer=setTimeout(function(){drawCords(statusData);},120);});

/* ════ ADMIN / AUTH ════ */
function fetchAdminStatus(){
  return fetch("/api/admin/status",{credentials:"same-origin"}).then(function(r){return r.json();}).then(function(d){
    adminState.provisioned=!!d.provisioned;adminState.authenticated=!!d.authenticated;
    renderAdminPanel();applyAuthGating();
    if(adminState.authenticated){fetchApSecurity();fetchRegistrar();}
  }).catch(function(){});
}
function renderAdminPanel(){
  $("admin-loading").style.display="none";
  $("admin-setpin").style.display="none";$("admin-login").style.display="none";
  $("admin-loggedin").style.display="none";
  if(!adminState.provisioned)$("admin-setpin").style.display="block";
  else if(!adminState.authenticated)$("admin-login").style.display="block";
  else $("admin-loggedin").style.display="block";
}
function controlsUnlocked(){return !adminState.provisioned||adminState.authenticated;}
function applyAuthGating(){
  var unlocked=controlsUnlocked();
  ["wifi-connect-btn","wifi-ap-btn","wifi-reset-btn","ota-upload-btn","ota-reboot-btn"].forEach(function(id){var b=$(id);if(b)b.disabled=!unlocked;});
  var wn=$("wifi-admin-note");if(wn)wn.style.display=unlocked?"none":"block";
  var on=$("ota-gate-note");if(on)on.style.display=unlocked?"none":"block";
  var of=$("ota-file");if(of)of.disabled=!unlocked;
}
function handleAuthExpired(){adminState.authenticated=false;renderAdminPanel();applyAuthGating();setMsg("admin-msg","Session expired — please log in.","err");}
function adminSetPin(mode){
  var inputId=mode==="change"?"adm-changepin-val":"adm-newpin";
  var pin=$(inputId).value;
  if(!pin||pin.length<4){setMsg("admin-msg","PIN must be at least 4 characters.","err");return;}
  fetch("/api/admin/set-pin",{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/x-www-form-urlencoded"},body:"pin="+encodeURIComponent(pin)})
    .then(function(r){
      if(r.status===401){handleAuthExpired();return;}
)html2a"
R"html3(      if(r.status===400){setMsg("admin-msg","Invalid PIN (min 4 chars).","err");return;}
      if(!r.ok){setMsg("admin-msg","Failed (HTTP "+r.status+").","err");return;}
      $(inputId).value="";$("admin-changepin").style.display="none";
      setMsg("admin-msg","Admin PIN updated.","ok");fetchAdminStatus();
    }).catch(function(e){setMsg("admin-msg","Error: "+e.message,"err");});
}
/* post() resolves to the raw response text, so the AP handlers parse it here. */
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
    /* textContent throughout: MAC and extension come off the wire from a phone,
       so they are never interpolated as HTML. */
    var tdE=document.createElement("td");tdE.textContent=x.extension||"\u2014";
    var tdM=document.createElement("td");tdM.textContent=x.mac||"\u2014";
    var tdS=document.createElement("td");
    tdS.textContent=(x.state==="secured"?"secured":"learned")+(x.online?" \u00b7 online":"");
    var tdA=document.createElement("td");
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
      /* 409 = switching to secure with nothing secured yet would reject every
         phone. Make the operator say so explicitly rather than silently doing it. */
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
  var pin=$("adm-pin").value;if(!pin){setMsg("admin-msg","Enter your PIN.","err");return;}
  fetch("/api/admin/login",{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/x-www-form-urlencoded"},body:"pin="+encodeURIComponent(pin)})
    .then(function(r){
      $("adm-pin").value="";
      if(r.status===401){setMsg("admin-msg","Incorrect PIN.","err");return;}
      if(r.status===429){setMsg("admin-msg","Locked — wait a minute.","err");return;}
      if(r.status===409){setMsg("admin-msg","No PIN set yet.","err");fetchAdminStatus();return;}
      if(!r.ok){setMsg("admin-msg","Login failed (HTTP "+r.status+").","err");return;}
      /* The login response carries this session's CSRF token so a fetch()-based
         login can start making mutating calls immediately. */
      r.json().then(function(d){if(d&&d.csrf){PD_CSRF=d.csrf;}}).catch(function(){});
      setMsg("admin-msg","Logged in.","ok");toast("Admin unlocked","ok");fetchAdminStatus();
    }).catch(function(e){setMsg("admin-msg","Error: "+e.message,"err");});
}
function adminLogout(){
  fetch("/api/admin/logout",{method:"POST",credentials:"same-origin"}).then(function(){setMsg("admin-msg","Logged out.","warn");fetchAdminStatus();}).catch(function(){});
}
function adminKeepAlive(){
  fetch("/api/admin/keepalive",{method:"POST",credentials:"same-origin"}).then(function(r){
    if(r.status===401){handleAuthExpired();return;}
    if(!r.ok){setMsg("admin-msg","Failed (HTTP "+r.status+").","err");return;}
    setMsg("admin-msg","Dashboard will stay open for 1 more hour.","ok");
  }).catch(function(e){setMsg("admin-msg","Error: "+e.message,"err");});
}
function toggleChangePin(){var cp=$("admin-changepin");cp.style.display=cp.style.display==="block"?"none":"block";if(cp.style.display==="block")$("adm-changepin-val").focus();}

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
  var st=$("wifi-status");st.textContent="Scanning…";st.style.color="var(--amber)";
  fetch("/api/wifi/scan").then(function(r){return r.json();}).then(function(d){
    var nets=d.networks||[];st.textContent="Found "+nets.length+" networks";st.style.color="var(--green)";
    renderWifi(nets);
  }).catch(function(e){st.textContent="Scan failed: "+e.message;st.style.color="var(--red)";});
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
  var st=$("wifi-status");st.textContent="Connecting to "+selectedSSID+"…";st.style.color="var(--amber)";
  post("/api/wifi/connect","ssid="+encodeURIComponent(selectedSSID)+"&password="+encodeURIComponent($("wifi-pw").value))
    .then(function(){st.textContent="Connected to "+selectedSSID+"!";st.style.color="var(--green)";cancelWifiConnect();toast("WiFi connected","ok");})
    .catch(function(e){st.textContent="Failed: "+e.message;st.style.color="var(--red)";});
}
function startApMode(){
  var st=$("wifi-status");st.textContent="Enabling AP Mode…";st.style.color="var(--amber)";
  fetch("/api/wifi/mode_ap",{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/x-www-form-urlencoded"}})
    .then(function(r){if(r.status===401){handleAuthExpired();throw new Error("session expired");}return r.json();})
    .then(function(){st.textContent="AP mode set! Rebooting…";st.style.color="var(--green)";})
    .catch(function(e){st.textContent="Failed: "+e.message;st.style.color="var(--red)";});
}
function holdConfigMode(){
  fetch("/api/configuring",{method:"POST"}).then(function(r){return r.json();})
    .then(function(d){toast(d.message||"Setup mode held.","ok");}).catch(function(e){toast("Error: "+e.message,"err");});
}
function factoryReset(){
  if(!confirm("Factory reset erases saved Wi-Fi config and reboots into captive-portal setup. Continue?"))return;
  var st=$("wifi-status");st.textContent="Factory resetting…";st.style.color="var(--red)";
  fetch("/api/factory-reset",{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/x-www-form-urlencoded"},body:"confirm=ERASE"})
    .then(function(r){if(r.status===401){handleAuthExpired();throw new Error("session expired");}return r.json();})
    .then(function(d){toast(d.message||"Rebooting…","warn");}).catch(function(e){toast("Error: "+e.message,"err");});
}

/* ── keyboard shortcuts ── */
document.addEventListener("keydown",function(e){
  if(e.key==="F1"){e.preventDefault();openModal("help-modal");}
  else if(e.key==="F5"){e.preventDefault();refreshNow();}
  else if(e.key==="F9"){e.preventDefault();openModal("wifi-modal");scanWifi();}
  else if(e.key==="Escape"){["jack-modal","admin-modal","wifi-modal","help-modal"].forEach(function(id){closeModal(id);});}
});
["adm-newpin","adm-changepin-val"].forEach(function(id){var el=$(id);if(el)el.addEventListener("keydown",function(e){if(e.key==="Enter")adminSetPin(id==="adm-changepin-val"?"change":undefined);});});
(function(){var el=$("adm-pin");if(el)el.addEventListener("keydown",function(e){if(e.key==="Enter")adminLogin();});})();

/* ── init ── */
restoreTheme();
fetchStatus();fetchCdr();fetchAdminStatus();fetchOtaStatus();
setInterval(fetchStatus,2000);
setInterval(fetchCdr,5000);
setInterval(fetchAdminStatus,15000);
setInterval(function(){if(!otaUploading)fetchOtaStatus();},15000);
</script>
</body>
</html>
)html3"
;

#endif // INDEX_HTML_H
