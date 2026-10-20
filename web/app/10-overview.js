/* ════ MAIN (overview): annunciator, signal-path bus, readouts, jack board, recent calls ════
   Core (00-core.js) owns fetchStatus, fetchAdminStatus, fetchCdr, fetchOtaStatus,
   updateRail, setOnline, setupBanner, applyE911 and applyEmergencyRoute, and the shell
   (index.html) holds the alarm bar and banners. This file reads core signals only:
   sig.status (core fetchStatus calls renderBoard), sig.cdr, sig.ota, sig.admin, sig.nav,
   and core failCount (two status polls in a row failed). It adds the SBC-mode and
   E911-notify reads, which run on login state and on visit. */

var ovPktHistory=new Array(24).fill(0);
var ovLastPkts=null;
var ovLastDelta=0;
var OV_WAIT="· WAIT",OV_IDLE="· IDLE",OV_NA="· N/A",OV_CLEAR="· CLEAR",OV_NODATA="◆ NO DATA";

function ovSetText(id,txt){
  var e=$(id);
  if(e&&e.textContent!==txt)e.textContent=txt;
}
function ovSetClass(id,cls){
  var e=$(id);
  if(e&&e.className!==cls)e.className=cls;
}

/* ── extension classification from /api/status ──
   One entry per extension seen this poll, merged from clients (registration),
   dnd, sessions (call state, with whom) and parkedCalls (self-park model). */
function buildIndex(d){
  var idx={};
  var ensure=n=>{
    n=String(n);
    if(!idx[n])idx[n]={num:n,addr:"",reg:false,dnd:false,voicemail:false,sessionState:"",peer:"",duration:"",parked:false,parkedBy:"",orbit:""};
    return idx[n];
  };
  (d.clients||[]).forEach(c=>{var e=ensure(c.number);e.reg=true;e.addr=c.address||"";});
  (d.dnd||[]).forEach(n=>{ensure(n).dnd=true;});
  (d.voicemail||[]).forEach(n=>{ensure(n).voicemail=true;});
  (d.sessions||[]).forEach(s=>{
    var a=ensure(s.caller),b=ensure(s.callee);
    a.sessionState=s.state||"";a.peer=String(s.callee);a.duration=s.duration||"";
    b.sessionState=s.state||"";b.peer=String(s.caller);b.duration=s.duration||"";
  });
  (d.parkedCalls||[]).forEach(p=>{
    var e=ensure(p.parkedExt);e.parked=true;e.parkedBy=p.parker;e.orbit=p.orbit;
  });
  return idx;
}

/* State priority: parked, then live session state, then registration. Busy,
   Cancel and Bye are ordinary teardown states and must not override the base
   idle/unreg class; Unavailable is the one exception and shows as alert. */
function jackStateOf(e){
  if(e.parked)return "parked";
  var st=e.sessionState;
  if(st==="Invited")return "ringing";
  if(st==="Connected"||st==="Unknown")return "active";
  if(st==="Unavailable")return "alert";
  if(e.reg)return "idle";
  return "unreg";
}

/* Chip text is glyph + word; the .st CSS adds the brackets. cls: "live" for live traffic, "p1" for fault. */
function jackChip(e,state){
  if(state==="active")return {t:"▲ "+(e.duration||"ACTIVE"),c:"live"};
  if(state==="ringing")return {t:"◆ RINGING",c:"live"};
  if(state==="parked")return {t:"■ PARK "+(e.orbit||""),c:""};
  if(state==="alert")return {t:"◆ UNAVAIL",c:"p1"};
  if(state==="idle")return {t:"· IDLE",c:""};
  return {t:"■ UNREG",c:""};
}

/* ── jack board: core fetchStatus calls this on every poll ── */
function renderBoard(d){
  var idx=buildIndex(d);
  var nums=Object.keys(idx).sort((a,b)=>{return (parseInt(a,10)||0)-(parseInt(b,10)||0);});
  var board=$("jacks");
  /* board.textContent below destroys every jack button. Remember the focused
     jack so a keyboard user is not dumped back to <body> on every poll tick. */
  var act=document.activeElement;
  var keepExt=(act&&board.contains(act)&&act.dataset)?act.dataset.ext:null;
  board.textContent="";
  if(!nums.length){
    var empty=mk("div");
    empty.className="note empty-board";
    empty.textContent=(d.rosterVisible===false)
      ?(String(d.clientCount||0)+(d.clientCount===1?' phone':' phones')+' registered. Log in to see them.')
      :'No extensions seen yet. Register a phone to light a jack.';
    board.appendChild(empty);
  }
  nums.forEach(n=>{
    var e=idx[n];
    var state=jackStateOf(e);
    var b=mk("button");
    b.type="button";
    b.className="jack state-"+state;
    b.dataset.ext=n;
    b.addEventListener("click",()=>{nav.show("extensions");});
    var ring=mk("span");
    ring.className="ring";
    ring.setAttribute("aria-hidden","true");
    var led=mk("span");
    led.className="led";
    led.setAttribute("aria-hidden","true");
    ring.appendChild(led);
    var dnd=null;
    if(e.dnd){
      dnd=mk("span");
      /* DND is an operator setting: grey chip, st adds the brackets. */
      dnd.className="st";
      dnd.textContent="· DND";
    }
    var lab=mk("span");
    lab.className="label";
    lab.textContent=n;
    var sub=mk("span");
    var chip=jackChip(e,state);
    sub.className="sublabel st"+(chip.c?" "+chip.c:"");
    sub.textContent=chip.t;
    b.appendChild(ring);
    b.appendChild(lab);
    b.appendChild(sub);
    if(dnd)b.appendChild(dnd);
    board.appendChild(b);
  });
  if(keepExt!==null){
    var same=null;
    board.querySelectorAll(".jack").forEach(j=>{if(j.dataset.ext===keepExt)same=j;});
    if(same)same.focus();
  }
  ovSetText("ov-jacks",String(d.rosterVisible===false?(d.clientCount||0):(d.clients||[]).length));
  ovSetText("board-cap",String(nums.length));
}

/* ── packet sparkline: rolling per-poll THROUGHPUT (delta of the cumulative counter) ── */
function ovPushPacketSample(current){
  var delta=0;
  if(ovLastPkts!==null){delta=current-ovLastPkts;if(delta<0)delta=0;}
  ovLastPkts=current;
  ovLastDelta=delta;
  ovPktHistory.shift();ovPktHistory.push(delta);
  ovDrawSparkline();
  ovSetText("ov-pkts",current.toLocaleString());
}

function ovDrawSparkline(){
  var max=Math.max.apply(null,ovPktHistory.concat([1]));
  var w=70,h=20;
  var pts=ovPktHistory.map((v,i)=>{return (i/(ovPktHistory.length-1))*w+","+(h-(v/max)*h);}).join(" ");
  var el=$("sparkline");
  if(el){el.setAttribute("points",pts);el.classList.toggle("live",ovLastDelta>0);}
}

/* ── annunciator tile map ──
   A tile exists only where a firmware field drives it (brief 7b, 2026-10-17: a tile with no data
   source is omitted, never shown as N/A). The has() predicate says whether this response carries the tile's
   field; a tile whose field is absent is hidden once its source has answered, and shown again if
   a later poll carries it. Sources (src/Helpers/HttpServer.cpp):
   status = GET /api/status (sendApiStatus), admin = GET /api/admin/status (sendApiAdminStatus),
   ota = GET /api/ota/status (sendApiOtaStatus).
   HEAP   status largestFreeBlockInternal: under 16384 B is LOW (P2), under 4096 B is FAULT (P1).
          Both floors are UI choices, not firmware constants. The host build sends 0 with
          resetReason "n/a" (no heap_caps), so the tile is hidden there.
   POOL   status l2Tx: FAULT (P1) only when the pool is in use AND has no frame free now, i.e.
          poolAvailable 0 with poolAllocations above 0. poolAvailable alone is not enough:
          DmaFramePool::available() returns 0 while the pool is uninitialised (ESP: null queue,
          DmaFramePool.cpp:170-174; host: s_top 0 before the first acquire, :177-178), and the pool
          is only built on first acquire or an explicit init (:96-99, :113-116). The desktop build
          reports {poolAllocations:0, poolAvailable:0, poolSize:6}: not in use, not exhausted.
          An allocation count above 0 proves the pool exists, so 0 free then means every frame is
          lent out. Any of msgPoolRefusals, vpeerPoolRefusals, rtpTxPoolRefused, l2Tx.poolExhaustions
          above 0 is REFUSED (P2); poolExhaustions counts refused acquires (:108, :125). Those four
          are counts since boot; only a reboot clears them. l2Tx is emitted on both platforms
          (HttpServer.cpp:2877-2883). The alarm bar (00-core.js alarmsNow) reads only the refusal
          counters, never poolAvailable, so it has no exhausted-now predicate to keep in step.
   E911   status emergencyRoute "none" is NO ROUTE (P1); "anchor" with e911Configured false is
          NO NOTIFY (P2); "anchor" otherwise is ANCHOR. The field is omitted with no engine, which
          hides the tile.
   OTA    ota (fetchOtaStatus): fetchError is NO DATA; pendingVerify is PENDING (P2); inProgress is
          UPDATING (P2); otaSupported false is NO OTA (the route answers, the build cannot update).
   SETUP  admin needsSetup is NEEDED (P2).
   NVS    status cdrPersistFailures or cdrLoadFailures above 0 is FAILED (P2). This covers only the
          CDR ring's NVS namespace (src/SIP/CdrRing.cpp), not NVS as a whole.
   WDT    status resetReason ending in _WDT (INT_WDT, TASK_WDT, OTHER_WDT) is WDT RESET (P2). It is
          latched at boot and stays until the next boot. The host build sends "n/a", which hides
          the tile.
   Not built (no field in any of the three responses): SIP BIND (port is a literal, there is no
   bind state), ANCHOR (no anchor link field; emergencyRoute is the E911 route only), NTP. */
var OV_TILES=[
  {id:"heap",src:"status",
   has:function(d){return d.resetReason!=="n/a"&&typeof d.largestFreeBlockInternal==="number";},
   f:function(d){
    if(d.largestFreeBlockInternal<4096)return ["p1","◆ FAULT"];
    if(d.largestFreeBlockInternal<16384)return ["p2","▲ LOW"];
    return ["",OV_IDLE];
  }},
  {id:"pool",src:"status",
   has:function(d){return !!d.l2Tx;},
   f:function(d){
    if(d.l2Tx.poolAvailable===0&&(d.l2Tx.poolAllocations||0)>0)return ["p1","◆ FAULT"];
    var refused=(d.msgPoolRefusals||0)+(d.vpeerPoolRefusals||0)+(d.rtpTxPoolRefused||0)+(d.l2Tx.poolExhaustions||0);
    if(refused>0)return ["p2","▲ REFUSED"];
    return ["",OV_IDLE];
  }},
  {id:"e911",src:"status",
   has:function(d){return typeof d.emergencyRoute==="string";},
   f:function(d){
    if(d.emergencyRoute==="none")return ["p1","◆ NO ROUTE"];
    if(d.emergencyRoute==="anchor")return d.e911Configured===false?["p2","▲ NO NOTIFY"]:["",window.PD_E911_ANCHOR||"· ANCHOR"];
    return ["",OV_NA];
  }},
  {id:"ota",src:"ota",f:function(o){
    if(o.fetchError)return ["p1",OV_NODATA];
    if(o.pendingVerify===true)return ["p2","▲ PENDING"];
    if(o.inProgress===true)return ["p2","▲ UPDATING"];
    if(o.otaSupported===false)return ["","· NO OTA"];
    return ["",OV_IDLE];
  }},
  {id:"wdt",src:"status",
   has:function(d){return typeof d.resetReason==="string"&&d.resetReason!=="n/a";},
   f:function(d){
    return /_WDT$/.test(d.resetReason)?["p2","▲ WDT RESET"]:["",OV_CLEAR];
  }},
  {id:"setup",src:"admin",
   has:function(a){return typeof a.needsSetup==="boolean";},
   f:function(a){
    return a.needsSetup===true?["p2","▲ NEEDED"]:["",OV_IDLE];
  }},
  {id:"nvs",src:"status",
   has:function(d){return typeof d.cdrPersistFailures==="number"||typeof d.cdrLoadFailures==="number";},
   f:function(d){
    return ((d.cdrPersistFailures||0)>0||(d.cdrLoadFailures||0)>0)?["p2","▲ FAILED"]:["",OV_IDLE];
  }}
];

/* state: "" nominal, "p1" fault, "p2" warning, "live" active traffic */
function ovTile(name,state,txt){
  if(!$("tile-"+name))return;
  ovSetClass("tile-"+name,"tile"+(state==="p1"?" p1":state==="p2"?" p2":""));
  ovSetClass("st-"+name,"st"+(state==="live"?" live":state==="p1"?" p1":state==="p2"?" p2":""));
  ovSetText("st-"+name,txt);
}

function ovShowTile(name,on){
  var e=$("tile-"+name);
  if(e&&e.hidden===!!on)e.hidden=!on;
}

/* One pass over the table. A tile waits (visible) until its source answers, then is hidden when the
   response has no field for it. A throwing rule shows as ERROR on its own tile and does not stop the others. */
function ovRenderTiles(){
  var d=sig.status.get(),a=sig.admin.get(),o=sig.ota.get();
  OV_TILES.forEach(t=>{
    var src=t.src==="ota"?o:t.src==="admin"?a:d;
    if(!src){ovShowTile(t.id,true);ovTile(t.id,"",OV_WAIT);return;}
    if(t.src==="status"&&failCount>=2){ovTile(t.id,"p1",OV_NODATA);return;}
    var present=true;
    try{present=!t.has||t.has(src);}catch(e){present=true;}
    ovShowTile(t.id,present);
    if(!present)return;
    var r;
    try{r=t.f(src);}catch(e){r=["p2","▲ ERROR"];}
    ovTile(t.id,r[0],r[1]);
  });
}

/* ── signal-path bus: live values in wells; a line goes cyan only while its traffic is live ── */
function ovLive(id,on){
  var e=$(id);
  if(e)e.classList.toggle("live",!!on);
}

function ovRenderBus(d){
  ovSetText("ov-bus-rx",(d.packetsProcessed||0).toLocaleString());
  ovSetText("ov-bus-drop",(d.packetsDropped||0).toLocaleString());
  ovSetText("ov-bus-sess",String(d.sessionCount||0));
  ovSetText("ov-bus-park",String(d.parkedCount||0));
  ovSetText("ov-bus-reg",String(d.clientCount||0));
  ovSetText("ov-bus-dnd",String((d.dnd||[]).length));
  ovLive("bus-a",ovLastDelta>0);
  ovLive("bus-b",(d.sessionCount||0)>0);
}

/* ── call-log summary: sig.cdr is set by core fetchCdr ({auth, msg, recs}); the list is in Live console ── */
function ovRenderCdr(c){
  if(!c)return;
  var recs=c.auth?(c.recs||[]):[];
  var answered=recs.filter(r=>{return String(r.result||"").toLowerCase()==="answered";}).length;
  ovSetText("cdr-count",String(recs.length));
  ovSetText("cdr-summary",recs.length?(answered+" answered · "+(recs.length-answered)+" other"):"");
  ovSetText("cdr-note",!c.auth?(c.msg||"Log in to view the call log"):c.msg?c.msg:recs.length?"The list is in Live console.":"No calls recorded yet");
}

/* ── firmware cells: sig.ota is set by core fetchOtaStatus. Partition is plain text, verify is a chip. ── */
function ovRenderOta(o){
  if(!o)return;
  /* A build profile (05-sbc.js) may pin the Verify cell to its own plain text (SBC: host-tested only). */
  if(window.PD_VERIFY){
    ovSetText("ov-fw-verify",window.PD_VERIFY);
    ovSetClass("ov-fw-verify","");
    if(o.fetchError){ovSetText("ov-fw-part","unavailable: "+o.fetchError);return;}
    ovSetText("ov-fw-part",String(o.runningPartition||"unknown"));
    return;
  }
  if(o.fetchError){
    ovSetText("ov-fw-part","unavailable: "+o.fetchError);
    ovSetText("ov-fw-verify",OV_NA);
    ovSetClass("ov-fw-verify","st");
    return;
  }
  ovSetText("ov-fw-part",String(o.runningPartition||"unknown"));
  var pend=o.pendingVerify===true;
  ovSetText("ov-fw-verify",pend?"▲ PENDING":"· NONE PENDING");
  ovSetClass("ov-fw-verify",pend?"st p2":"st");
}

/* httpMethod resolves with the parsed object; accept text too. A body that is not
   JSON throws, so the cell shows "unavailable" rather than a false value. */
function ovBody(r){
  if(typeof r!=="string")return r||{};
  return JSON.parse(r);
}

function ovRenderSbc(s){
  var on=s.enabled===true||s.enabled===1||s.enabled==="1"||s.enabled==="true";
  ovSetText("ov-mode",on?("SBC on, route "+s.route+" (max "+s.maxRoute+")"):"SBC off");
}

/* The well holds the count only; words go in the note beside it. An empty list is P2 (nobody on site is notified). */
function ovRenderNotify(c){
  var list=String(c.notifyExts||"").split(/[\s,]+/).filter(Boolean);
  var n=list.length;
  ovSetText("ov-notify",String(n));
  ovSetText("ov-notify-note",n?"":"NONE SET: nobody on site is notified");
  ovSetClass("ov-notify",n?"well":"well p2");
}

/* SBC mode and the E911 notify list need a session. Runs on login-state change and on
   visit, not on the 2 s poll. */
function fetchOverview(){
  if(!adminState.loggedIn||adminState.needsSetup){
    ovSetText("ov-mode","log in to view");
    ovSetText("ov-notify","—");
    ovSetText("ov-notify-note","log in to view");
    ovSetClass("ov-notify","well");
    return;
  }
  httpMethod("GET","/api/sbc-mode").then(r=>{ovRenderSbc(ovBody(r));}).catch(e=>{ovSetText("ov-mode","unavailable: "+e.message);});
  httpMethod("GET","/api/e911-config").then(r=>{ovRenderNotify(ovBody(r));}).catch(e=>{
    ovSetText("ov-notify","—");
    ovSetText("ov-notify-note","unavailable: "+e.message);
    ovSetClass("ov-notify","well");
  });
}

/* manual refresh (the Refresh button) */
function refreshNow(){
  fetchStatus();
  fetchCdr();
  fetchOverview();
  ui.toast("Refreshed","ok");
}

/* ── subscriptions (core store: effect runs now and on every set) ── */
store.effect(()=>{
  var d=sig.status.get();
  if(d)ovPushPacketSample(d.packetsProcessed||0);
});
store.effect(()=>{var d=sig.status.get();if(d)ovRenderBus(d);});
store.effect(()=>{ovRenderTiles();});
store.effect(()=>{ovRenderCdr(sig.cdr.get());});
store.effect(()=>{ovRenderOta(sig.ota.get());});
store.effect(()=>{sig.admin.get();fetchOverview();});
store.effect(()=>{if(sig.nav.get()==="overview")fetchOverview();});

