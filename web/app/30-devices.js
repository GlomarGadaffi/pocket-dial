/* 30-devices: registrar (Learn mode, adopted rows, forget), SIP PnP, zero-touch claim window.
   Core (00-core.js) owns httpMethod, post, setMsg, ui, adminState and nav. This file only calls them.
   Secure is not offered: it needs a SIP password, which this UI cannot set. */

function devParse(t){
  if(typeof t==="string"){try{return JSON.parse(t);}catch(e){return {};}}
  return t||{};
}


function devGate(msgId){
  if(canWrite())return true;
  setMsg(msgId,adminState.needsSetup?"Finish the admin setup first.":"Log in before changing devices.","");
  return false;
}

function devSet(id,v){
  var e=$(id);
  if(e)e.textContent=(v===undefined||v===null||v==="")?"\u2014":String(v);
}

function devCell(tr,v){
  var td=mk("td");
  td.textContent=(v===undefined||v===null||v==="")?"\u2014":String(v);
  tr.appendChild(td);
}

function devEmptyRow(body,cols,text){
  var tr=mk("tr");
  var td=mk("td");
  td.colSpan=cols;
  td.textContent=text;
  tr.appendChild(td);
  body.appendChild(tr);
}

/* Runs when Devices is shown and when the session changes. Nothing is fetched before a session exists. */
function devicesShown(){
  if(!canWrite()){
    setMsg("reg-msg","Log in to view devices.","");
    return;
  }
  setMsg("reg-msg","","");
  devFetchRegistrar();
  devFetchPnp();
  devFetchZeroTouch();
}

/* ---- Registration (Learn) ---- */

function devFetchRegistrar(){
  if(!canWrite())return Promise.resolve();
  return httpMethod("GET","/api/registrar",null)
    .then(t=>{renderRegistrar(devParse(t));})
    .catch(e=>{setMsg("reg-msg","Could not read devices ("+e.message+").",msgCls(e));});
}

function renderRegistrar(d){
  d=d||{};
  var mode=d.mode||"unknown";
  $("reg-mode-cur").textContent=(d.attached===false)?"(SIP engine not attached yet)":mode;
  if(d.attached!==false&&mode!=="unknown"){$("reg-mode").value=mode;}
  var body=$("reg-roster-body");
  body.textContent="";
  var devs=d.devices||[];
  var learned=0;
  devs.forEach(x=>{if(x.state!=="secured")learned++;});
  $("reg-forget-all").setAttribute("aria-disabled",learned?"false":"true");
  if(!devs.length){
    devEmptyRow(body,4,(mode==="learn")
      ? "No phones adopted yet. Register one now and it will appear here."
      : "No phones adopted. Switch to Learn mode to onboard them.");
    return;
  }
  devs.forEach(x=>{
    var tr=mk("tr");
    devCell(tr,x.extension);
    devCell(tr,x.mac);
    var tdS=mk("td");
    var sec=x.state==="secured";
    tdS.textContent=(sec?"secured":"learned")+(sec?"":x.shared?" \u00b7 shared":x.locked?" \u00b7 locked":" \u00b7 unlocked")+(x.online?" \u00b7 online":"");
    tr.appendChild(tdS);
    var tdA=mk("td");
    if(!sec){
      var b=mk("button");
      b.type="button";
      b.className="btn";
      b.textContent="Secure";
      b.title="Needs a SIP password, which this UI cannot set";
      b.disabled=true;
      b.setAttribute("aria-describedby","reg-secure-why");
      tdA.appendChild(b);
    }
    var f=mk("button");
    f.type="button";
    f.className="btn";
    f.textContent="[ ARM ] Forget";
    f.setAttribute("aria-label","[ ARM ] Forget "+x.mac);
    f.onclick=()=>{devRegistrarAction("forget",x.mac,f);};
    tdA.appendChild(f);
    tr.appendChild(tdA);
    body.appendChild(tr);
  });
}

function devSaveMode(){
  if(!devGate("reg-msg"))return;
  var mode=$("reg-mode").value;
  post("/api/registrar","mode="+encodeURIComponent(mode))
    .then(t=>{
      renderRegistrar(devParse(t));
      setMsg("reg-msg","Registration mode is now "+mode+".","ok");
    })
    .catch(fm("reg-msg"));
}

/* Forget drops the record and the phone is re-adopted on its next registration: its row button is ARM then EXEC. */
function devRegistrarAction(action,target,btn){
  if(!devGate("reg-msg"))return;
  var send=()=>{
    post("/api/registrar/device","action="+encodeURIComponent(action)+"&target="+encodeURIComponent(target))
      .then(t=>{
        renderRegistrar(devParse(t));
        setMsg("reg-msg",(action==="secure"?"Extension secured.":"Device forgotten."),"ok");
      }).catch(fm("reg-msg"));
  };
  if(action==="forget")ui.arm(btn,"Forget",send);else send();
}

function devForgetLearned(){
  if(!devGate("reg-msg"))return;
  if($("reg-forget-all").getAttribute("aria-disabled")==="true")return;
  ui.arm($("reg-forget-all"),"Forget all",()=>{
    post("/api/registrar/forget-learned","").then(t=>{
      renderRegistrar(devParse(t));
      setMsg("reg-msg","Learned devices forgotten.","ok");
    }).catch(fm("reg-msg"));
  });
}

/* ---- SIP PnP ---- */

function devFetchPnp(){
  if(!canWrite())return Promise.resolve();
  return httpMethod("GET","/api/pnp",null)
    .then(t=>{devRenderPnp(devParse(t));})
    .catch(e=>{setMsg("pnp-msg","Could not read PnP state ("+e.message+").",msgCls(e));});
}

function devRenderPnp(d){
  d=d||{};
  var on=d.attached!==false;
  var mode=d.mode||"unknown";
  devSet("pnp-mode-cur",on?mode:"(SIP engine not attached yet)");
  if(on&&mode!=="unknown"){$("pnp-mode").value=mode;}
  devPnpLabel();
  devSet("pnp-listening",on?(d.listening?"yes":"no"):null);
  devSet("pnp-errno",on?(d.socketErrno||0):null);
  devSet("pnp-netmask",on?d.netmask:null);
  var rx=(on&&d.rx)||{};
  devSet("pnp-rx-dgram",on?rx.datagrams:null);
  devSet("pnp-rx-off",on?rx.offSubnet:null);
  devSet("pnp-rx-notpnp",on?rx.notPnp:null);
  devSet("pnp-rx-answered",on?rx.answered:null);
  var body=$("pnp-body");
  body.textContent="";
  var devs=(on&&d.devices)||[];
  if(!devs.length){
    devEmptyRow(body,8,"No phones seen yet.");
    return;
  }
  /* Vendor, model and version are text sent by the phone: textContent only. */
  devs.forEach(x=>{
    var tr=mk("tr");
    devCell(tr,x.mac);
    devCell(tr,x.vendor);
    devCell(tr,x.model);
    devCell(tr,x.version);
    devCell(tr,x.ip);
    devCell(tr,x.seen);
    devCell(tr,x.lastSeen);
    devCell(tr,x.notified?"yes":"no");
    body.appendChild(tr);
  });
}

/* Turning Provision on makes this board answer phones' provisioning requests (another PBX on the LAN may
   answer too), so that one change is ARM then EXEC on the Apply button; the other modes apply at once. */
function devSavePnp(){
  if(!devGate("pnp-msg"))return;
  var mode=$("pnp-mode").value;
  var was=$("pnp-mode-cur").textContent;
  var send=()=>{
    post("/api/pnp","mode="+encodeURIComponent(mode))
      .then(t=>{
        devRenderPnp(devParse(t));
        setMsg("pnp-msg","PnP mode is now "+mode+".","ok");
      }).catch(fm("pnp-msg"));
  };
  if(mode==="provision"&&was!=="provision")ui.arm($("pnp-apply"),"Turn on provisioning",send);else send();
}
function devPnpLabel(){
  var b=$("pnp-apply"),on=$("pnp-mode").value==="provision"&&$("pnp-mode-cur").textContent!=="provision";
  ui.disarm(b);
  b.textContent=on?"[ ARM ] Turn on provisioning":"Apply PnP mode";
  b.className=on?"btn":"btn btn-primary";
}
$("pnp-mode").addEventListener("change",devPnpLabel);

/* ---- Zero-touch claim window ---- */

function devFetchZeroTouch(){
  if(!canWrite())return Promise.resolve();
  return httpMethod("GET","/api/zero-touch",null)
    .then(t=>{devRenderZeroTouch(devParse(t));})
    .catch(e=>{setMsg("zt-msg","Could not read zero-touch state ("+e.message+").",msgCls(e));});
}

function devRenderZeroTouch(d){
  d=d||{};
  var on=d.attached!==false;
  var open=on&&!!d.open;
  setSt($("zt-state"),!on?"(SIP engine not attached yet)":(open?"\u00B7 OPEN":"\u00B7 CLOSED"));
  devSet("zt-range",(open&&d.lo!==undefined)?(d.lo+" to "+d.hi):null);
  devSet("zt-secs",open?d.secondsLeft:null);
  devSet("zt-unclaimed",on?d.unclaimed:null);
  devSet("zt-free",on?d.free:null);
  devSet("zt-refusals",on?d.refusals:null);
  devSet("zt-lastref",on?d.lastRefusal:null);
  devSet("zt-learnonly",on?(d.learnOnly?"yes":"no"):null);
}

function devOpenZeroTouch(){
  if(!devGate("zt-msg"))return;
  var lo=$("zt-lo").value.trim(),hi=$("zt-hi").value.trim(),min=$("zt-minutes").value.trim();
  if(!lo||!hi||!min){
    setMsg("zt-msg","Enter the first and last extension and the minutes.","");
    return;
  }
  post("/api/zero-touch","open=1&lo="+encodeURIComponent(lo)+"&hi="+encodeURIComponent(hi)+"&minutes="+encodeURIComponent(min))
    .then(t=>{
      devRenderZeroTouch(devParse(t));
      setMsg("zt-msg","Window open.","ok");
    })
    .catch(fm("zt-msg"));
}

function devCloseZeroTouch(){
  if(!devGate("zt-msg"))return;
  post("/api/zero-touch","open=0")
    .then(t=>{
      devRenderZeroTouch(devParse(t));
      setMsg("zt-msg","Window closed.","ok");
    })
    .catch(fm("zt-msg"));
}

store.effect(()=>{
  sig.admin.get();
  if(sig.nav.get()==="devices")devicesShown();
});
