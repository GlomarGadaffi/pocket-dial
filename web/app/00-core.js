/* 00-core.js: helpers, auth, poll loop, nav, toasts, confirm. Sections call these and never redefine them.
   Requests reject with .status and .data; .cancelled means a 409 confirm was declined. Signals: read with .get() inside store.effect(fn).
   Gate controls with data-needs="login"|"owner". poll.register(path, ms, fn, "<section>") runs only while shown; true runs always. */
/* Swapped for the session token when served. */
var PD_CSRF="__PD_CSRF__";
/* The board serves 3 connections and refuses a source that holds more than 2 (kMaxConnectionsPerSource, #529),
   and a 3rd request is DRAM it cannot spare. The page used to fire up to 6 GETs at once at boot and got 503s. Every
   fetch goes through a FIFO queue of 2, and a slot frees when the body has been read, not at the headers. Uploads
   use XHR and are not queued. */
(function(){var f=window.fetch.bind(window),q=[],n=0;
 function done(){n--;next();}
 function next(){while(n<2&&q.length){var j=q.shift();n++;
  f(j.u,j.o).then(r=>{r.clone().arrayBuffer().then(done,done);j.res(r);},e=>{done();j.rej(e);});}}
 window.fetch=function(u,o){return new Promise((res,rej)=>{q.push({u:u,o:o,res:res,rej:rej});next();});};
})();
var adminState={needsSetup:false,loggedIn:false,role:"",csrf:PD_CSRF,ownerProvisioned:false,remain:0,expired:false};
var otaUploading=false;
var failCount=0;
var lastAdminKey="";
var reloadAsked=false;
var gateQueued=false;
/* Sections present in the DOM at start, in document order. A profile script (05-sbc.js) may drop sections
   before core runs; nav items, sub-tabs, F-keys and Alt+digit follow what is left. A missing section is never an error.
   Devices has no nav item (it is an EXT sub-tab) but sits right after EXT in the DOM, so Alt+3 keeps its slot. */
var SECS=[].map.call(document.querySelectorAll("section[id^='sec-']"),s=>s.id.slice(4));
document.querySelectorAll("#nav li,#fkey-bar [data-sec],.tabs [data-sec]").forEach(n=>{
 var a=n.querySelector("[data-sec]")||n;
 if(SECS.indexOf(a.getAttribute("data-sec"))<0)n.parentNode.removeChild(n);});
var STATUS_TXT={411:"Length required: the upload had no size",413:"File too large",422:"File rejected: wrong format or content",429:"Too many attempts. Locked out; wait a minute and try again.",501:"Not supported on this build"};
function mk(t){
 return document.createElement(t);
}
function $(id){
 return document.getElementById(id);
}
function rj(r){
 if(!r.ok)throw new Error("HTTP "+r.status);
 return r.json();
}
function esc(s){
 return String(s==null?"":s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;").replace(/'/g,"&#39;");
}
function parseJsonOr(t){
 try{return JSON.parse(t);}catch(e){return {};}
}
function formBody(o){
 return Object.keys(o).filter(k=>o[k]!=null).map(k=>encodeURIComponent(k)+"="+encodeURIComponent(o[k])).join("&");
}
function pad2(n){
 return (n<10?"0":"")+n;
}
function fmtClock(sec){
 sec=Math.max(0,Math.floor(sec||0));
 var h=Math.floor(sec/3600),m=Math.floor(sec%3600/60),s=sec%60;
 return (h>0?h+":"+pad2(m):m)+":"+pad2(s);
}
function fmtUptime(sec){
 sec=Math.max(0,Math.floor(sec||0));
 var d=Math.floor(sec/86400),h=Math.floor(sec%86400/3600),m=Math.floor(sec%3600/60),s=sec%60;
 return (d>0?d+"d ":"")+pad2(h)+":"+pad2(m)+":"+pad2(s);
}
function fmtBytes(n){
 n=Number(n)||0;
 if(n<1024)return n+" B";
 if(n<1048576)return (n/1024).toFixed(1)+" KiB";
 return (n/1048576).toFixed(1)+" MiB";
}
/* Mirrors the server: a Sysop also passes owner gates until an owner exists. */
function canWrite(){
 return adminState.loggedIn&&!adminState.needsSetup;
}
function isOwner(){
 return adminState.role==="owner"||(adminState.role==="sysop"&&!adminState.ownerProvisioned);
}
/* ---- signal store ---- */
var store=(()=>{
 var cur=null;
 const drop=e=>{e.deps.forEach(s=>s.off(e));e.deps=[];};
 const run=e=>{
  if(e.dead||e.busy)return;
  drop(e);
  var prev=cur;
  cur=e;
  e.busy=true;
  try{e.fn();}catch(x){if(window.console)console.error(x);}
  e.busy=false;
  cur=prev;};
 const signal=v=>{
  var subs=[];
  var s={
   get:()=>{if(cur&&subs.indexOf(cur)<0){subs.push(cur);cur.deps.push(s);}return v;},
   peek:()=>v,
   set:n=>{if(n===v)return;v=n;subs.slice().forEach(run);},
   off:e=>{var i=subs.indexOf(e);if(i>=0)subs.splice(i,1);}};
  return s;};
 const effect=fn=>{
  var e={fn:fn,deps:[],dead:false,busy:false};
  run(e);
  return ()=>{e.dead=true;drop(e);};};
 return {signal:signal,effect:effect};
})();
var CDR_OUT={auth:false,msg:"Log in to view the call log",recs:[]};
var sig={
 status:store.signal(null),
 cdr:store.signal(CDR_OUT),
 admin:store.signal({loggedIn:false,needsSetup:false,role:"",ownerProvisioned:false}),
 ota:store.signal(null),
 moh:store.signal(null),
 trace:store.signal([]),
 traceOn:store.signal(false),
 traceErr:store.signal(""),
 nav:store.signal("")};
/* ---- messages: inline (setMsg), toast, confirm ---- */
/* Solid fill is for device faults (5xx, or no HTTP status at all). A 4xx is a refusal or bad input: grey. */
function msgCls(e){return e&&e.status>=400&&e.status<500?"":"err";}
function fm(id,pre){
 return e=>{setMsg(id,(pre===undefined?"Error: ":pre)+e.message,msgCls(e));};
}
function setMsg(id,txt,cls){
 var e=$(id);
 if(!e)return;
 e.setAttribute("role",cls==="err"?"alert":"status");
 e.textContent=txt||"";
 e.className="msg"+(cls?" "+cls:"");
}
/* Status chip: el becomes a .st (CSS adds the brackets). txt is glyph + word, no brackets. cls: p1|p2 only for off-normal. */
function setSt(el,txt,cls){if(!el)return;el.className="st"+(cls?" "+cls:"");el.textContent=txt;}
var ui={};
/* kind: "err" (p1) only for a device fault, "warn" (p2) only for off-normal device state, "ok" for a done
   action; "" (grey, · glyph) for permission text, session expiry and progress. */
ui.toast=(text,kind)=>{
 var err=kind==="err",warn=kind==="warn";
 var host=$(err?"toast-alert":"toast-status");
 if(!host)return;
 var p=mk("p");
 p.className="toast st "+(err?"p1":warn?"p2":"");
 var g=mk("span");
 g.className="g";
 g.setAttribute("aria-hidden","true");
 g.textContent=err?"◆":warn?"▲":"·";
 var t=mk("span");
 t.textContent=text;
 var x=mk("button");
 x.type="button";
 x.className="lnk";
 x.textContent="DISMISS";
 const gone=()=>{if(p.parentNode)p.parentNode.removeChild(p);};
 x.addEventListener("click",gone);
 p.append(g,t,x);
 host.appendChild(p);
 while(host.children.length>4)host.removeChild(host.firstChild);
 setTimeout(gone,err?15000:warn?9000:5000);};
function showDlg(d){
 if(d.open)return;
 if(d.showModal)d.showModal();else d.setAttribute("open","");
}
/* Destructive control = ONE button, two presses (brief 7b, 2026-10-17). A trigger's click handler calls
   ui.arm(button,label,onExec): the first press arms the button (.armed hazard border, "[ EXEC ] label" in red)
   and a 10 s timer disarms it back to "[ ARM ] label"; a second press inside the window disarms it and runs
   onExec. One button is armed at a time. An aria-label of "[ ARM ] <fuller text>" keeps its fuller text.
   ui.disarm(button) cancels an armed button whose precondition changed. */
var armCur=null;
function armPaint(b,on){
 var pre=on?"[ EXEC ] ":"[ ARM ] ",a=(b.getAttribute("aria-label")||"").replace(/^\[ (ARM|EXEC) \] /,"");
 b.classList.toggle("armed",on);
 b.classList.toggle("btn-exec",on);
 b.textContent=pre+b._armLabel;
 b.setAttribute("aria-label",pre+(a||b._armLabel));
}
ui.disarm=b=>{
 if(!b||!b._armT)return;
 clearTimeout(b._armT);
 b._armT=0;
 if(b===armCur)armCur=null;
 armPaint(b,false);};
ui.arm=(b,label,onExec)=>{
 if(!b)return;
 b._armLabel=label;
 if(b._armT){ui.disarm(b);onExec();return;}
 ui.disarm(armCur);
 armCur=b;
 b.classList.add("btn-arm");
 armPaint(b,true);
 b._armT=setTimeout(()=>ui.disarm(b),10000);};
/* The dialog asks a question the server raised (409 confirm=LOCKOUT) or a reload; destructive actions never use it. */
var confirmRes=null;
ui.confirm=(title,line,actionLabel)=>{
 var d=$("confirm-dlg");
 if(confirmRes){var old=confirmRes;confirmRes=null;old(false);}
 $("confirm-t").textContent=title;
 $("confirm-d").textContent=line;
 $("confirm-yes").textContent=actionLabel||"Confirm";
 return new Promise(res=>{
  confirmRes=res;
  showDlg(d);
  $("confirm-no").focus();});};
/* The buttons resolve the promise themselves; Esc still lands on close. */
function confirmEnd(ok){
 var r=confirmRes,d=$("confirm-dlg");
 confirmRes=null;
 if(d.open)d.close();
 if(r)r(ok);
}
$("confirm-yes").addEventListener("click",e=>{e.preventDefault();confirmEnd(true);});
$("confirm-no").addEventListener("click",e=>{e.preventDefault();confirmEnd(false);});
$("confirm-dlg").addEventListener("close",()=>{confirmEnd(false);});
/* Turning on an anchor media path defaults to NO. ui.accept() resolves true only when the admin ticks the box
   and presses "Accept and enable"; Esc, click-away and "No" resolve false. Nothing is remembered: each enable asks. */
var acceptRes=null;
ui.accept=()=>{
 var d=$("accept-dlg");
 if(acceptRes){var old=acceptRes;acceptRes=null;old(false);}
 $("accept-ck").checked=false;
 $("accept-yes").disabled=true;
 return new Promise(res=>{
  acceptRes=res;
  showDlg(d);
  $("accept-no").focus();});};
function acceptEnd(ok){
 var r=acceptRes,d=$("accept-dlg");
 acceptRes=null;
 if(d.open)d.close();
 if(r)r(ok);
}
$("accept-ck").addEventListener("change",()=>{$("accept-yes").disabled=!$("accept-ck").checked;});
$("accept-yes").addEventListener("click",e=>{e.preventDefault();if($("accept-ck").checked)acceptEnd(true);});
$("accept-no").addEventListener("click",e=>{e.preventDefault();acceptEnd(false);});
$("accept-dlg").addEventListener("close",()=>{acceptEnd(false);});
/* ---- gating: data-needs="login" | "owner" ---- */
function gateAllowed(need){
 if(need==="login")return canWrite();
 if(need==="owner")return canWrite()&&isOwner();
 return true;
}
function gateReason(need){
 if(adminState.needsSetup)return "Finish first-time setup first.";
 if(need==="owner"&&adminState.loggedIn)return "Owner login required.";
 return "Log in to use this control.";
}
ui.gate=root=>{
 (root||document).querySelectorAll("[data-needs]").forEach(n=>{
  var need=n.getAttribute("data-needs");
  if(!gateAllowed(need)){
   if(!n.hasAttribute("data-gated"))n._t0=n.getAttribute("title")||"";
   n.setAttribute("data-gated","1");
   n.setAttribute("aria-disabled","true");
   n.setAttribute("title",gateReason(need));
   return;}
  if(!n.hasAttribute("data-gated"))return;
  n.removeAttribute("aria-disabled");
  n.removeAttribute("data-gated");
  if(n._t0)n.setAttribute("title",n._t0);else n.removeAttribute("title");});};
function queueGate(){
 if(gateQueued)return;
 gateQueued=true;
 requestAnimationFrame(()=>{gateQueued=false;ui.gate(document);});
}
function gateDenied(n){
 var need=n.getAttribute("data-needs");
 if(need&&!gateAllowed(need)){
  if(!adminState.loggedIn&&!adminState.needsSetup){openLogin("Log in to use this control.");return;}
  ui.toast(gateReason(need),"");
  return;}
 ui.toast(n.getAttribute("title")||"Not available right now.","");
}
document.addEventListener("click",e=>{
 var n=e.target&&e.target.closest?e.target.closest("[data-needs],[aria-disabled=true]"):null;
 if(!n)return;
 var need=n.getAttribute("data-needs");
 if(n.getAttribute("aria-disabled")!=="true"&&!(need&&!gateAllowed(need)))return;
 e.preventDefault();
 e.stopPropagation();
 gateDenied(n);},true);
/* ---- networking ---- */
/* up={blob,onprog} sends an XHR upload with progress; both paths resolve to {ok,status,text()}. */
function wire(method,path,bs,up){
 if(up)return new Promise((res,rej)=>{
  var x=new XMLHttpRequest();
  x.open("POST",path,true);
  x.withCredentials=true;
  x.setRequestHeader("Content-Type","application/octet-stream");
  x.setRequestHeader("X-CSRF",PD_CSRF);
  if(up.onprog)x.upload.onprogress=v=>{if(v.lengthComputable)up.onprog(v.loaded/v.total);};
  x.onload=()=>res({ok:x.status>=200&&x.status<300,status:x.status,text:()=>Promise.resolve(x.responseText)});
  x.onerror=()=>{rej(new Error("Upload failed: network error"));};
  x.send(up.blob);});
 var o={method:method,credentials:"same-origin",headers:{}};
 if(method!=="GET"){
  o.headers["X-CSRF"]=PD_CSRF;
  if(bs){
   o.headers["Content-Type"]="application/x-www-form-urlencoded";
   o.body=bs;}}
 return fetch(path,o);
}
/* Resolves with the parsed body ({} when empty). 401 ends the session, 403 asks for a reload,
   a 409 from POST /api/registrar asks to confirm LOCKOUT and resends, anything else is the server's message. */
function httpMethod(method,path,body,quiet,up){
 var bs=typeof body==="string"?body:(body?formBody(body):"");
 return wire(method,path,bs,up).then(r=>r.text().then(t=>{
  var d=parseJsonOr(t);
  if(r.ok)return d;
  var st=r.status,msg=d.error||d.message||STATUS_TXT[st]||("HTTP "+st);
  var e=new Error(msg);
  e.status=r.status;
  e.data=d;
  if(st===401){
   if(adminState.loggedIn){e.message="Session expired: log in again to continue.";handleAuthExpired();}
   else{e.message="Log in to continue.";if(!quiet)openLogin("Log in to continue.");}
  }else if(st===403){
   if(d.error==="setup_required"){e.message="Finish first-time setup before changing settings.";fetchAdminStatus();}
   else if(/owner/i.test(d.error||""))e.message="Owner login required.";
   else{e.message="Rejected: stale security token or cross-origin request. Reload the page.";reloadPrompt();}
  }else if(st===409&&path==="/api/registrar"&&method==="POST"&&!/(^|&)confirm=/.test(bs)){
   return ui.confirm("Confirm this change",msg,"Apply anyway").then(ok=>{
    if(!ok){e.cancelled=true;throw e;}
    return httpMethod(method,path,(bs?bs+"&":"")+"confirm=LOCKOUT",quiet);});}
  return Promise.reject(e);}));
}
function post(path,body){
 return httpMethod("POST",path,body);
}
function put(path,body){
 return httpMethod("PUT",path,body);
}
function del(path,body){
 return httpMethod("DELETE",path,body);
}
function getJson(path){
 return httpMethod("GET",path,null,true);
}
/* Raw-body upload (OTA image, MOH WAV). onprog gets a 0..1 fraction. */
function uploadBody(path,blob,onprog){
 return httpMethod("POST",path,"",true,{blob:blob,onprog:onprog});
}
function reloadPrompt(){
 if(reloadAsked)return;
 reloadAsked=true;
 ui.confirm("Reload required","The security token for this page was rejected, or the request came from another origin. Reload to get a fresh token. Anything typed into a form will be lost.","Reload").then(ok=>{
  reloadAsked=false;
  if(ok)location.reload();});
}
/* ---- poll registry: core's own polls are the setInterval lines at the bottom ---- */
var poll={list:[],pub:["/api/status","/api/admin/status","/api/ota/status","/api/wifi/scan"]};
poll.want=e=>{
 var shown=e.always===true||e.always===nav.current;
 var pub=poll.pub.indexOf(e.path)>=0;
 return shown&&(pub||canWrite());};
poll.run=e=>{
 if(e.busy||document.hidden)return;
 e.busy=true;
 getJson(e.path).then(d=>{e.fn(d,null);},x=>{e.fn(null,x);}).then(()=>{e.busy=false;},()=>{e.busy=false;});};
poll.sync=()=>{
 poll.list.forEach(e=>{
  var w=poll.want(e);
  if(w&&!e.t){poll.run(e);e.t=setInterval(()=>poll.run(e),e.ms);}
  else if(!w&&e.t){clearInterval(e.t);e.t=0;}});};
poll.register=(path,ms,fn,always)=>{
 var e={path:path,ms:ms,fn:fn,always:always,t:0,busy:false};
 poll.list.push(e);
 poll.sync();
 return e;};
/* ---- fetchers owned by core; sections subscribe to the signals ---- */
function setOnline(ok){
 $("conn").className="st "+(ok?"":"p2");
 $("conn-g").textContent=ok?"·":"▲";
 $("conn-txt").textContent=ok?"online":"offline";
}
function updateRail(d){
 $("s-uptime").textContent=fmtUptime(d.uptime);
 $("s-ip").textContent=(d.ip||"0.0.0.0")+":"+(d.port||5060);
 $("s-phones").textContent=typeof d.clientCount==="number"?d.clientCount:(d.clients||[]).length;
 $("s-calls").textContent=typeof d.sessionCount==="number"?d.sessionCount:(d.sessions||[]).length;
 if(d.version)$("build").textContent="fw "+d.version;
}
function fetchStatus(){
 if(document.hidden)return Promise.resolve();
 return fetch("/api/status",{credentials:"same-origin"}).then(rj).then(d=>{
  failCount=0;
  setOnline(true);
  updateRail(d);
  applyE911(d);
  applyEmergencyRoute(d);
  if(typeof renderBoard==="function"){try{renderBoard(d);}catch(x){if(window.console)console.error(x);}}
  sig.status.set(d);
 }).catch(()=>{
  failCount++;
  if(failCount>=2)setOnline(false);});
}
/* #521: emergencyRoute "none" keeps the route banner up; an absent field says nothing. */
function applyEmergencyRoute(d){
 var b=$("e911-route-banner");
 if(!b||!d||typeof d.emergencyRoute==="undefined")return;
 b.style.display=d.emergencyRoute==="none"?"":"none";
}
/* #450: an absent field shows nothing; hidden while emergencyRoute is "none" (the route banner covers it). */
function applyE911(d){var b=$("e911-banner");if(!b||!d||typeof d.e911Configured==="undefined")return;b.style.display=(d.e911Configured||d.emergencyRoute==="none")?"none":"";
 /* #792: anchor route names 3CX; other routes restore the default sentence. */
 var t=$("e911-banner-text");
 if(!t)return;
 if(t._def===undefined)t._def=t.textContent;
 t.textContent=d.emergencyRoute==="anchor"?"A 911 call goes out through the 3CX anchor, whose own E911 setup applies. This board's on-site notify list is empty.":t._def;
}
/* #167: wifiCapable is read from sig.status (applyApCapable in 80-security.js). Absent means capable. */
function fetchCdr(){
 if(document.hidden)return Promise.resolve();
 if(!adminState.loggedIn){sig.cdr.set(CDR_OUT);return Promise.resolve();}
 return fetch("/api/cdr",{credentials:"same-origin"}).then(r=>{
  if(r.status===401){
   if(adminState.loggedIn)handleAuthExpired();
   sig.cdr.set({auth:false,msg:"Log in to view the call log",recs:[]});
   return null;}
  return rj(r);
 }).then(recs=>{
  if(recs)sig.cdr.set({auth:true,msg:"",recs:recs});
 }).catch(e=>{
  sig.cdr.set({auth:true,msg:"Call log unavailable: "+e.message,recs:sig.cdr.peek().recs});});
}
function fetchOtaStatus(){
 if(document.hidden)return Promise.resolve();
 return fetch("/api/ota/status",{credentials:"same-origin"}).then(rj).then(d=>sig.ota.set(d)).catch(e=>sig.ota.set({fetchError:e.message}));
}
function fetchMohStatus(){
 if(document.hidden||!adminState.loggedIn||adminState.needsSetup)return Promise.resolve();
 return fetch("/api/moh",{credentials:"same-origin"}).then(r=>{
  if(r.status===401){handleAuthExpired();throw new Error("session expired");}
  return rj(r);
 }).then(d=>sig.moh.set(d)).catch(e=>sig.moh.set({fetchError:e.message}));
}
/* Trace polls only while on; startTrace/stopTrace are the only switches. */
var traceCtl={timer:0};
function startTrace(){
 if(sig.traceOn.peek())return;
 if(!adminState.loggedIn){ui.toast("Log in to start the trace.","");return;}
 sig.traceOn.set(true);
 pollTrace();
 traceCtl.timer=setInterval(pollTrace,1500);
}
function stopTrace(){
 if(traceCtl.timer){clearInterval(traceCtl.timer);traceCtl.timer=0;}
 sig.traceOn.set(false);
}
function pollTrace(){
 if(document.hidden)return Promise.resolve();
 return fetch("/api/trace",{credentials:"same-origin"}).then(r=>{
  if(r.status===401){handleAuthExpired();stopTrace();throw new Error("session expired");}
  return rj(r);
 }).then(recs=>{
  sig.traceErr.set("");
  sig.trace.set(recs||[]);
 }).catch(e=>{sig.traceErr.set(e.message);});
}
/* ---- alarm annunciator: derived from polled data. ACK stores each signature in sessionStorage;
   an acked alarm stays hidden until its signature changes or it clears. ---- */
var ALARM_POOL_KEYS=["msgPoolRefusals","vpeerPoolRefusals","rtpTxPoolRefused","rtpTxPoolRetired","droppedNoPool","repliesRefused","trunkRefusedDialogByes","httpStatusRefusals","httpPerSourceRefusals"];
var ALARM_IDS=["setup","e911","ota","pool"];
var ackMem={};
var alarmSeen="";
function ackGet(id){
 try{return sessionStorage.getItem("pd-ack-"+id);}catch(e){return ackMem[id]||null;}
}
function ackSet(id,v){
 try{if(v===null)sessionStorage.removeItem("pd-ack-"+id);else sessionStorage.setItem("pd-ack-"+id,v);}
 catch(e){if(v===null)delete ackMem[id];else ackMem[id]=v;}
}
/* No ANCHOR alarm: /api/status has no anchor-link field (brief 7b decision, 2026-10-17; recorded gap for the SBC profile). */
function alarmsNow(){
 var out=[],s=sig.status.get(),o=sig.ota.get();
 if(adminState.needsSetup)out.push({id:"setup",p:2,sig:"on",txt:"SETUP: admin login not set, SIP stays off"});
 if(s&&s.emergencyRoute==="none")out.push({id:"e911",p:1,sig:"on",txt:"911 ROUTE NONE: 911 and 933 refused"});
 if(o&&o.pendingVerify===true)out.push({id:"ota",p:2,sig:"on",txt:"OTA: new firmware pending verification"});
 var hot=[];
 if(s)ALARM_POOL_KEYS.forEach(k=>{var v=s[k];if(typeof v==="number"&&v>0)hot.push(k+" "+v);});
 if(hot.length)out.push({id:"pool",p:2,sig:hot.join(","),txt:"POOL/REFUSAL: "+hot.join(", ")});
 return out;
}
function alarmRender(){
 var st=$("alarm-state"),tx=$("alarm-text");
 if(!st||!tx)return;
 var all=alarmsNow(),show=[],acked=0;
 ALARM_IDS.forEach(id=>{if(!all.some(a=>a.id===id))ackSet(id,null);});
 all.forEach(a=>{
  if(ackGet(a.id)===a.p+"|"+a.sig)acked++;
  else show.push(a);});
 var top=show.some(a=>a.p===1)?1:show.length?2:0;
 st.className="st"+(top===1?" p1":top===2?" p2":"");
 st.textContent=top===1?"◆ FAULT":top===2?"▲ WARN":acked?"· ACKED":"· IDLE";
 var key=show.map(a=>a.id+"|"+a.p+"|"+a.sig).join(";");
 if(key===alarmSeen)return;
 alarmSeen=key;
 tx.textContent="";
 /* The cell ellipsizes at narrow widths (app.css .alarm-bar .alarm); the title carries the full text. */
 tx.title=show.map(a=>a.txt).join("; ");
 show.forEach(a=>{
  var s=mk("span");
  s.className="alarm p"+a.p+(a.p===1?" unack":"");
  s.textContent=(a.p===1?"[ ◆ FAULT ] ":"[ ▲ WARN ] ")+a.txt;
  s.title=a.txt;
  tx.appendChild(s);});
}
function alarmAck(){
 alarmsNow().forEach(a=>ackSet(a.id,a.p+"|"+a.sig));
 alarmRender();
}
/* ---- admin session ---- */
function setupBanner(txt){
 var b=$("setup-banner");
 if(!b)return;
 b.textContent=txt;
 b.style.display=txt?"":"none";
}
function fetchAdminStatus(){
 return fetch("/api/admin/status",{credentials:"same-origin"}).then(rj).then(d=>{
  adminState.needsSetup=!!d.needsSetup;
  adminState.loggedIn=!!d.authenticated;
  adminState.role=d.authenticated?(d.role||"sysop"):"";
  adminState.ownerProvisioned=!!d.ownerProvisioned;
  adminState.remain=d.sessionRemainingSec||0;
  if(adminState.loggedIn)adminState.expired=false;
  adminChanged();
  setupBanner(adminState.needsSetup?"Set the admin login first. Phones cannot register until you do: SIP stays off until a real admin login is set.":"");
 }).catch(e=>{setupBanner("Could not read admin status: "+e.message);});
}
function renderAdminBar(){
 var a=adminState;
 $("auth-btn").textContent=a.loggedIn?"Log out":"Log in";
 $("role").hidden=!(a.loggedIn&&a.role);
 $("role").textContent=a.role||"";
 $("sess").textContent=a.loggedIn?(a.remain>0?"SESSION: "+fmtClock(a.remain):"SESSION: ACTIVE"):(a.expired?"SESSION: EXPIRED":"SESSION: LOGGED OUT");
}
function adminChanged(){
 var a=adminState;
 var key=[a.loggedIn,a.needsSetup,a.role,a.ownerProvisioned].join("|");
 renderAdminBar();
 nav.render();
 ui.gate(document);
 if(key===lastAdminKey)return;
 lastAdminKey=key;
 sig.admin.set({loggedIn:a.loggedIn,needsSetup:a.needsSetup,role:a.role,ownerProvisioned:a.ownerProvisioned});
 poll.sync();
 if(!a.loggedIn)stopTrace();
 fetchStatus();
 fetchCdr();
}
function handleAuthExpired(){
 if(!adminState.loggedIn)return;
 adminState.loggedIn=false;
 adminState.expired=true;
 adminState.role="";
 adminState.remain=0;
 adminChanged();
 ui.toast("Session expired. Log in again to continue.","");
 openLogin("Session expired. Log in again to continue.");
}
function openLogin(note){
 if(adminState.needsSetup)return;
 var d=$("login-dlg");
 setMsg("login-msg",note||"","");
 showDlg(d);
 $("login-user").focus();
}
function adminLogin(userId,passId,msgId){
 var user=$(userId).value,pass=$(passId).value;
 if(!user||!pass){setMsg(msgId,"Enter your username and password.","");return Promise.resolve(false);}
 return fetch("/api/admin/login",{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/x-www-form-urlencoded"},body:formBody({username:user,password:pass})}).then(r=>{
  $(passId).value="";
  return r.text().then(t=>{
   var d=parseJsonOr(t);
   if(r.status===401){setMsg(msgId,"Incorrect username or password.","");return false;}
   if(r.status===429){setMsg(msgId,d.error||STATUS_TXT[429],"");return false;}
   if(!r.ok){setMsg(msgId,"Login failed (HTTP "+r.status+").","");return false;}
   if(d.csrf){PD_CSRF=d.csrf;adminState.csrf=d.csrf;}
   adminState.loggedIn=true;
   adminState.expired=false;
   adminState.needsSetup=!!d.needsSetup;
   adminState.role=d.role||"sysop";
   setMsg(msgId,"","");
   adminChanged();
   fetchAdminStatus();
   return true;});
 }).catch(e=>{
  setMsg(msgId,"Login failed: "+e.message,"");
  return false;});
}
function adminLogout(){
 return fetch("/api/admin/logout",{method:"POST",credentials:"same-origin"}).then(r=>{
  if(!r.ok)throw new Error("HTTP "+r.status);
  PD_CSRF="";
  adminState.csrf="";
  adminState.loggedIn=false;
  adminState.expired=false;
  adminState.role="";
  adminState.remain=0;
  stopTrace();
  adminChanged();
  ui.toast("Logged out.","ok");
  return fetchAdminStatus();
 }).catch(e=>{ui.toast("Log out failed: "+e.message,"err");});
}
function adminCompleteSetup(){
 var user=$("setup-user").value.trim(),pass=$("setup-pass").value,pass2=$("setup-pass2").value,pin=$("setup-pin").value.trim();
 if(!user||pass.length<8){setMsg("setup-msg","A username and a password of 8 or more characters are required.","");return;}
 if(pass!==pass2){setMsg("setup-msg","The two passwords differ.","");return;}
 if(pin&&!/^[0-9]{4,16}$/.test(pin)){setMsg("setup-msg","The DTMF PIN must be 4 to 16 digits.","");return;}
 var b={username:user,password:pass};
 if(pin)b.dtmfPin=pin;
 post("/api/admin/set-credential",b).then(()=>{
  ["setup-pass","setup-pass2","setup-pin"].forEach(i=>{$(i).value="";});
  setMsg("setup-msg","Login saved. The factory login is retired.","ok");
  return fetchAdminStatus();
 }).then(()=>{
  if(!adminState.loggedIn&&!adminState.needsSetup)openLogin("Login saved. Log in with the new credentials.");
 }).catch(e=>{setMsg("setup-msg","Could not save the login: "+e.message,msgCls(e));});
}
/* ---- navigation ---- */
var nav={current:""};
nav.render=()=>{
 var setup=adminState.needsSetup;
 $("app").className="app"+(setup?" setup":"");
 $("nav").hidden=setup;
 $("fkey-bar").hidden=setup;
 $("view-setup").hidden=!setup;
 $("setup-login-form").hidden=adminState.loggedIn;
 $("setup-form").hidden=!adminState.loggedIn;
 SECS.forEach(name=>{var el=$("sec-"+name);if(el)el.hidden=setup||name!==nav.current;});
 document.querySelectorAll("[data-sec]").forEach(a=>{
  if(a.getAttribute("data-sec")===nav.current)a.setAttribute("aria-current","page");
  else a.removeAttribute("aria-current");});};
nav.show=(name,focus,replace)=>{
 if(SECS.indexOf(name)<0)name=SECS[0]||"";
 var changed=nav.current!==name;
 nav.current=name;
 nav.render();
 if(location.hash!=="#"+name){
  if(replace&&window.history&&history.replaceState)history.replaceState(null,"","#"+name);
  else location.hash=name;}
 var link=document.querySelector('[data-sec="'+name+'"]');
 document.title=(link?link.textContent.trim():name)+" - pocket-dial";
 if(changed){sig.nav.set(name);poll.sync();}
 var sec=$("sec-"+name);
 if(focus&&sec&&!adminState.needsSetup)sec.focus({preventScroll:true});};
function hashSection(){
 var h=location.hash.replace(/^#/,"");
 return SECS.indexOf(h)>=0?h:"";
}
window.addEventListener("hashchange",()=>{
 var h=hashSection();
 if(h)nav.show(h,true);});
document.addEventListener("keydown",e=>{
 if(!e.altKey||e.ctrlKey||e.metaKey||e.shiftKey||adminState.needsSetup)return;
 var m=/^Digit(\d)$/.exec(e.code||"");
 if(!m)return;
 var name=SECS[m[1]==="0"?9:Number(m[1])-1];
 if(!name)return;
 e.preventDefault();
 nav.show(name,true);});
/* F1-F10 except F5, F11, F12 (the browser keeps those). Plain keys only. The keys renumber over the F-key
   buttons left after the prune above, in this order, so a profile with fewer sections leaves no gap. */
var FKEY_ORDER=["F1","F2","F3","F4","F6","F7","F8","F9","F10"];
var FKEYS={};
document.querySelectorAll("#fkey-bar [data-sec]").forEach((b,i)=>{
 var k=FKEY_ORDER[i];
 if(!k)return;
 FKEYS[k]=b.getAttribute("data-sec");
 b.setAttribute("aria-keyshortcuts",k);
 var f=b.querySelector(".fk");
 if(f)f.textContent=k;});
document.addEventListener("keydown",e=>{
 if(e.ctrlKey||e.metaKey||e.altKey||e.shiftKey||adminState.needsSetup)return;
 if(!Object.prototype.hasOwnProperty.call(FKEYS,e.key))return;
 e.preventDefault();
 nav.show(FKEYS[e.key],true);});
/* ---- init ---- */
/* Profile hooks, set by 05-sbc.js: window.PD_PRODUCT is the top-bar product string, window.PD_TITLES maps a
   section name to its heading. Read now and again on DOMContentLoaded, so they work whether that file runs
   before or after core. */
function applyProfile(){
 var t=$("pb-title");
 if(t)t.textContent=window.PD_PRODUCT||"POCKET-DIAL";
 var m=window.PD_TITLES||{};
 Object.keys(m).forEach(name=>{
  var sec=$("sec-"+name);
  if(!sec)return;
  var h=sec.querySelector("h2");
  if(h)h.textContent=m[name];
  sec.setAttribute("aria-label",m[name]);});
}
applyProfile();
document.addEventListener("DOMContentLoaded",applyProfile);
/* Fragments omit type and spellcheck; set them here. */
document.querySelectorAll("#main button:not([type])").forEach(b=>{b.type="button";});
document.querySelectorAll("#main input[type=text]").forEach(i=>{i.spellcheck=false;});
/* Live regions exist before their text changes. */
document.querySelectorAll(".msg[id]").forEach(function(e){e.setAttribute("role","status");});
$("auth-btn").addEventListener("click",()=>{
 if(adminState.loggedIn)adminLogout();else openLogin("");});
$("login-form").addEventListener("submit",e=>{
 e.preventDefault();
 adminLogin("login-user","login-pass","login-msg").then(ok=>{if(ok){$("login-dlg").close();ui.toast("Logged in.","ok");}});});
$("login-cancel").addEventListener("click",()=>{$("login-dlg").close();});
$("setup-login-form").addEventListener("submit",e=>{
 e.preventDefault();
 adminLogin("setup-login-user","setup-login-pass","setup-login-msg");});
$("setup-form").addEventListener("submit",e=>{
 e.preventDefault();
 adminCompleteSetup();});
if(window.MutationObserver)new MutationObserver(queueGate).observe($("main"),{childList:true,subtree:true});
document.addEventListener("visibilitychange",()=>{
 if(!document.hidden){fetchStatus();fetchAdminStatus();fetchCdr();fetchOtaStatus();}});
store.effect(()=>{
 var n=sig.nav.get();
 if(n==="audio")fetchMohStatus();
 if(n!=="console"&&sig.traceOn.peek())stopTrace();});
$("alarm-ack").addEventListener("click",alarmAck);
/* EXT / DEVICES sub-tabs (.tabs) switch sections like the nav does. */
document.querySelectorAll(".tabs [data-sec]").forEach(b=>{b.addEventListener("click",()=>{nav.show(b.getAttribute("data-sec"),true);});});
$("fkey-bar").addEventListener("click",e=>{
 var b=e.target.closest?e.target.closest("[data-sec]"):null;
 if(b)nav.show(b.getAttribute("data-sec"),true);});
store.effect(()=>{
 sig.admin.get();sig.status.get();sig.ota.get();
 alarmRender();});
nav.show(hashSection()||"overview",false,true);
renderAdminBar();
fetchStatus();fetchAdminStatus();fetchOtaStatus();
setInterval(fetchStatus,2000);
setInterval(fetchCdr,5000);
setInterval(fetchAdminStatus,15000);
setInterval(()=>{if(!otaUploading)fetchOtaStatus();},15000);
setInterval(()=>{if(nav.current==="audio")fetchMohStatus();},3000);
setInterval(()=>{
  if(adminState.loggedIn&&adminState.remain>0){
    adminState.remain--;renderAdminBar();
    if(adminState.remain===0)fetchAdminStatus();
  }
},1000);
/* Boot marker (brief 8 step 5): reached only if the whole script block parsed and core's init ran. */
document.documentElement.setAttribute("data-booted","1");
