/* ── Routing section: dial plan and SBC mode ──
   Routes: POST /api/dialplan (upsert; delete = pattern with an empty target),
   GET and PUT on /api/sbc-mode. E911 config lives in 80-security.js.
   Rules come from the status object (dialplan[]) that the core poll keeps fresh.
   Core helpers used: $, setMsg, post, put, httpMethod, fetchStatus, store, ui, adminState. */
var RT_ACTION_LABEL={trunk:"Trunk",group:"Ring group",page:"Page zone",park:"Park orbit"};
var RT_TARGET_LABEL={trunk:"Prepend after stripping (blank = prepend nothing)",group:"Ring group extension",page:"Paging zone (980–989)",park:"Park orbit (700–709)"};
var rtLoaded=false;
var rtSbcReady=false;
var rtRowsSig="";

function rtAria(id,off){
  var el=$(id);
  if(el)el.setAttribute("aria-disabled",off?"true":"false");
}
function rtNeedLogin(id){
  setMsg(id,adminState.needsSetup?"Finish admin setup first.":"Admin login required.","");
}
function rtStatusValue(){
  sig.admin.get();
  return sig.status.get();
}
function rtRules(d){
  return (d&&d.dialplan)||[];
}
function rtCell(tr,text,cls){
  var td=mk("td");
  if(cls)td.className=cls;
  td.textContent=text;
  tr.appendChild(td);
  return td;
}
function rtNoteRow(body,text){
  var tr=mk("tr");
  var td=mk("td");
  td.colSpan=6;
  td.className="note";
  td.textContent=text;
  tr.appendChild(td);
  body.appendChild(tr);
}
function rtRowButton(label,aria,fn){
  var b=mk("button");
  b.type="button";
  b.className="btn";
  b.textContent=label;
  b.setAttribute("aria-label",aria);
  b.setAttribute("aria-disabled",canWrite()?"false":"true");
  b.addEventListener("click",fn);
  return b;
}
/* Rebuilt only when the rules or the login state change, so a focused Edit or
   Delete button survives the 2 s status poll. */
function rtRenderRules(d){
  var rules=rtRules(d);
  var key=JSON.stringify(rules)+"|"+canWrite()+"|"+!!adminState.loggedIn;
  if(key===rtRowsSig)return;
  rtRowsSig=key;
  var body=$("rt-rules-body");
  $("rt-count").textContent=String(rules.length);
  body.textContent="";
  if(!adminState.loggedIn){
    rtNoteRow(body,"Log in to view dial plan rules.");
    return;
  }
  if(!rules.length){
    rtNoteRow(body,"No rules. Outside numbers are not routed until a trunk rule exists.");
    return;
  }
  rules.forEach((r,i)=>{
    var tr=mk("tr");
    var isTrunk=r.action==="trunk";
    rtCell(tr,String(i+1),"mono");
    rtCell(tr,r.pattern,"mono");
    rtCell(tr,RT_ACTION_LABEL[r.action]||r.action);
    rtCell(tr,isTrunk?(r.target||"none"):(r.target||""),"mono");
    rtCell(tr,isTrunk?String(Number(r.stripDigits||0)):"—","mono");
    var acts=mk("td");
    acts.className="row-actions";
    acts.appendChild(rtRowButton("Edit","Edit rule "+r.pattern,()=>{rtStartEdit(r);}));
    acts.appendChild(rtRowButton("[ ARM ] Delete","[ ARM ] Delete rule "+r.pattern,ev=>{rtDeleteRule(r,ev.currentTarget);}));
    tr.appendChild(acts);
    body.appendChild(tr);
  });
}
function rtActionChanged(){
  var act=$("rt-action").value;
  $("rt-strip-field").hidden=act!=="trunk";
  $("rt-target-label").textContent=RT_TARGET_LABEL[act]||"Target";
}
function rtStartEdit(r){
  if(!canWrite()){rtNeedLogin("rt-dp-msg");return;}
  $("rt-pattern").value=r.pattern;
  $("rt-pattern").readOnly=true;
  $("rt-action").value=r.action;
  $("rt-target").value=r.target||"";
  $("rt-strip").value=String(r.stripDigits||0);
  rtActionChanged();
  $("rt-form-title").textContent="Edit rule "+r.pattern;
  $("rt-form-note").textContent="Saving keeps this rule's position. To change the pattern, delete the rule and add a new one; it goes to the end.";
  $("rt-cancel").hidden=false;
  setMsg("rt-dp-msg","","status");
  $("rt-target").focus();
}
function rtCancelEdit(){
  $("rt-pattern").readOnly=false;
  $("rt-pattern").value="";
  $("rt-action").value="trunk";
  $("rt-target").value="";
  $("rt-strip").value="0";
  rtActionChanged();
  $("rt-form-title").textContent="Add a rule";
  $("rt-form-note").textContent="New rules go to the end of the list.";
  $("rt-cancel").hidden=true;
  setMsg("rt-dp-msg","","status");
}
/* Naming an action makes the server an upsert, so a trunk rule with an empty
   target is saved as "prepend nothing", never as a delete. */
function rtSaveRule(){
  if(!canWrite()){rtNeedLogin("rt-dp-msg");return;}
  var pattern=$("rt-pattern").value.trim();
  if(!pattern){setMsg("rt-dp-msg","Pattern required.","");return;}
  var action=$("rt-action").value;
  var target=$("rt-target").value.trim();
  if(!target&&action!=="trunk"){setMsg("rt-dp-msg","Target required for a "+RT_ACTION_LABEL[action]+" rule.","");return;}
  var body="pattern="+encodeURIComponent(pattern)+"&action="+action+"&target="+encodeURIComponent(target);
  if(action==="trunk"){
    var strip=$("rt-strip").value.trim()||"0";
    if(!/^\d{1,3}$/.test(strip)){setMsg("rt-dp-msg","Strip must be a small non-negative integer.","");return;}
    if(pattern.charAt(pattern.length-1)!=="*"&&Number(strip)>pattern.length){setMsg("rt-dp-msg","Strip is longer than this pattern's fixed length.","");return;}
    body+="&stripDigits="+strip;
  }
  setMsg("rt-dp-msg","Saving "+pattern+"…","");
  post("/api/dialplan",body).then(()=>{
    rtCancelEdit();
    setMsg("rt-dp-msg","Rule "+pattern+" saved.","ok");
    fetchStatus();
  }).catch(e=>{
    setMsg("rt-dp-msg",e.message,msgCls(e));
  });
}
/* Delete is a POST with the pattern and an empty target and no action. The row button is ARM then EXEC. */
function rtDeleteRule(r,btn){
  if(!canWrite()){rtNeedLogin("rt-dp-msg");return;}
  ui.arm(btn,"Delete",()=>{
    post("/api/dialplan","pattern="+encodeURIComponent(r.pattern)+"&target=").then(()=>{
      if($("rt-pattern").readOnly&&$("rt-pattern").value===r.pattern)rtCancelEdit();
      setMsg("rt-dp-msg","Rule "+r.pattern+" deleted.","ok");
      fetchStatus();
    }).catch(e=>{
      setMsg("rt-dp-msg",e.message,msgCls(e));
    });
  });
}
function rtSbcLoad(){
  return httpMethod("GET","/api/sbc-mode").then(d=>{
    var sel=$("rt-sbc-route");
    var max=Number(d.maxRoute)||0;
    sel.textContent="";
    for(var i=0;i<max;i++){
      var o=mk("option");
      o.value=String(i);
      o.textContent="Slot "+(i+1);
      sel.appendChild(o);
    }
    if(!max)throw new Error("this build has no telephony slots");
    var route=Number(d.route)||0;
    sel.value=String(route);
    $("rt-sbc-enabled").checked=!!d.enabled;
    $("rt-sbc-current").textContent=(d.enabled?"On":"Off")+", slot "+(route+1);
    rtSbcReady=true;
    rtAria("rt-sbc-save",!canWrite());
    return true;
  }).catch(e=>{
    rtSbcReady=false;
    rtAria("rt-sbc-save",true);
    $("rt-sbc-current").textContent="—";
    setMsg("rt-sbc-msg","Could not read SBC mode ("+e.message+"). Save is off until it loads.",msgCls(e));
    return false;
  });
}
/* The PUT is followed by a fresh GET so the form shows what the board kept. */
function rtSbcSave(){
  if(!canWrite()){rtNeedLogin("rt-sbc-msg");return;}
  if(!rtSbcReady){setMsg("rt-sbc-msg","SBC mode has not loaded. Save is off until it does.","");return;}
  var en=$("rt-sbc-enabled").checked;
  var route=$("rt-sbc-route").value||"0";
  setMsg("rt-sbc-msg","Saving…","");
  put("/api/sbc-mode","enabled="+(en?"1":"0")+"&route="+encodeURIComponent(route)).then(()=>{
    return rtSbcLoad();
  }).then(ok=>{
    if(ok)setMsg("rt-sbc-msg",en?"SBC mode enabled, slot "+(Number(route)+1)+".":"SBC mode disabled.","ok");
  }).catch(e=>{
    setMsg("rt-sbc-msg",e.message,msgCls(e));
  });
}
function rtGate(){
  var w=canWrite();
  if(!w){
    rtLoaded=false;
    rtSbcReady=false;
  }
  rtAria("rt-save",!w);
  rtAria("rt-sbc-save",!w||!rtSbcReady);
  rtAria("rt-sbc-enabled",!w);
  rtAria("rt-sbc-route",!w);
  var gateTxt=w?"":(adminState.needsSetup?"Admin setup is not finished. Routing changes are locked.":"Log in as admin to change routing.");
  if($("rt-gate-msg").textContent!==gateTxt)setMsg("rt-gate-msg",gateTxt,"");
}
/* Loads the admin-only reads once per visit (no polling of its own). */
function rtLoadAdmin(){
  if(!canWrite()){rtGate();return;}
  if(rtLoaded)return;
  rtLoaded=true;
  setMsg("rt-sbc-msg","","status");
  rtSbcLoad();
}
function rtShown(){
  rtRowsSig="";
  rtRenderRules(rtStatusValue());
  rtLoaded=false;
  rtLoadAdmin();
}
/* The status value is read by the caller's effect before any early return, so
   the effect stays subscribed while the section is hidden. */
function rtOnStatus(d){
  rtRenderRules(d);
  if($("sec-routing").hidden)return;
  rtGate();
  rtLoadAdmin();
}
function rtWatchShow(){
  var sec=$("sec-routing");
  var mo=new MutationObserver(()=>{
    if(!sec.hidden)rtShown();
  });
  mo.observe(sec,{attributes:true,attributeFilter:["hidden"]});
}
function rtBind(){
  $("rt-save").addEventListener("click",rtSaveRule);
  $("rt-cancel").addEventListener("click",rtCancelEdit);
  $("rt-action").addEventListener("change",rtActionChanged);
  $("rt-sbc-save").addEventListener("click",rtSbcSave);
  rtWatchShow();
  store.effect(()=>{rtOnStatus(rtStatusValue());});
  rtActionChanged();
  rtGate();
}
try{rtBind();}catch(e){setMsg("rt-gate-msg","Routing failed to start: "+e.message,"err");}
