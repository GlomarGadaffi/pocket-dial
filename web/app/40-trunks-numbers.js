/* Trunks & numbers. Server text via textContent only. DID mapping is 41-did.js (left out of the SBC build),
   reached only through the typeof check in tnLoad; nothing else here may name it. */
var tnSlots=[];
var tnSelected=0;
var tnTest={};
var tnAcceptVer=0;
var tnSlotMsg="tn-tapi-msg";
var tnFieldIds=["tn-tapi-baseurl","tn-tapi-clientid","tn-tapi-secret","tn-tapi-routedn"];
var tnWriteIds=tnFieldIds.concat(["tn-tapi-enabled","tn-tapi-save","tn-tapi-activate","tn-tapi-clear"]);
function tnBody(v){
try{return typeof v==="string"?JSON.parse(v)||{}:v||{};}catch(e){return {};}
}
function tnEl(tag,v,cls){
var e=mk(tag);
if(cls)e.className=cls;
if(typeof v==="string")e.textContent=v;
else if(v)e.append(v);
return e;
}
function tnGet(path,id,fn){
return httpMethod("GET",path).then(r=>fn(tnBody(r))).catch(fm(id,""));
}
function tnThen(p,id,txt,refresh){
return p.then(()=>{setMsg(id,txt,"ok");return refresh();}).catch(fm(id,""));
}
function tnStatusEl(cls,glyph,word){
var s=tnEl("span",0,"st "+cls);
var g=tnEl("span",glyph,"g");
g.setAttribute("aria-hidden","true");
s.append(g,word);
return s;
}
function tnText(s){
return tnEl("span",s,"mono");
}
function tnSetOff(id,off){
var el=$(id);
if(!el)return;
el.setAttribute("aria-disabled",off?"true":"false");
if(el.tagName==="INPUT"&&el.type!=="checkbox")el.readOnly=off;
}
function tnApplyGate(){
var ready=canWrite();
tnWriteIds.forEach(id=>tnSetOff(id,!ready));
if(ready)return setMsg("tn-gate","","");
setMsg("tn-gate",adminState.needsSetup?"Finish admin setup first. Trunks and numbers are unavailable until then.":"Log in to view or change trunks and numbers.","");
}
function tnGuard(){
var ok=canWrite();
if(!ok)tnApplyGate();
return ok;
}
function tnClearViews(){
["tn-tapi-body","tn-trunk-kv","tn-tapi-secret-state"].forEach(id=>$(id).textContent="");
$("tn-tapi-active").textContent="—";
$("tn-accept-banner").style.display="none";
$("tn-tapi-edit-title").textContent="Configure slot";
tnFieldIds.forEach(id=>$(id).value="");
$("tn-tapi-enabled").checked=false;
tnSlots=[];
tnSelected=0;
tnTest={};
tnSetOff("tn-tapi-test",true);
setMsg("tn-test-result","","");
}
function tnLoad(){
tnApplyGate();
if(typeof tnDidLoad==="function")tnDidLoad();
if(!canWrite())return tnClearViews();
tnFetchSlots(false);
tnFetchTrunk();
}
function tnFetchSlots(keepForm){
return tnGet("/api/telephony-config",tnSlotMsg,d=>{
tnSlots=d.slots||[];
tnAcceptVer=d.acceptanceVersion||0;
tnRenderSlots();
if(keepForm)tnUpdateEditMeta();
else tnSelectSlot(tnSelected);
});
}
function tnChipEl(s){
if(!(s.baseUrl||s.clientId||s.secretSet||s.routeDn||s.enabled))return tnStatusEl("standby","·","Not configured");
if(!s.implemented)return tnStatusEl("warning","▲","Configured, not yet connected");
if(s.active&&!s.enabled)return tnStatusEl("warning","▲","Selected, disabled");
return s.active?tnStatusEl("ok","·","Active"):tnStatusEl("standby","·","Configured");
}
function tnBtn(cls,label,aria,enabled,fn){
var b=tnEl("button",label,cls);
b.type="button";
b.setAttribute("aria-label",aria);
b.setAttribute("aria-disabled",enabled?"false":"true");
b.onclick=()=>{if(b.getAttribute("aria-disabled")!=="true")fn(b);};
return b;
}
function tnRenderSlots(){
var body=$("tn-tapi-body");
var lbl="None (loopback default)";
var miss=[];
body.textContent="";
tnSlots.forEach((s,i)=>{
if(s.active)lbl="Slot "+(i+1)+(!s.enabled?" (disabled, loopback runs)":s.implemented?"":" (not yet connected)");
if(s.acceptanceMissing)miss.push(i+1);
var acts=tnEl("div",0,"row-btns");
acts.append(tnBtn("btn","Edit","Edit slot "+(i+1),canWrite(),()=>tnEditSlot(i)));
if(!s.active)acts.append(tnBtn("btn","Activate","Activate slot "+(i+1),canWrite(),()=>tnActivate(i)));
var tr=tnEl("tr");
tr.append(tnEl("td","Slot "+(i+1)),tnEl("td",tnChipEl(s)),tnEl("td",s.baseUrl||"—","mono"),tnEl("td",s.routeDn||"—","mono"),tnEl("td",acts));
body.append(tr);
});
$("tn-tapi-active").textContent=lbl;
$("tn-accept-banner").style.display=miss.length?"":"none";
$("tn-accept-text").textContent=miss.length?"Slot "+miss.join(", ")+(miss.length>1?" are":" is")+" enabled without a recorded acceptance of the limitations. It keeps working. Edit it and accept to record who accepted and when.":"";
}
function tnEditSlot(i){
tnSelectSlot(i);
setMsg(tnSlotMsg,"","");
}
function tnSecretState(set){
var el=$("tn-tapi-secret-state");
el.textContent="";
el.append(set?tnStatusEl("ok","·","Secret stored. Leave blank to keep it."):tnStatusEl("standby","·","No secret stored."));
}
function tnSelectSlot(i){
if(!tnSlots.length)return;
tnSelected=Math.min(Math.max(0,i),tnSlots.length-1);
var s=tnSlots[tnSelected]||{};
$("tn-tapi-baseurl").value=s.baseUrl||"";
$("tn-tapi-clientid").value=s.clientId||"";
$("tn-tapi-secret").value="";
$("tn-tapi-routedn").value=s.routeDn||"";
$("tn-tapi-enabled").checked=!!s.enabled;
tnSecretState(!!s.secretSet);
tnUpdateEditMeta();
tnShowTest(tnSelected);
}
function tnUpdateEditMeta(){
if(!tnSlots.length)return;
var s=tnSlots[tnSelected]||{};
$("tn-tapi-edit-title").textContent="Configure slot "+(tnSelected+1)+(s.active?" (active)":"");
tnSetOff("tn-tapi-test",!(canWrite()&&s.active&&s.implemented));
}
function tnSaveSlot(){
if(!tnGuard()||!tnSlots.length)return;
var i=tnSelected;
var turningOn=$("tn-tapi-enabled").checked&&!(tnSlots[i]&&tnSlots[i].enabled&&tnSlots[i].accepted);
if(turningOn){
ui.accept().then(ok=>{
if(ok)tnSaveSlotNow(i,true);
else{$("tn-tapi-enabled").checked=false;setMsg(tnSlotMsg,"Not enabled. The slot stays off until you accept the limitations.","");}
});
return;
}
tnSaveSlotNow(i,false);
}
function tnSaveSlotNow(i,accepted){
var f={
enabled:$("tn-tapi-enabled").checked?"1":"0",
baseUrl:$("tn-tapi-baseurl").value.trim(),
clientId:$("tn-tapi-clientid").value.trim(),
secret:$("tn-tapi-secret").value,
routeDn:$("tn-tapi-routedn").value.trim()
};
if(accepted)f.acceptLimitations=String(tnAcceptVer);
var q=new URLSearchParams(f).toString();
tnThen(put("/api/telephony-config/"+i,q),tnSlotMsg,"Slot "+(i+1)+" saved.",()=>tnFetchSlots(false));
}
function tnActivate(i){
if(!tnGuard()||!tnSlots.length)return;
if(tnSlots[i]&&tnSlots[i].active)return;
if(tnSlots[i]&&tnSlots[i].accepted)return tnActivateNow(i,false);
ui.accept().then(ok=>{
if(!ok){setMsg(tnSlotMsg,"Not activated. The slot stays off until you accept the limitations.","");return;}
tnActivateNow(i,true);
});
}
function tnActivateNow(i,accepted){
tnThen(post("/api/telephony-config/"+i+"/activate",accepted?"acceptLimitations="+tnAcceptVer:""),tnSlotMsg,"Slot "+(i+1)+" is now active.",()=>tnFetchSlots(true));
}
function tnShowTest(i){
if(i!==tnSelected)return;
var r=tnTest[i];
if(!r)return setMsg("tn-test-result","","");
setMsg("tn-test-result","last test: "+(r.ok?"OK":"FAIL")+(r.detail?" · "+r.detail:"")+" · "+r.at.toLocaleTimeString(),r.ok?"ok":"err");
}
function tnTestSlot(){
if(!tnGuard()||!tnSlots.length)return;
var i=tnSelected;
var s=tnSlots[i]||{};
if(!(s.active&&s.implemented))return setMsg(tnSlotMsg,"Slot "+(i+1)+" must be active and connected before testing.","");
var btn=$("tn-tapi-test");
btn.setAttribute("aria-disabled","true");
btn.textContent="Dialing…";
post("/api/telephony-config/"+i+"/test","").then(t=>{
var d=tnBody(t);
tnTest[i]={ok:!!d.ok,detail:(d.ok?d.participantId:d.error)||"",at:new Date()};
}).catch(e=>tnTest[i]={ok:false,detail:e.message,at:new Date()}).then(()=>{
btn.textContent="Test dial";
tnShowTest(i);
tnUpdateEditMeta();
});
}
function tnClearSlot(){
if(!tnGuard()||!tnSlots.length)return;
var i=tnSelected;
ui.arm($("tn-tapi-clear"),"Clear slot",()=>tnThen(del("/api/telephony-config/"+i,""),tnSlotMsg,"Slot "+(i+1)+" cleared.",()=>tnFetchSlots(false)));
}
function tnFetchTrunk(){
return tnGet("/api/trunk","tn-trunk-msg",tnRenderTrunk);
}
function tnKvRow(dl,label,valueEl){
var row=tnEl("div",0,"kvrow");
row.append(tnEl("dt",label),tnEl("dd",valueEl));
dl.append(row);
}
function tnRenderTrunk(t){
var dl=$("tn-trunk-kv");
dl.textContent="";
tnKvRow(dl,"Enabled",t.enabled?tnStatusEl("ok","·","On"):tnStatusEl("standby","·","Off"));
[["Host",t.host],["Port",t.port?""+t.port:""],["Outbound proxy",t.proxyHost?t.proxyHost+(t.proxyPort?":"+t.proxyPort:""):""],["From user",t.fromUser],["Caller ID",t.callerId],["Auth user",t.authUser]].forEach(p=>tnKvRow(dl,p[0],tnText(p[1]||"not set")));
tnKvRow(dl,"Password",t.hasPassword?tnStatusEl("ok","·","Stored"):tnStatusEl("standby","·","Not set"));
}
store.effect(()=>{
sig.admin.get();
if(sig.nav.get()==="trunks-numbers")tnLoad();
});
