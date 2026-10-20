/* 85-maintenance: firmware, backup, factory reset, email, syslog, crash dump, pcap. Wi-Fi: 86-wifi.js. */
var MNT_BODY_CAP=16384;
var mntEmailLoaded=false;
function mntNeed(id,owner){
setMsg(id,adminState.needsSetup?"Finish the first-time admin setup first.":owner?"Owner login required for this action.":"Log in as admin to change this.","");
}
function mntBlocked(id,owner){
var no=owner?!(canWrite()&&isOwner()):!canWrite();
if(no)mntNeed(id,owner);
return no;
}
function mntErr(e){
return e&&e.message?e.message:String(e);
}
function mntFail(id,what,e){
if(e&&e.cancelled)return;
setMsg(id,what+": "+mntErr(e),msgCls(e));
}
function mntCatch(id,what){
return e=>mntFail(id,what,e);
}
function mntText(v){
return v==null||v===""?"—":String(v);
}
function mntList(a){
return Array.isArray(a)&&a.length?a.map(x=>typeof x==="string"?x:JSON.stringify(x)).join(", "):"none";
}
function mntStored(id,on){
setSt($(id),on?"· STORED":"· NOT SET");
}
function mntPick(id){
var el=$(id);
return el&&el.files&&el.files[0];
}
/* rows: [label, text] is a chip (glyph + word) or plain text; [label, number, unit] is a well with its unit outside. */
function mntKV(id,rows){
var dl=$(id);
dl.textContent="";
rows.forEach(r=>{
var row=mk("div"),dt=mk("dt"),dd=mk("dd");
row.className="kvrow";
dt.textContent=r[0];
if(r.length>2){var w=mk("span"),u=mk("span");w.className="well";w.textContent=r[1];u.className="unit";u.textContent=r[2];dd.append(w,u);}
else if(/^[▲◆■·] /.test(r[1])){var sp=mk("span");sp.className="st";sp.textContent=r[1];dd.append(sp);}
else dd.textContent=r[1];
row.append(dt,dd);
dl.append(row);
});
}
function mntSaveBlob(blob,name){
var url=URL.createObjectURL(blob),a=mk("a");
a.href=url;
a.download=name;
document.body.appendChild(a);
a.click();
a.remove();
setTimeout(()=>URL.revokeObjectURL(url),1000);
}
function mntSaveJson(obj,name){
mntSaveBlob(new Blob([JSON.stringify(obj,null,2)],{type:"application/json"}),name);
}
function mntDownload(path,name,msgId){
return fetch(path,{credentials:"same-origin"}).then(r=>{
if(r.status===401&&adminState.loggedIn)handleAuthExpired();
if(!r.ok)return r.text().then(t=>{throw new Error(parseJsonOr(t).error||STATUS_TXT[r.status]||("HTTP "+r.status));});
return r.blob().then(b=>{
mntSaveBlob(b,name);
setMsg(msgId,"Download started: "+name+" ("+fmtBytes(b.size)+").","ok");
});
}).catch(mntCatch(msgId,"Download failed"));
}
/* Firmware status arrives from core's fetchOtaStatus through sig.ota. */
function mntRenderOta(d){
if(!d)return;
if(d.fetchError)return setMsg("mnt-ota-state","Could not read firmware status: "+d.fetchError,"err");
$("mnt-ota-running").textContent=mntText(d.runningPartition);
$("mnt-ota-parts").textContent=mntText(d.boot)+" / "+mntText(d.next);
setSt($("mnt-ota-inprogress"),d.inProgress?"▲ UPDATING":"· IDLE",d.inProgress?"p2":"");
/* A capability, not a fault: nominal glyph either way. */
setSt($("mnt-ota-supported"),d.otaSupported?"· YES":"· NO");
setSt($("mnt-ota-pending"),d.pendingVerify?"▲ PENDING VERIFICATION":"· NONE PENDING",d.pendingVerify?"p2":"");
setMsg("mnt-ota-state","");
}
function mntOtaUpload(){
if(mntBlocked("mnt-ota-msg",true))return;
if(otaUploading)return;
var file=mntPick("mnt-ota-file");
if(!file)return setMsg("mnt-ota-msg","Choose a firmware .bin file first.","");
if(file.size===0)return setMsg("mnt-ota-msg","The file is empty. Choose the firmware image again.","");
var row=$("mnt-ota-prog-row"),bar=$("mnt-ota-prog"),pct=$("mnt-ota-pct");
row.hidden=false;
bar.value=0;
pct.textContent="0";
otaUploading=true;
setMsg("mnt-ota-msg","Uploading "+file.name+" ("+file.size.toLocaleString()+" bytes)…","");
uploadBody("/api/ota/upload",file,f=>{
var p=Math.round(f*100);
bar.value=p;
pct.textContent=String(p);
}).then(d=>{
bar.value=100;
pct.textContent="100";
setMsg("mnt-ota-msg","Upload complete ("+mntText(d.bytes||file.size)+" bytes). Reboot to apply.","ok");
return fetchOtaStatus();
}).catch(e=>{
row.hidden=true;
setMsg("mnt-ota-msg",mntErr(e),"err");
}).then(()=>{otaUploading=false;});
}
/* Reboot drops any active call: ARM then EXEC on the button. */
function otaReboot(){
if(mntBlocked("mnt-ota-msg",false))return;
ui.arm($("mnt-ota-reboot-btn"),"Reboot",()=>{
setMsg("mnt-ota-msg","Rebooting device…","");
post("/api/ota/reboot","confirm=1").then(d=>{
setMsg("mnt-ota-msg",d.message||"Reboot signal sent. Restarting…","ok");
}).catch(mntCatch("mnt-ota-msg","Reboot failed"));
});
}
function mntExport(){
if(mntBlocked("mnt-exp-msg",false))return;
var pw=$("mnt-exp-pw").value;
if(!pw)return getJson("/api/config/export").then(d=>{
mntSaveJson(d,"pocketdial-config.json");
setMsg("mnt-exp-msg","Export downloaded. It has no encrypted secrets block.","ok");
}).catch(mntCatch("mnt-exp-msg","Export failed"));
if(mntBlocked("mnt-exp-msg",true))return;
if(pw.length<12)return setMsg("mnt-exp-msg","The export password must be at least 12 characters.","");
post("/api/config/export",{password:pw}).then(d=>{
$("mnt-exp-pw").value="";
mntSaveJson(d,"pocketdial-config-encrypted.json");
setMsg("mnt-exp-msg","Export downloaded with an encrypted secrets block. Keep the password; the block needs it to open.","ok");
}).catch(mntCatch("mnt-exp-msg","Export failed"));
}
function mntImportWipe(){
$("mnt-imp-pw").value="";
$("mnt-imp-file").value="";
}
function mntImport(){
if(mntBlocked("mnt-imp-msg",false))return;
var pw=$("mnt-imp-pw").value;
if(pw&&!(canWrite()&&isOwner()))return mntNeed("mnt-imp-msg",true);
var file=mntPick("mnt-imp-file");
if(!file)return setMsg("mnt-imp-msg","Choose an export file (.json) first.","");
file.text().then(text=>{
var body={blob:text,confirm:"REPLACE"};
if(pw)body.password=pw;
var size=formBody(body).length;
if(size>MNT_BODY_CAP)return setMsg("mnt-imp-msg","This file is too large for one import request: "+fmtBytes(size)+" once encoded, and the device caps a request body at 16 KB.","");
ui.arm($("mnt-imp-btn"),"Import settings",()=>{
post("/api/config/import",body).then(d=>{
mntImportWipe();
setMsg("mnt-imp-msg","Applied: "+mntList(d.applied)+". Skipped: "+mntList(d.skipped)+".","ok");
}).catch(e=>{
mntImportWipe();
mntFail("mnt-imp-msg","Import failed",e);
});
});
}).catch(mntCatch("mnt-imp-msg","Import failed"));
}
/* The consequence sentence lives in this function because DashboardResetText_test pins it to the body of
   factoryReset. mntBind calls factoryReset() once at load, and that first call only writes the sentence beside
   the button (#mnt-reset-why, the button's aria-describedby); every later call is a press: ERASE typed, then
   ARM, then EXEC. */
var mntResetWhyShown=false;
function factoryReset(){
var why="Factory reset erases: the admin login and DTMF PIN, device settings (AP password, registrar mode), carrier trunk and Telephony API credentials, email and Google service secrets, every extension's SIP password, call forwards, the E911 notify list, DID mappings, call history (including the SD archive), voicemail, the stored crash dump and saved Wi-Fi. Settings from the install-time seed are re-applied. The board then reboots. This cannot be undone.";
if(!mntResetWhyShown){mntResetWhyShown=true;$("mnt-reset-why").textContent=why;return;}
if(mntBlocked("mnt-reset-msg",true))return;
var field=$("mnt-reset-confirm");
if(field.value!=="ERASE")return setMsg("mnt-reset-msg","Type ERASE in the box first.","");
ui.arm($("mnt-reset-btn"),"Factory reset",()=>{
setMsg("mnt-reset-msg","Factory resetting…","");
post("/api/factory-reset","confirm=ERASE").then(d=>{
field.value="";
var m=d.message||"Rebooting…";
setMsg("mnt-reset-msg",m,"");
ui.toast(m,"");
}).catch(e=>{
field.value="";
mntFail("mnt-reset-msg","Factory reset failed",e);
});
});
}
/* POST overwrites host, user, from, to and gsaEmail, so every field is sent,
   and the form reloads from the device before Save turns on. */
function mntLoadEmail(){
return getJson("/api/email").then(d=>{
$("mnt-mail-host").value=d.host||"";
$("mnt-mail-port").value=d.port==null?"":String(d.port);
$("mnt-mail-mode").value=d.mode||"starttls";
$("mnt-mail-auth").value=d.auth||"none";
$("mnt-mail-user").value=d.user||"";
$("mnt-mail-from").value=d.from||"";
$("mnt-mail-to").value=d.to||"";
$("mnt-mail-gsa").value=d.gsaEmail||"";
$("mnt-mail-insecure").checked=!!d.insecure;
$("mnt-mail-pass").value="";
$("mnt-mail-gsakey").value="";
$("mnt-mail-capem").value="";
mntStored("mnt-mail-pass-state",d.hasPassword);
mntStored("mnt-mail-gsakey-state",d.hasGsaKey);
mntStored("mnt-mail-capem-state",d.hasCaPem);
mntEmailLoaded=true;
$("mnt-mail-save").setAttribute("aria-disabled","false");
setMsg("mnt-mail-load-msg","");
}).catch(e=>{
mntEmailLoaded=false;
$("mnt-mail-save").setAttribute("aria-disabled","true");
setMsg("mnt-mail-load-msg","Could not load email settings: "+mntErr(e)+". Save stays off until they load.",msgCls(e));
});
}
function mntEmailSave(){
if(mntBlocked("mnt-mail-msg",false))return;
if(!mntEmailLoaded)return setMsg("mnt-mail-msg","The email settings have not loaded. Reload them before saving.","");
var body={
host:$("mnt-mail-host").value.trim(),
port:$("mnt-mail-port").value.trim(),
mode:$("mnt-mail-mode").value,
auth:$("mnt-mail-auth").value,
user:$("mnt-mail-user").value.trim(),
from:$("mnt-mail-from").value.trim(),
to:$("mnt-mail-to").value.trim(),
gsaEmail:$("mnt-mail-gsa").value.trim(),
insecure:$("mnt-mail-insecure").checked?"1":"0"
};
var pass=$("mnt-mail-pass").value,gsaKey=$("mnt-mail-gsakey").value,caPem=$("mnt-mail-capem").value;
if(pass)body.pass=pass;
if(gsaKey)body.gsaKey=gsaKey;
if(caPem)body.caPem=caPem;
post("/api/email",body).then(()=>{
setMsg("mnt-mail-msg","Saved. The fields show what the device kept.","ok");
return mntLoadEmail();
}).catch(mntCatch("mnt-mail-msg","Could not save"));
}
function mntEmailTest(){
if(mntBlocked("mnt-mail-test-msg",false))return;
var to=$("mnt-mail-testto").value.trim();
setMsg("mnt-mail-test-msg","Sending the test message…","");
post("/api/email/test",to?{to:to}:{}).then(d=>{
if(d.ok)setMsg("mnt-mail-test-msg","Test message sent.","ok");
else setMsg("mnt-mail-test-msg","Test failed: "+mntText(d.error)+(d.smtpReplyCode?" (SMTP reply "+d.smtpReplyCode+")":""),"err");
}).catch(mntCatch("mnt-mail-test-msg","Test failed"));
}
function mntLoadSyslog(){
return getJson("/api/syslog").then(d=>{
if(d.supported===false)setSt($("mnt-sys-state"),"· NOT SUPPORTED ON THIS BUILD");
else setSt($("mnt-sys-state"),d.enabled?"· ON, SENDING TO "+mntText(d.host)+":"+mntText(d.port):"· OFF");
$("mnt-sys-host").value=d.host||"";
$("mnt-sys-port").value=d.port==null?"":String(d.port);
setMsg("mnt-sys-msg","");
}).catch(mntCatch("mnt-sys-msg","Could not read the syslog target"));
}
function mntSyslogSave(){
if(mntBlocked("mnt-sys-msg",false))return;
post("/api/syslog",{host:$("mnt-sys-host").value.trim(),port:$("mnt-sys-port").value.trim()}).then(d=>{
setMsg("mnt-sys-msg",d.message||"Saved.","ok");
return mntLoadSyslog();
}).catch(mntCatch("mnt-sys-msg","Could not save"));
}
function mntLoadCoredump(){
return getJson("/api/coredump/info").then(d=>{
mntKV("mnt-core-kv",[
["Supported",d.supported?"· YES":"· NO"],
["Stored dump",d.present?"▲ PRESENT":"· NONE"],
["Size"].concat(d.present&&d.size!=null?fmtBytes(d.size).split(" "):["—","B"]),
["Valid",d.valid?"· YES":"· NO"],
["Task",mntText(d.task)],
["Program counter",mntText(d.pc)],
["Firmware ELF SHA",mntText(d.elfSha)],
["Reason",mntText(d.reason)]
]);
setMsg("mnt-core-msg","");
}).catch(mntCatch("mnt-core-msg","Could not read crash dump status"));
}
function mntCoreDownload(){
if(mntBlocked("mnt-core-msg",true))return;
mntDownload("/api/coredump","pocketdial-coredump.bin","mnt-core-msg");
}
/* Erasing the dump cannot be undone: ARM then EXEC on the button. */
function mntCoreErase(){
if(mntBlocked("mnt-core-msg",false))return;
ui.arm($("mnt-core-erase"),"Erase dump",()=>{
post("/api/coredump/erase","").then(()=>{
setMsg("mnt-core-msg","Crash dump erased.","ok");
return mntLoadCoredump();
}).catch(mntCatch("mnt-core-msg","Erase failed"));
});
}
function mntPcap(){
if(mntBlocked("mnt-pcap-msg",false))return;
mntDownload("/api/pcap","pocketdial-capture.pcap","mnt-pcap-msg");
}
function mntBind(){
[["ota-upload-btn",mntOtaUpload],["ota-reboot-btn",otaReboot],["exp-btn",mntExport],["imp-btn",mntImport],
["reset-btn",factoryReset],["mail-save",mntEmailSave],["mail-test-btn",mntEmailTest],
["sys-save",mntSyslogSave],["core-refresh",mntLoadCoredump],["core-dl",mntCoreDownload],["core-erase",mntCoreErase],
["pcap-btn",mntPcap]
].forEach(p=>{$("mnt-"+p[0]).addEventListener("click",p[1]);});
factoryReset();
}
mntBind();
/* The OTA panel follows core's signal. */
store.effect(()=>{mntRenderOta(sig.ota.get());});
/* Opening the section or an admin change loads the logged-in readouts. The loaders read no signals,
   so this effect keeps only the nav and admin deps. */
store.effect(()=>{
var n=sig.nav.get(),a=sig.admin.get();
if(n!=="maintenance"||!a.loggedIn||a.needsSetup)return;
mntLoadSyslog();
mntLoadEmail();
mntLoadCoredump();
});
