/* 80-security: admin login and PIN, owner login, Wi-Fi access point security, and the
   E911 notification form. Log in, log out and first-time setup are core's (openLogin,
   adminLogout, view-setup). Core owns httpMethod, post/put, setMsg, ui, adminState,
   fetchAdminStatus, fetchStatus, applyE911 and nav. This file only calls them. */

var secApSecure=false;

function secWriteGate(msgId){
  if(canWrite())return true;
  setMsg(msgId,adminState.needsSetup?"Finish the admin setup first.":"Log in before changing settings.","");
  return false;
}

/* Runs when Security is shown and when the session changes. Nothing is fetched before a session exists. */
function securityShown(){
  securityRender();
  if(!adminState.loggedIn||adminState.needsSetup)return;
  fetchE911();
  fetchApSecurity();
}

/* Shows exactly one of: log-in prompt or the admin view. First-time setup is core's view-setup. */
function securityRender(){
  var authed=canWrite();
  $("sec-login").hidden=authed;
  $("sec-admin").hidden=!authed;
  if(!authed)return;
  var role=String(adminState.role||"").toLowerCase();
  $("sec-role").textContent="Role: "+(role||"unknown");
  if(!adminState.ownerProvisioned)$("sec-owner-state").textContent="No owner login exists yet. Any admin session can create the first one.";
  else if(role==="owner")$("sec-owner-state").textContent="You are signed in as owner.";
  else $("sec-owner-state").textContent="An owner login is set. Only an owner session can change it.";
  var b=$("sec-owner-save");
  b.setAttribute("aria-disabled",isOwner()?"false":"true");
  /* Replacing an existing owner is destructive: its trigger is ARM then EXEC. A first owner is a plain save. */
  ui.disarm(b);
  b.textContent=adminState.ownerProvisioned?"[ ARM ] Replace owner login":"Save owner login";
  b.className=adminState.ownerProvisioned?"btn":"btn btn-primary";
  b.setAttribute("aria-label",b.textContent);
}

function securityChangeCredential(){
  if(!secWriteGate("sec-cred-msg"))return;
  var user=$("sec-cred-user").value.trim(),pass=$("sec-cred-pass").value;
  if(!user||pass.length<8){setMsg("sec-cred-msg","Username and an 8+ character password are required.","");return;}
  post("/api/admin/set-credential",{username:user,password:pass}).then(()=>{
    $("sec-cred-pass").value="";
    setMsg("sec-cred-msg","Admin login updated.","ok");
  }).catch(fm("sec-cred-msg"));
}

function securityChangeDtmfPin(){
  if(!secWriteGate("sec-pin-msg"))return;
  var pin=$("sec-cred-pin").value;
  if(!/^\d{4,16}$/.test(pin)){setMsg("sec-pin-msg","The DTMF PIN must be 4 to 16 digits.","");return;}
  post("/api/admin/set-credential",{dtmfPin:pin}).then(()=>{
    $("sec-cred-pin").value="";
    setMsg("sec-pin-msg","DTMF PIN updated.","ok");
  }).catch(fm("sec-pin-msg"));
}

/* The server allows a Sysop session to create the first owner. Once an owner exists,
   only an owner session may replace it. */
function securitySetOwner(){
  if(!secWriteGate("sec-owner-msg"))return;
  if(!isOwner()){setMsg("sec-owner-msg","Only an owner session can change the owner login.","");return;}
  var user=$("sec-owner-user").value.trim(),pass=$("sec-owner-pass").value;
  if(!user||!pass){setMsg("sec-owner-msg","Owner username and password are required.","");return;}
  var send=()=>{
    post("/api/admin/set-owner-credential",{ownerUsername:user,ownerPassword:pass}).then(()=>{
      $("sec-owner-pass").value="";
      setMsg("sec-owner-msg","Owner login saved.","ok");
      return fetchAdminStatus();
    }).catch(fm("sec-owner-msg"));
  };
  if(adminState.ownerProvisioned)ui.arm($("sec-owner-save"),"Replace owner login",send);else send();
}

/* The PSK comes back in clear. It is shown masked; the reveal button only changes the field type. */
function renderApSecurity(d){
  if(typeof d.secure!=="undefined"){
    secApSecure=!!d.secure;
    $("ap-secure").checked=secApSecure;
    setSt($("ap-mode"),secApSecure?"· WPA2 (ENCRYPTED)":"▲ OPEN (UNENCRYPTED)",secApSecure?"":"p2");
  }
  if(typeof d.psk!=="undefined")$("ap-psk").value=d.psk||"";
  secApLabel();
}

/* Save is a plain save unless it turns WPA2 on (every phone re-joins): then it reads [ ARM ] Turn on WPA2. */
function secApLabel(){
  var b=$("ap-save"),on=$("ap-secure").checked&&!secApSecure;
  ui.disarm(b);
  b.textContent=on?"[ ARM ] Turn on WPA2":"Save";
  b.className=on?"btn":"btn btn-primary";
}

function fetchApSecurity(){
  getJson("/api/ap-security")
  .then(d=>{renderApSecurity(d);})
  .catch(e=>{setMsg("ap-msg","Could not read access point security ("+e.message+").",msgCls(e));});
}

function secTogglePsk(){
  var f=$("ap-psk"),b=$("ap-psk-reveal"),reveal=f.type==="password";
  f.type=reveal?"text":"password";
  b.textContent=reveal?"Hide":"Show";
  b.setAttribute("aria-pressed",reveal?"true":"false");
}

/* Turning WPA2 on is a breaking change for associated phones (#ap-break-note says so), so that save is ARM then EXEC. */
function saveApSecurity(){
  if(!secWriteGate("ap-msg"))return;
  var psk=$("ap-psk").value,on=$("ap-secure").checked;
  if(psk.length<8||psk.length>63){setMsg("ap-msg","Passphrase must be 8–63 characters.","");return;}
  var send=()=>{
    post("/api/ap-security",{secure:on?"1":"0",psk:psk}).then(d=>{
      renderApSecurity(d);
      setMsg("ap-msg","Saved. Takes effect the next time the access point starts.","ok");
    }).catch(fm("ap-msg"));
  };
  if(on&&!secApSecure)ui.arm($("ap-save"),"Turn on WPA2",send);else send();
}

/* A new passphrase locks out every phone that has not re-joined, so it runs ARM then EXEC. */
function regenApPsk(){
  if(!secWriteGate("ap-msg"))return;
  ui.arm($("ap-regen"),"Generate new passphrase",()=>{
    post("/api/ap-security",{regenerate:"1"}).then(d=>{
      renderApSecurity(d);
      setMsg("ap-msg","New passphrase generated. Write it down before the access point restarts.","ok");
    }).catch(fm("ap-msg"));
  });
}
$("ap-secure").addEventListener("change",secApLabel);

function fillE911(d){
  if(!d)return;
  if(d.notifyExts!==undefined)$("e911-exts").value=d.notifyExts;
  if(d.callback!==undefined)$("e911-callback").value=d.callback;
  if(d.location!==undefined)$("e911-location").value=d.location;
}

/* Save stays off until a load succeeds: saving blank fields would erase the notify list. */
function fetchE911(){
  fetch("/api/e911-config",{credentials:"same-origin"}).then(r=>{
    if(r.status===401)throw new Error("log in again");
    return rj(r);
  }).then(d=>{
    fillE911(d);
    $("e911-save").disabled=false;
    setMsg("e911-msg","","");
  })
  .catch(e=>{
    $("e911-save").disabled=true;
    setMsg("e911-msg","Could not load E911 settings ("+e.message+"). Save is off until they load.",msgCls(e));
  });
}

/* The server echoes what it kept (list truncated, bad field dropped), so show that. */
function saveE911(){
  if(!secWriteGate("e911-msg"))return;
  put("/api/e911-config",{notifyExts:$("e911-exts").value.trim(),callback:$("e911-callback").value.trim(),location:$("e911-location").value.trim()})
  .then(d=>{
    fillE911(d);
    setMsg("e911-msg","Saved. The fields show what was kept.","ok");
    fetchStatus();
  })
  .catch(fm("e911-msg",""));
}

/* #167: the board states whether it has a radio. The AP section is hidden when
   /api/status reports wifiCapable false. An ABSENT wifiCapable (older firmware) shows it,
   so the page never infers "no radio" from an empty scan. */
function applyApCapable(d){
  var s=$("ap-security-section");
  if(!s||!d||typeof d.wifiCapable==="undefined")return;
  s.style.display=d.wifiCapable?"":"none";
}

store.effect(()=>{
  sig.admin.get();
  if(sig.nav.get()==="security")securityShown();
});
store.effect(()=>{
  var d=sig.status.get();
  if(d)applyApCapable(d);
});
