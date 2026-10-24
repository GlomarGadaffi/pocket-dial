/* 86-wifi: Wi-Fi scan and connect, Standalone AP switch, hold setup mode. Guarded by
   POCKETDIAL_HAS_WIFI in manifest.txt: builds without a radio leave this file out, so nothing
   in 85-maintenance.js may name anything defined here. Its markup is sections/86-wifi.html,
   inserted at <div id="wifi-slot"> in the Maintenance section.
   Uses from 85-maintenance.js: mntNeed, mntFail. From core: $, mk, setMsg, getJson, post, canWrite, ui. */

var mntWifiSelected="";

function mntBars(rssi){
  if(!isFinite(rssi))return "—";
  return rssi>-50?"▂▄▆█":rssi>-65?"▂▄▆ ":rssi>-75?"▂▄  ":"▂   ";
}
/* ---- network: Wi-Fi scan, Standalone AP, setup mode ---- */
function mntScanWifi(){
  setMsg("mnt-scan-msg","Scanning…","");
  getJson("/api/wifi/scan").then(d=>{
    var nets=Array.isArray(d.networks)?d.networks:[];
    renderWifi(nets);
    var n=nets.length;
    setMsg("mnt-scan-msg","Found "+n+(n===1?" network":" networks")+(d.note?". "+String(d.note):"."),"ok");
  }).catch(e=>{mntFail("mnt-scan-msg","Scan failed",e);});
}
/* Each network is a button row. Choosing one opens the password form below the list. */
function renderWifi(nets){
  var list=$("mnt-wifi-list");list.textContent="";
  if(!nets.length){
    var p=mk("p");p.className="hint";p.textContent="No networks found.";list.appendChild(p);return;
  }
  nets.forEach(n=>{
    var ssid=String(n.ssid==null?"":n.ssid);
    var rssi=n.rssi==null||n.rssi===""?NaN:Number(n.rssi);
    var enc=n.encryption?String(n.encryption):"open";
    var row=document.createElement("button");row.type="button";row.className="wifi-net";
    row.addEventListener("click",()=>{mntSelectWifi(ssid);});
    var s=mk("span");s.className="mono";s.textContent=ssid||"(hidden network)";
    var m=mk("span");m.className="muted mono";
    m.textContent=mntBars(rssi)+" "+(isFinite(rssi)?rssi+" dBm":"no signal reading")+" "+enc;
    row.appendChild(s);row.appendChild(m);list.appendChild(row);
  });
}
function mntSelectWifi(ssid){
  mntWifiSelected=ssid;
  $("mnt-wifi-ssid").textContent=ssid||"(hidden network)";
  $("mnt-wifi-pw").value="";
  $("mnt-wifi-connect").hidden=false;
  $("mnt-wifi-pw").focus();
}
function mntWifiCancel(){
  mntWifiSelected="";
  $("mnt-wifi-pw").value="";
  $("mnt-wifi-connect").hidden=true;
}
function mntWifiConnect(){
  if(!canWrite()){mntNeed("mnt-wifi-msg",false);return;}
  if(!mntWifiSelected){setMsg("mnt-wifi-msg","Choose a network first.","");return;}
  var ssid=mntWifiSelected;
  var pw=$("mnt-wifi-pw").value;
  setMsg("mnt-wifi-msg","Connecting to "+ssid+"…","");
  post("/api/wifi/connect",{ssid:ssid,password:pw}).then(d=>{
    $("mnt-wifi-pw").value="";
    setMsg("mnt-wifi-msg",d.message||"Connect request sent.","ok");
  }).catch(e=>{
    $("mnt-wifi-pw").value="";
    mntFail("mnt-wifi-msg","Connect failed",e);
  });
}
/* Standalone AP reboots the board (the hint below the buttons says so): ARM then EXEC on the button. */
function startApMode(){
  if(!canWrite()){mntNeed("mnt-net-msg",false);return;}
  ui.arm($("mnt-ap-btn"),"Switch to Standalone AP",()=>{
    setMsg("mnt-net-msg","Enabling AP mode…","");
    post("/api/wifi/mode_ap","").then(d=>{
      setMsg("mnt-net-msg",d.message||"AP mode set. Rebooting…","ok");
    }).catch(e=>{mntFail("mnt-net-msg","AP mode failed",e);});
  });
}
function holdConfigMode(){
  if(!canWrite()){mntNeed("mnt-net-msg",false);return;}
  post("/api/configuring","").then(d=>{
    var m=d.message||"Setup mode held.";
    setMsg("mnt-net-msg",m,"ok");
    ui.toast(m,"ok");
  }).catch(e=>{mntFail("mnt-net-msg","Could not hold setup mode",e);});
}

function mntWifiBind(){
  [["scan-btn",mntScanWifi],["wifi-connect-btn",mntWifiConnect],["wifi-cancel-btn",mntWifiCancel],
   ["ap-btn",startApMode],["cfg-btn",holdConfigMode]
  ].forEach(p=>{$("mnt-"+p[0]).addEventListener("click",p[1]);});
}

mntWifiBind();
