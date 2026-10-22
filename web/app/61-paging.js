/* 61-paging: multicast paging settings (GET/PUT /api/multicast-paging). Guarded in manifest.txt by
   POCKETDIAL_MULTICAST_PAGING: builds without paging leave this file out, so nothing in
   60-call-handling.js may name anything defined here except through the typeof check on
   chPagingTick. Its markup is sections/61-paging.html, inserted at <div id="paging-slot"> in the
   Call handling section.
   Uses from 60-call-handling.js: chWriteGate. From core: $, setMsg, put, httpMethod, canWrite, adminState, fm. */
var chMc={loaded:false,ok:false};

/* Called by renderCallHandling on every poll while the section is shown. Loads the form once per login. */
function chPagingTick(authed){
  if(!adminState.loggedIn)chMc.loaded=false;
  if(authed&&!chMc.loaded)chLoadMulticast();
}
function chSetSaveEnabled(on){
  $("ch-mc-save").setAttribute("aria-disabled",on?"false":"true");
}
/* Reads GET /api/multicast-paging once per login. A failed read leaves Save
   disabled; the Reload button is the retry. Form fields are filled only here. */
function chLoadMulticast(){
  if(!canWrite()){
    setMsg("ch-mc-msg","Log in to read paging settings.","");
    return;
  }
  chMc.loaded=true;
  setMsg("ch-mc-state","Reading paging settings...","ok");
  Promise.resolve(httpMethod("GET","/api/multicast-paging")).then(d=>{
    chMc.ok=true;
    $("ch-mc-enabled").checked=!!d.enabled;
    $("ch-mc-group").value=d.group||"";
    $("ch-mc-port").value=d.port!==undefined?String(d.port):"";
    chSetSaveEnabled(true);
    setMsg("ch-mc-state",(d.enabled?"Paging enabled":"Paging off")+", group "+(d.group||"unset")+", port "+(d.port!==undefined?d.port:"unset")+".","ok");
  }).catch(err=>{
    chMc.ok=false;
    chSetSaveEnabled(false);
    setMsg("ch-mc-state","Paging settings could not be read. This firmware build may not include multicast paging.",msgCls(err));
    setMsg("ch-mc-msg",err.message,msgCls(err));
  });
}
function chSaveMulticast(){
  if($("ch-mc-save").getAttribute("aria-disabled")==="true"){
    setMsg("ch-mc-msg","Paging settings have not loaded. Use Reload paging first.","");
    return;
  }
  if(!chWriteGate("ch-mc-msg"))return;
  var on=$("ch-mc-enabled").checked?"1":"0";
  var group=$("ch-mc-group").value.trim();
  var port=$("ch-mc-port").value.trim();
  put("/api/multicast-paging","enabled="+on+"&group="+encodeURIComponent(group)+"&port="+encodeURIComponent(port))
    .then(()=>{
      setMsg("ch-mc-msg","Paging settings saved.","ok");
      chLoadMulticast();
    })
    .catch(fm("ch-mc-msg",""));
}
