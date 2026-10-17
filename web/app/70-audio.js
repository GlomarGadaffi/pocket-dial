/* ── Audio section: music on hold, preview, media transmit ──
   Routes: GET /api/moh, POST /api/moh/upload (raw WAV, XHR),
   POST /api/moh/preview, POST /api/moh/preview/stop, POST /api/media-tx (Owner).
   Core helpers used: $, setMsg, post, adminState, isOwner, sig.moh, fetchMohStatus. */
var mohUploading=false;
var MOH_MAX_BYTES=8*1024*1024;

function audioOwner(){
  return canWrite()&&isOwner();
}
function audioAria(id,off){
  var el=$(id);
  if(el)el.setAttribute("aria-disabled",off?"true":"false");
}
function audioSetText(id,txt,cls){
  var el=$(id);
  if(el&&el.textContent===txt)return;
  setMsg(id,txt,cls);
}
function audioNeedLogin(id){
  setMsg(id,adminState.needsSetup?"Finish admin setup first.":"Admin login required.","");
}
function audioGate(){
  var w=canWrite(),o=audioOwner();
  audioAria("moh-upload-btn",!w);
  audioAria("moh-play-btn",!w);
  audioAria("moh-stop-btn",!w);
  audioAria("mtx-save",!o);
  audioAria("mtx-nodelay",!o);
  audioSetText("moh-gate-msg",w?"":(adminState.needsSetup?"Admin setup is not finished. Music on hold and media transmit are locked.":"Log in as admin to manage music on hold."),"");
  audioSetText("mtx-hint",(w&&!o)?"Owner login required to change this switch.":"","");
}
/* Core polls GET /api/moh every 3 s while Audio is shown (fetchMohStatus) and publishes it on
   sig.moh. This paints it. */
function audioRenderMoh(d){
  audioGate();
  if(!canWrite())return;
  if(!d)return;
  if(d.fetchError){
    setMsg("moh-status-msg","Could not read music on hold status ("+d.fetchError+").","err");
    return;
  }
  audioSetText("moh-status-msg","","status");
  var clip=$("moh-clip"),len=$("moh-len"),lis=$("moh-listeners"),note=$("moh-listeners-note"),ps=$("moh-preview-state");
  if(!d.supported){
    setSt(clip,"· NOT AVAILABLE: NO SD CARD SUPPORT");
    len.textContent="—";
    note.textContent="";
    lis.textContent="\u2014";
    ps.textContent="\u2014";
    return;
  }
  setSt(clip,d.loaded?"· LOADED":"· NO CLIP ON THE CARD");
  len.textContent=d.loaded?fmtClock(d.seconds):"—";
  var n=d.listeners||0;
  lis.textContent=String(n);
  note.textContent=d.preview?"includes the preview":"";
  setSt(ps,d.preview?("▲ PLAYING TO "+d.preview):"· NO PREVIEW RUNNING",d.preview?"live":"");
}
function mohUpload(){
  if(mohUploading)return;
  if(!canWrite()){audioNeedLogin("moh-msg");return;}
  var file=$("moh-file").files[0];
  if(!file){setMsg("moh-msg","Choose a .wav file first.","");return;}
  if(file.size===0){setMsg("moh-msg","The file is empty. Choose a WAV file with content.","");return;}
  if(file.size>MOH_MAX_BYTES){setMsg("moh-msg","File is too large (8 MB max).","");return;}
  var row=$("moh-prog-row"),bar=$("moh-prog"),pct=$("moh-pct");
  row.hidden=false;
  bar.value=0;
  pct.textContent="0";
  mohUploading=true;
  audioAria("moh-upload-btn",true);
  setMsg("moh-msg","Uploading "+file.name+" ("+file.size.toLocaleString()+" bytes)...","");
  uploadBody("/api/moh/upload",file,f=>{
    var p=Math.round(f*100);
    bar.value=p;
    pct.textContent=String(p);
  }).then(()=>{
    bar.value=100;
    pct.textContent="100";
    setMsg("moh-msg","Upload complete. Reboot to load the new clip.","ok");
    fetchMohStatus();
  }).catch(e=>{
    row.hidden=true;
    /* 422 is input validation (grey); any other failure is a device fault (solid fill). */
    var bad=e.status===422;
    setMsg("moh-msg",bad?"Not a valid 8 kHz mono mu-law WAV. Convert it with tools/gen_moh.py.":e.message,bad?"":"err");
  }).then(()=>{
    mohUploading=false;
    audioGate();
  });
}
function mohPreview(){
  if(!canWrite()){audioNeedLogin("moh-preview-msg");return;}
  var ext=$("moh-preview-ext").value.trim();
  if(!ext){setMsg("moh-preview-msg","Enter an extension to ring.","");return;}
  if(!/^[A-Za-z0-9#*]+$/.test(ext)){setMsg("moh-preview-msg","Extension may contain only letters, digits, '#' and '*'.","");return;}
  setMsg("moh-preview-msg","Ringing "+ext+"...","");
  post("/api/moh/preview",{extension:ext}).then(()=>{
    setMsg("moh-preview-msg","Ringing "+ext+". Answer to listen.","ok");
    fetchMohStatus();
  }).catch(fm("moh-preview-msg",""));
}
function mohPreviewStop(){
  if(!canWrite()){audioNeedLogin("moh-preview-msg");return;}
  post("/api/moh/preview/stop").then(()=>{
    setMsg("moh-preview-msg","Preview stopped.","ok");
    fetchMohStatus();
  }).catch(fm("moh-preview-msg",""));
}
function mediaTxApply(){
  if(!canWrite()){audioNeedLogin("mtx-msg");return;}
  if(!audioOwner()){setMsg("mtx-msg","Owner login required to change this switch.","");return;}
  var v=$("mtx-nodelay").value==="1"?"1":"0";
  setMsg("mtx-msg","Applying nodelay="+v+"...","");
  post("/api/media-tx",{nodelay:v}).then(d=>{
    var n=(d&&d.nodelay!==undefined)?(d.nodelay===1||d.nodelay==="1"?1:0):Number(v);
    $("mtx-current").textContent="nodelay="+n;
    setMsg("mtx-msg","Applied: nodelay="+n+". Takes effect when the next audio stream opens, not mid-call.","ok");
  }).catch(fm("mtx-msg",""));
}
function audioBind(){
  $("moh-upload-btn").addEventListener("click",mohUpload);
  $("moh-play-btn").addEventListener("click",mohPreview);
  $("moh-stop-btn").addEventListener("click",mohPreviewStop);
  $("moh-preview-ext").addEventListener("keydown",e=>{
    if(e.key==="Enter")mohPreview();
  });
  $("mtx-save").addEventListener("click",mediaTxApply);
}
audioBind();
store.effect(()=>{
  sig.admin.get();
  audioRenderMoh(sig.moh.get());
});
