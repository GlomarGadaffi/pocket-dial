/* 20-extensions: per-extension cards (state, DND, voicemail, forwards, force disconnect)
   and the Learn hint. The registrar roster lives in Devices. Core (00-core.js)
   owns httpMethod, post, setMsg, ui, store, sig, adminState and the poll loop; this file
   only calls them. Routes: GET /api/status (via sig.status), POST /api/dnd,
   /api/voicemail, /api/forward, /api/kill.
   Write controls carry data-needs="login"; core sets and clears their aria-disabled. */

var extUi={cards:Object.create(null)};


function extNumSort(a,b){
  return (parseInt(a,10)||0)-(parseInt(b,10)||0);
}

function extStateOf(e){
  if(e.parked)return {cls:"standby",glyph:"\u25a0",word:"parked"};
  if(e.st==="Invited")return {cls:"live",glyph:"\u25c6",word:"ringing"};
  if(e.st==="Connected"||e.st==="Unknown")return {cls:"live",glyph:"\u25b2",word:"on call"};
  if(e.st==="Unavailable")return {cls:"critical",glyph:"\u25c6",word:"unavailable"};
  if(e.reg)return {cls:"ok",glyph:"\u00b7",word:"registered"};
  return {cls:"standby",glyph:"\u25a0",word:"not registered"};
}

function extModel(d){
  var m=Object.create(null);
  function ens(n){var k=String(n);if(!m[k])m[k]={reg:false,dnd:false,vm:false,st:"",parked:false,fwd:{always:"",busy:"",noanswer:""}};return m[k];}
  (d.clients||[]).forEach(c=>{ens(c.number).reg=true;});
  (d.dnd||[]).forEach(n=>{ens(n).dnd=true;});
  (d.voicemail||[]).forEach(n=>{ens(n).vm=true;});
  (d.forwards||[]).forEach(f=>{
    ens(f.extension).fwd={always:String(f.always||""),busy:String(f.busy||""),noanswer:String(f.noanswer||"")};
  });
  (d.sessions||[]).forEach(s=>{ens(s.caller).st=s.state||"";ens(s.callee).st=s.state||"";});
  (d.parkedCalls||[]).forEach(p=>{ens(p.parkedExt).parked=true;});
  return m;
}

function extMakeCheck(ext,act,text){
  var lab=mk("label");lab.className="opt opt-"+act;
  var inp=mk("input");inp.type="checkbox";
  inp.setAttribute("data-act",act);inp.setAttribute("data-needs","login");
  inp.setAttribute("aria-label",text+" for "+ext);
  lab.appendChild(inp);lab.appendChild(document.createTextNode(" "+text));
  return {label:lab,input:inp};
}

function extMakeCard(k){
  var root=mk("article");root.className="card";root.setAttribute("data-ext",k);
  var top=mk("div");top.className="pcard-top";
  var name=mk("span");name.className="pname mono";name.textContent=k;
  var fill=mk("span");fill.className="fill";
  var st=mk("span");
  var g=mk("span");g.className="g";
  var word=mk("span");
  st.appendChild(g);st.appendChild(word);
  top.appendChild(name);top.appendChild(fill);top.appendChild(st);
  var tog=mk("div");tog.className="row";
  var dnd=extMakeCheck(k,"dnd","DND");
  var vm=extMakeCheck(k,"vm","Voicemail");
  tog.appendChild(dnd.label);tog.appendChild(vm.label);
  var fwdBox=mk("div");fwdBox.className="rep";
  var fwd={};
  [["always","Always"],["busy","Busy"],["noanswer","No answer"]].forEach(p=>{
    var row=mk("div");row.className="rep-row";
    var f=mk("div");f.className="field";
    var l=mk("span");l.className="lbl";l.textContent=p[1];
    var inp=mk("input");inp.type="text";inp.setAttribute("inputmode","numeric");
    inp.placeholder="target ext";inp.setAttribute("data-needs","login");
    inp.setAttribute("aria-label",p[1]+" forward target for "+k);inp.setAttribute("data-fwd",p[0]);
    var b=mk("button");b.type="button";b.className="btn";b.textContent="Set";
    b.setAttribute("data-needs","login");
    b.setAttribute("data-act","fwd");b.setAttribute("data-trigger",p[0]);
    f.appendChild(l);f.appendChild(inp);row.appendChild(f);row.appendChild(b);
    fwdBox.appendChild(row);
    fwd[p[0]]={input:inp,button:b};
  });
  var killRow=mk("div");killRow.className="row";
  var kb=mk("button");kb.type="button";kb.className="btn";
  kb.textContent="[ ARM ] Disconnect";kb.setAttribute("aria-label","[ ARM ] Force disconnect "+k);kb.setAttribute("data-act","kill");kb.setAttribute("data-needs","login");
  killRow.appendChild(kb);
  root.appendChild(top);root.appendChild(tog);root.appendChild(fwdBox);root.appendChild(killRow);
  return {root:root,st:st,g:g,word:word,dnd:dnd.input,vm:vm.input,fwd:fwd,kill:kb};
}

/* A checkbox the user is changing keeps its value until its POST settles. */
function extSyncToggle(inp,on){
  if(!inp.dataset.pending)inp.checked=!!on;
}

/* A forward input the user is typing in, or has edited and not yet saved, keeps its value. */
function extUpdateCard(c,e){
  var s=extStateOf(e);
  c.st.className="st "+s.cls;
  c.g.textContent=s.glyph;
  c.word.textContent=s.word;
  extSyncToggle(c.dnd,e.dnd);
  extSyncToggle(c.vm,e.vm);
  ["always","busy","noanswer"].forEach(t=>{
    var f=c.fwd[t];
    if(document.activeElement!==f.input&&f.input.dataset.dirty!=="1")f.input.value=e.fwd[t];
  });
}

function extRender(d){
  var visible=!!d&&d.rosterVisible!==false;
  var m=visible?extModel(d):Object.create(null);
  var keys=Object.keys(m).sort(extNumSort);
  var list=$("ext-cards");
  Object.keys(extUi.cards).forEach(k=>{
    if(!m[k]){list.removeChild(extUi.cards[k].root);delete extUi.cards[k];}
  });
  var before=null;
  for(var i=keys.length-1;i>=0;i--){
    var k=keys[i];
    var c=extUi.cards[k];
    if(!c){c=extMakeCard(k);extUi.cards[k]=c;list.insertBefore(c.root,before);}
    extUpdateCard(c,m[k]);
    before=c.root;
  }
  $("ext-empty-text").textContent=!d?"Loading extensions.":(visible?"No extensions yet. Learn or zero-touch creates them when a phone registers.":"Log in to see extensions.");
  $("ext-empty").hidden=keys.length>0;
}

function extSetFlag(ext,act,inp){
  var on=inp.checked;
  if(!canWrite()){inp.checked=!on;setMsg("ext-msg","Log in to change extension settings.","");return;}
  var path=act==="dnd"?"/api/dnd":"/api/voicemail";
  inp.dataset.pending="1";
  post(path,"extension="+encodeURIComponent(ext)+"&on="+(on?"1":"0"))
    .then(()=>{setMsg("ext-msg",(act==="dnd"?"DND ":"Voicemail ")+(on?"enabled":"disabled")+" for "+ext,"ok");})
    .catch(e=>{inp.checked=!on;setMsg("ext-msg","Error: "+e.message,msgCls(e));})
    .then(()=>{delete inp.dataset.pending;});
}

function extSaveForward(ext,trig,inp){
  if(!canWrite()){setMsg("ext-msg","Log in to change extension settings.","");return;}
  var t=inp.value.trim();
  post("/api/forward","extension="+encodeURIComponent(ext)+"&trigger="+trig+"&target="+encodeURIComponent(t))
    .then(()=>{
      inp.dataset.dirty="";
      setMsg("ext-msg",trig+" forward "+(t?("\u2192 "+t):"cleared")+" for "+ext,"ok");
    })
    .catch(fm("ext-msg"));
}

/* Force disconnect drops the extension's call: its button is ARM then EXEC. */
function extKill(ext,btn){
  if(!canWrite()){setMsg("ext-msg","Log in to change extension settings.","");return;}
  ui.arm(btn,"Disconnect",()=>{
    post("/api/kill","extension="+encodeURIComponent(ext))
      .then(()=>{setMsg("ext-msg","Disconnect signal sent to "+ext+".","ok");})
      .catch(fm("ext-msg"));
  });
}

function extOnChange(ev){
  var t=ev.target;
  var act=t.getAttribute?t.getAttribute("data-act"):null;
  if(act!=="dnd"&&act!=="vm")return;
  extSetFlag(t.closest(".card").getAttribute("data-ext"),act,t);
}

function extOnClick(ev){
  var b=ev.target.closest("button[data-act]");
  if(!b)return;
  var card=b.closest(".card");
  var ext=card.getAttribute("data-ext");
  var act=b.getAttribute("data-act");
  if(act==="kill"){extKill(ext,b);return;}
  if(act==="fwd"){
    var trig=b.getAttribute("data-trigger");
    extSaveForward(ext,trig,card.querySelector('[data-fwd="'+trig+'"]'));
  }
}

function extOnInput(ev){
  var t=ev.target;
  if(t.getAttribute&&t.getAttribute("data-fwd"))t.dataset.dirty="1";
}

function extOnKey(ev){
  var t=ev.target;
  if(ev.key!=="Enter"||!t.getAttribute||!t.getAttribute("data-fwd"))return;
  extSaveForward(t.closest(".card").getAttribute("data-ext"),t.getAttribute("data-fwd"),t);
}

function extGate(){
  $("ext-gate").hidden=canWrite();
}

function extStatusValue(){
  sig.admin.get();
  return sig.status.get();
}

function extOnStatus(d){
  extGate();
  extRender(d);
}

function extWire(){
  var root=$("ext-cards");
  root.addEventListener("change",extOnChange);
  root.addEventListener("click",extOnClick);
  root.addEventListener("input",extOnInput);
  root.addEventListener("keydown",extOnKey);
  store.effect(()=>{extOnStatus(extStatusValue());});
  extGate();
}

try{extWire();}catch(e){setMsg("ext-msg","Extensions failed to start: "+e.message,"err");}
