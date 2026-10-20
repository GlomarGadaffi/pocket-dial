/* ════ CONSOLE: live view, read-only ════
   Core (00-core.js) owns the fetches and their timers: fetchStatus writes sig.status,
   fetchCdr writes sig.cdr, and startTrace/stopTrace/pollTrace drive sig.trace,
   sig.traceOn and sig.traceErr. This file only renders those signals.
   Routes shown here: GET /api/status (calls, parked calls, roster), GET /api/cdr,
   GET /api/trace, and GET /api/pcap as a download link. No control here changes
   state: there are no hold, park or transfer actions.
   Core helpers used: $, setMsg, sig, store.effect, fmtClock, startTrace, stopTrace. */
var CON_GLYPH={ok:"·",standby:"·",warning:"▲",critical:"■"};
var CON_TRACE_MAX=200;
var CON_CDR_MAX=20;

function conNode(tag,cls,txt){
  var n=mk(tag);
  if(cls)n.className=cls;
  if(txt!==undefined&&txt!==null)n.textContent=String(txt);
  return n;
}
function conClear(el){
  while(el.firstChild)el.removeChild(el.firstChild);
}
function conTd(content,cls){
  var td=conNode("td",cls);
  if(content instanceof Node)td.appendChild(content);
  else td.textContent=String(content==null?"":content);
  return td;
}
/* Glyph plus word, never colour alone. An empty class gives a neutral glyph. */
function conState(k,word,glyph){
  var s=conNode("span","st"+(k?" "+k:""));
  var g=conNode("span","g",glyph||CON_GLYPH[k]||"·");
  g.setAttribute("aria-hidden","true");
  s.appendChild(g);
  s.appendChild(conNode("span","",word));
  return s;
}
/* SIP session states as sessionStateToString() emits them. An unrecognised state
   shows its raw word with a neutral glyph; it is never folded into "Idle". */
function conSessionState(raw){
  if(raw==="Invited")return ["live","Ringing","◆"];
  if(raw==="Connected")return ["live","Connected","▲"];
  if(raw==="Busy")return ["standby","Busy"];
  if(raw==="Unavailable")return ["critical","Unavailable"];
  if(raw==="Cancel")return ["standby","Cancelled"];
  if(raw==="Bye")return ["standby","Ending"];
  if(raw==="Unknown")return ["standby","Unknown"];
  return ["",String(raw||"No state")];
}
/* CDR results as cdrResultToString() emits them. These are history rows, not current faults: every one is a
   grey chip, glyph + word, no fill. */
function conResultState(raw){
  var r=String(raw||"").toLowerCase();
  if(r==="answered")return ["ok","Answered"];
  if(r==="busy")return ["standby","Busy"];
  if(r==="cancelled")return ["standby","Cancelled"];
  if(r==="unavailable")return ["","Unavailable","▲"];
  if(r==="failed")return ["","Failed","■"];
  return ["",String(raw||"Unknown")];
}
function conAge(s){
  s=Math.max(0,Math.floor(Number(s)||0));
  if(s<60)return s+"s ago";
  if(s<3600)return Math.floor(s/60)+"m ago";
  return Math.floor(s/3600)+"h ago";
}

/* ── status: link, counts, calls, parked, roster (sig.status) ── */
/* sig.status keeps the last good read when the device stops answering, so the
   word shows when that read arrived; it stops moving if the device goes quiet. */
function conRenderLink(d){
  var el=$("con-link");
  if(!el)return;
  conClear(el);
  if(!d){el.appendChild(conState("standby","Waiting for the first status read"));return;}
  var t=new Date();
  el.appendChild(conState("ok","Last status read "+pad2(t.getHours())+":"+pad2(t.getMinutes())+":"+pad2(t.getSeconds())));
}
function conRenderStatus(d){
  var dash="—";
  var set=(id,txt)=>{var e=$(id);if(e)e.textContent=txt;};
  conRenderLink(d);
  if(!d){
    ["con-phones","con-calls-n","con-parked-n","con-oldest"].forEach(id=>{set(id,dash);});
    return;
  }
  set("con-phones",String(d.clientCount||0));
  set("con-calls-n",String(d.sessionCount||0));
  set("con-parked-n",String(d.parkedCount||0));
  set("con-oldest",d.oldestSessionSec>0?fmtClock(d.oldestSessionSec):dash);
  conRenderCalls(d);
  conRenderParked(d);
  conRenderRoster(d);
}
function conRenderCalls(d){
  var body=$("con-calls-body"),empty=$("con-calls-empty"),txt=$("con-calls-empty-txt");
  if(!body||!empty||!txt)return;
  var rows=d.sessions||[];
  conClear(body);
  rows.forEach(s=>{
    var st=conSessionState(s.state);
    var tr=conNode("tr");
    tr.appendChild(conTd(s.caller,"mono"));
    tr.appendChild(conTd(s.callee,"mono"));
    tr.appendChild(conTd(conState(st[0],st[1],st[2])));
    tr.appendChild(conTd(s.duration,"mono num"));
    body.appendChild(tr);
  });
  if(rows.length){empty.hidden=true;return;}
  empty.hidden=false;
  if(d.sessionCount>0)txt.textContent=d.sessionCount+(d.sessionCount===1?" call is":" calls are")+" up. Log in to see the parties.";
  else txt.textContent="No calls up right now.";
}
function conRenderParked(d){
  var list=$("con-parked"),note=$("con-parked-note");
  if(!list||!note)return;
  var rows=d.parkedCalls||[];
  conClear(list);
  rows.forEach(p=>{
    var li=conNode("li");
    li.appendChild(conNode("span","mono","Orbit "+p.orbit+": ext "+p.parkedExt+", parked by "+p.parker));
    li.appendChild(conState("","Parked"));
    li.appendChild(conNode("span","mono num",fmtClock(p.secondsParked)));
    list.appendChild(li);
  });
  note.textContent=rows.length?"":(d.parkedCount>0?d.parkedCount+" parked. Log in to see which extensions.":"Nothing is parked.");
}
function conRenderRoster(d){
  var list=$("con-roster");
  if(!list)return;
  conClear(list);
  if(d.rosterVisible===false){
    setMsg("con-roster-msg",(d.clientCount||0)+(d.clientCount===1?' phone':' phones')+' registered. Log in to see them.',"");
    return;
  }
  var rows=d.clients||[];
  if(!rows.length){setMsg("con-roster-msg","No phones registered.","");return;}
  setMsg("con-roster-msg","","");
  rows.forEach(c=>{
    var li=conNode("li");
    li.appendChild(conNode("span","mono",c.number));
    li.appendChild(conNode("span","mono",c.address));
    li.appendChild(conState("ok","Registered"));
    list.appendChild(li);
  });
}
store.effect(()=>{conRenderStatus(sig.status.get());});

/* ── call log tail (sig.cdr, set by core fetchCdr) ── */
function conRenderCdr(c){
  var body=$("con-cdr-body"),empty=$("con-cdr-empty");
  if(!body||!empty||!c)return;
  conClear(body);
  if(!c.auth){
    setMsg("con-cdr-msg",c.msg||"Log in to view the call log","");
    empty.hidden=true;
    return;
  }
  setMsg("con-cdr-msg",c.msg||"",c.msg?"err":"");
  var rows=(c.recs||[]).slice(0,CON_CDR_MAX);
  rows.forEach(r=>{
    var res=conResultState(r.result);
    var tr=conNode("tr");
    tr.appendChild(conTd(r.caller,"mono"));
    tr.appendChild(conTd(r.callee,"mono"));
    tr.appendChild(conTd(conState(res[0],res[1],res[2])));
    tr.appendChild(conTd(fmtClock(r.duration),"mono num"));
    tr.appendChild(conTd(conAge(r.ageSec),"mono"));
    body.appendChild(tr);
  });
  empty.hidden=rows.length>0;
}
store.effect(()=>{conRenderCdr(sig.cdr.get());});

/* ── SIP trace (sig.trace, sig.traceOn, sig.traceErr; core owns the polling) ── */
function conTraceLine(r){
  var p=conNode("p","trace");
  var out=r.dir==="out";
  p.appendChild(conNode("span","prompt",(out?"→ OUT ":"← IN ")+String(r.peer==null?"":r.peer)+" · #"+r.seq+(r.truncated?" · truncated":"")));
  p.appendChild(document.createTextNode("\n"+String(r.text==null?"":r.text)));
  return p;
}
function conRenderTrace(recs,on,err){
  var btn=$("con-trace-btn"),state=$("con-trace-state"),box=$("con-trace");
  if(btn)btn.textContent=on?"Stop trace":"Start trace";
  if(state){
    conClear(state);
    if(on&&err)state.appendChild(conState("warning","Trace read failed, retrying: "+err));
    else state.appendChild(on?conState("ok","Trace on"):conState("standby","Trace off"));
  }
  if(!box)return;
  conClear(box);
  if(!on){box.appendChild(conNode("p","hint","Trace is off."));return;}
  var list=recs||[];
  if(!list.length){box.appendChild(conNode("p","hint","No SIP messages yet."));return;}
  for(var i=Math.max(0,list.length-CON_TRACE_MAX);i<list.length;i++)box.appendChild(conTraceLine(list[i]));
  box.scrollTop=box.scrollHeight;
}
function conTraceToggle(){
  if(sig.traceOn.peek())stopTrace();
  else startTrace();
}
store.effect(()=>{conRenderTrace(sig.trace.get(),sig.traceOn.get(),sig.traceErr.get());});
