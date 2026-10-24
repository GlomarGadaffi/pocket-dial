/* ── Call handling section: ring/hunt groups, parked calls (read-only). Multicast paging is in 61-paging.js.
   Reserved ranges are static markup. Per-extension forwards and force disconnect are on the
   Extensions cards (POST /api/forward, POST /api/kill).
   Routes: POST /api/group. Groups and parked calls come from /api/status,
   which sig.status carries; the effect at the end of this file repaints on every poll.
   Core helpers used: $, setMsg, post, put, httpMethod, adminState, ui. */
var chPaint={groups:"",parked:""};

function chSecHidden(){
  var s=$("sec-call-handling");
  return !s||s.hidden;
}
function chWriteGate(msgId){
  if(canWrite())return true;
  setMsg(msgId,adminState.needsSetup?"Finish the admin setup first.":"Log in before changing call handling.","");
  return false;
}
function chModeLabel(m){
  if(m==="hunt")return "Hunt";
  if(m==="ringall")return "Ring all";
  return String(m||"");
}
function chClock(s){
  s=Math.max(0,Math.floor(s||0));
  var h=Math.floor(s/3600),m=Math.floor((s%3600)/60),r=s%60;
  var t=(h>0&&m<10?"0":"")+m+":"+(r<10?"0":"")+r;
  return h>0?h+":"+t:t;
}
function chHint(parent,text){
  var p=mk("p");
  p.className="hint";
  p.textContent=text;
  parent.appendChild(p);
}
function chRow(parts){
  var row=mk("div");
  row.className="kvrow";
  row.setAttribute("role","listitem");
  parts.forEach(el=>{
    var cell=mk("div");
    cell.appendChild(el);
    row.appendChild(cell);
  });
  return row;
}
function chSpan(cls,text){
  var s=mk("span");
  if(cls)s.className=cls;
  s.textContent=text;
  return s;
}

/* Called with the /api/status object on every poll while this section is shown.
   Rebuilds only the read-only lists, and only when their data changed, so the
   buttons keep keyboard focus. Form inputs are never touched here. */
function renderCallHandling(d){
  if(!d||chSecHidden())return;
  var authed=canWrite();
  chRenderGroups(d.groups||[],authed);
  chRenderParked(d,authed);
  if(typeof chPagingTick==="function")chPagingTick(authed);
}
function chRenderGroups(groups,authed){
  var key=JSON.stringify(groups)+"|"+authed;
  if(key===chPaint.groups)return;
  chPaint.groups=key;
  var list=$("ch-groups-list");
  list.textContent="";
  if(!groups.length){
    chHint(list,authed?"No ring or hunt groups defined.":"Log in to see ring and hunt groups.");
    return;
  }
  groups.forEach(g=>{
    var btn=mk("button");
    btn.type="button";
    btn.className="btn";
    btn.textContent="Edit";
    btn.setAttribute("aria-label","Edit group "+g.extension);
    btn.onclick=()=>{chEditGroup(g);};
    var head=mk("span");
    head.appendChild(chSpan("mono",g.extension));
    head.appendChild(document.createTextNode(" "));
    head.appendChild(chSpan("tag",chModeLabel(g.mode)));
    list.appendChild(chRow([head,chSpan("mono muted",g.members||"no members"),btn]));
  });
}
function chEditGroup(g){
  $("ch-grp-ext").value=g.extension||"";
  $("ch-grp-members").value=g.members||"";
  $("ch-grp-mode").value=g.mode==="hunt"?"hunt":"ringall";
  setMsg("ch-grp-msg","Editing group "+g.extension+". Save to apply, or empty the members to delete it.","ok");
  chGrpLabel();
  $("ch-grp-ext").focus();
}
function chSaveGroup(){
  if(!chWriteGate("ch-grp-msg"))return;
  var ext=$("ch-grp-ext").value.trim();
  if(!ext){setMsg("ch-grp-msg","Group extension required.","");return;}
  var members=$("ch-grp-members").value.trim();
  var mode=$("ch-grp-mode").value;
  var body="extension="+encodeURIComponent(ext)+"&members="+encodeURIComponent(members)+"&mode="+encodeURIComponent(mode);
  var send=()=>{
    return post("/api/group",body).then(()=>{
      setMsg("ch-grp-msg",members?("Group "+ext+" saved."):("Group "+ext+" deleted."),"ok");
    });
  };
  if(members)send().catch(fm("ch-grp-msg",""));
  else ui.arm($("ch-grp-save"),"Delete group",()=>{send().catch(fm("ch-grp-msg",""));});
}
/* Empty members means Save deletes the group, so the trigger reads [ ARM ] Delete group until members are typed. */
function chGrpLabel(){
  var b=$("ch-grp-save"),del=!$("ch-grp-members").value.trim();
  ui.disarm(b);
  b.textContent=del?"[ ARM ] Delete group":"Save group";
  b.className=del?"btn":"btn btn-primary";
  b.setAttribute("aria-label",del?"[ ARM ] Delete group "+$("ch-grp-ext").value.trim():"Save group");
}
$("ch-grp-members").addEventListener("input",chGrpLabel);
chGrpLabel();
function chRenderParked(d,authed){
  var list=d.parkedCalls||[];
  var count=Number(d.parkedCount||0);
  var key=JSON.stringify(list)+"|"+count+"|"+authed;
  if(key===chPaint.parked)return;
  chPaint.parked=key;
  setMsg("ch-parked-count",count===0?"Nothing parked.":(count+(count===1?" call parked.":" calls parked.")),"ok");
  var ul=$("ch-parked-list");
  ul.textContent="";
  if(count>0&&!list.length){
    chHint(ul,authed?"Parked calls are listed here.":"Log in to see the orbit and parker for each parked call.");
  }
  list.forEach(p=>{
    ul.appendChild(chRow([
      chSpan("mono","orbit "+p.orbit),
      chSpan("mono muted","ext "+p.parkedExt+", parked by "+p.parker),
      chSpan("mono muted",chClock(p.secondsParked))
    ]));
  });
}
store.effect(()=>{
  sig.admin.get();
  var d=sig.status.get();
  if(sig.nav.get()==="call-handling")renderCallHandling(d);
});
