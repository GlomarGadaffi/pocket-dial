/* 41-did.js: DID -> extension mapping (GET/PUT/DELETE /api/did-mapping). Guarded "@unless
   POCKETDIAL_PROFILE_SBC" in manifest.txt: the SBC build leaves it out (3CX owns the numbers), so
   40-trunks-numbers.js reaches it only through its typeof-guarded tnDidLoad() call.
   Its markup is sections/41-did.html, spliced at <div id="did-slot"> in Trunks & numbers.
   Uses from 40-trunks-numbers.js: tnEl, tnBtn, tnGet, tnThen, tnGuard, tnSetOff. From core: $, setMsg,
   put, del, canWrite, ui. */
var tnDidMsg="tn-did-msg";
var tnDidWriteIds=["tn-did-new","tn-did-ext","tn-did-add"];
var tnReserved={"777":1,"999":1,"555":1,"888":1,"440":1,"796":1,"997":1,"pbx":1,"moh":1,"server":1};
/* Called by tnLoad: gates the controls, then loads the table or clears it when logged out. */
function tnDidLoad(){
  var ready=canWrite();
  tnDidWriteIds.forEach(id=>tnSetOff(id,!ready));
  if(ready)return tnFetchDids();
  $("tn-did-body").textContent="";
  $("tn-did-new").value=$("tn-did-ext").value="";
}
function tnFetchDids(){
  return tnGet("/api/did-mapping",tnDidMsg,d=>tnRenderDids(d.mappings||[]));
}
function tnRenderDids(list){
  var body=$("tn-did-body");
  body.textContent="";
  if(!list.length)return body.append(tnEl("tr",Object.assign(tnEl("td","No DID mappings configured. Add one below to route an incoming number to an extension.","hint"),{colSpan:3})));
  list.forEach(m=>{
    var tr=tnEl("tr");
    tr.append(tnEl("td",m.did,"mono"),tnEl("td",m.extension,"mono"),tnEl("td",tnBtn("btn","[ ARM ] Remove","[ ARM ] Remove DID "+m.did,canWrite(),b=>tnRemoveDid(m.did,b))));
    body.append(tr);
  });
}
function tnAddDid(){
  if(!tnGuard())return;
  var did=$("tn-did-new").value.trim();
  var ext=$("tn-did-ext").value.trim();
  if(!did||!ext)return setMsg(tnDidMsg,"DID and extension are both required.","");
  if(!/^[A-Za-z0-9#*]+$/.test(ext))return setMsg(tnDidMsg,"Extension may contain only letters, digits, '#' and '*'.","");
  if(tnReserved[ext.toLowerCase()])return setMsg(tnDidMsg,"Cannot map a DID to a virtual/reserved extension ("+ext+").","");
  var p=put("/api/did-mapping",new URLSearchParams({did:did,extension:ext}).toString()).then(()=>{$("tn-did-new").value=$("tn-did-ext").value="";});
  tnThen(p,tnDidMsg,"Mapping saved.",tnFetchDids);
}
/* Removing a mapping makes calls to that number ring all: the row button is ARM then EXEC. */
function tnRemoveDid(did,btn){
  if(!tnGuard())return;
  ui.arm(btn,"Remove",()=>tnThen(del("/api/did-mapping",new URLSearchParams({did:did}).toString()),tnDidMsg,"Mapping removed.",tnFetchDids));
}
