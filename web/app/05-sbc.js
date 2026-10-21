/* 05-sbc.js: SBC profile copy (build brief section 9). Guarded "@only POCKETDIAL_PROFILE_SBC" in
   manifest.txt, so only an SBC build carries it (no host fallback). Runs right after core and before the sections.
   Core's applyProfile reads PD_PRODUCT and PD_TITLES (again on DOMContentLoaded); 10-overview.js reads
   PD_E911_ANCHOR and PD_VERIFY when it renders; app.css hides the per-extension forward and DND
   controls under body.sbc. Defines no function or var: the unguarded page never names this file. */
window.PD_PRODUCT="POCKET-DIAL SBC";
window.PD_TITLES={"trunks-numbers":"3CX"};
window.PD_E911_ANCHOR="· E911 VIA 3CX";
window.PD_VERIFY="SBC mode: host-tested only";
document.body.classList.add("sbc");
/* nav item and F-key label: the last node is the <span> text (nav) or the text after the key (F-key bar) */
document.querySelectorAll('[data-sec="trunks-numbers"]').forEach(a=>{if(a.lastChild)a.lastChild.textContent="3CX";});
