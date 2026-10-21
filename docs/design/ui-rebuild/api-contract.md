# pocket-dial web UI replacement: API contract

Baseline: `origin/main` @ `de61ba14`. The backend and API stay as they are. Everything in `src/Helpers/index_html.h` is replaced.
Sources: the server route inventory (`HttpServer.cpp` dispatcher L812-1762) and the UI call map (`index_html.h`). This document merges those two maps and adds no new reads of the code. Anything that neither map verified is marked **unverified**.

Gate abbreviations:
- **open**: ungated
- **SO**: `requireSameOrigin` only
- **A(read)**: `requireAdmin(..., false)`, which means same origin plus a session, with no CSRF
- **A(csrf)**: `requireAdmin(..., true)`, which means same origin plus a session plus the CSRF header
- **Owner**: `minRole=Owner`. Without this tag the minimum role is Sysop.

All request bodies are `application/x-www-form-urlencoded` string fields, except the two raw uploads. All responses are JSON unless a row says otherwise.

---

## 1. Route table

| Method | Path | Gate | Request | Response (main keys) | Current UI caller |
|---|---|---|---|---|---|
| GET | `/`, `/index.html` | open | – | `text/html` (PD_HTML_0..7, CSRF substituted) | browser load |
| GET | `/setup/email` | open | – | `text/html` (PD_HTML_8) | standalone page |
| GET | `/setup/trunk` | open | – | `text/html` (PD_HTML_9) | standalone page |
| GET | `/config/<file>` | open | path: `000000000000.cfg`, `cfg<mac>.xml`, `<mac>-phone.cfg`, `spa<mac>.cfg`, `spa<model>.cfg`, `snom<mac>.xml`, Yealink `<mac>.cfg` | `application/xml` / `text/plain` | none (phones fetch these) |
| GET | `/api/status` | open; roster, sessions and dialplan only with a session | – | `ip,port,version,uptime,clients,clientCount,rosterVisible,sessionCount,sessions,dnd,voicemail,forwards,groups,dialplan,parkedCount,parkedCalls,freeHeap…,stackHwm_*,coredump,mediaTx` | `fetchStatus`, polled every 2 s |
| GET | `/metrics` | open | – | `text/plain; version=0.0.4` (Prometheus) | none |
| GET | `/api/admin/status` | open | – | `provisioned,needsSetup,authenticated,role,ownerProvisioned,sessionRemainingSec` | `fetchAdminStatus`, polled every 15 s |
| POST | `/api/admin/login` | SO | `username,password` | `status,authenticated,needsSetup,role,csrf`; 401 = bad credentials, 429 = locked out | `adminLogin` (sends no X-CSRF) |
| POST | `/api/admin/logout` | SO | – | `status` | `adminLogout` (sends no X-CSRF) |
| POST | `/api/admin/set-credential` | A(csrf); the only route allowed during setup | `username,password,dtmfPin` (any subset) | `status,provisioned,needsSetup` | `adminCompleteSetup`, `adminChangeCredential`, `adminChangeDtmfPin` |
| POST | `/api/admin/set-owner-credential` | A(csrf), Owner (a Sysop session may create the first owner) | `ownerUsername,ownerPassword` | `status,ownerProvisioned` | none |
| POST | `/api/kill` | A(csrf) | `extension` | `status,disconnected` | jack detail `killJack` |
| POST | `/api/dnd` | A(csrf) | `extension,on` | `status,extension,dnd` | jack detail `toggleDnd` |
| POST | `/api/voicemail` | A(csrf) | `extension,on` | `status,extension,voicemail` | jack detail `toggleVoicemail` |
| POST | `/api/forward` | A(csrf) | `extension,trigger,target` | `status,extension,trigger,target` | `jdSaveFwd`, `saveForward` |
| POST | `/api/group` | A(csrf) | `extension,mode,members` (empty `members` deletes the group) | `status,extension,mode,members` | `saveGroup` |
| POST | `/api/dialplan` | A(csrf) | `action,pattern,target,stripDigits` (delete = `pattern` with an empty `target`) | `status,pattern,action,target,stripDigits` | `saveDialRule`, `deleteDialRule` |
| GET | `/api/sbc-mode` | A(read) | – | `enabled,route,maxRoute` | `fetchSbcMode` |
| PUT | `/api/sbc-mode` | A(csrf) | `enabled` (`1/true/on`), `route` (numeric slot; anything else gets 400) | JSON | `saveSbcMode` |
| GET | `/api/e911-config` | A(read) | – | `notifyExts,callback,location,maxNotifyExts` | PBX modal, E911 section |
| PUT | `/api/e911-config` | A(csrf) | `notifyExts,callback,location` | JSON | PBX modal, E911 section |
| GET | `/api/telephony-config` | A(read) | – | `slots[]: index,type,enabled,implemented,active,baseUrl,clientId,routeDn,secretSet` | telephony modal; SBC route dropdown |
| PUT | `/api/telephony-config/<i>` | A(csrf) | `baseUrl,clientId,secret,routeDn,enabled` (blank `secret` keeps the stored one) | `status,slot` | `saveTelephonySlot` |
| POST | `/api/telephony-config/<i>/activate` | A(csrf) | – | `status,activeIndex` | slot table |
| POST | `/api/telephony-config/<i>/test` | A(csrf) | – | `ok,participantId,error` | slot table |
| DELETE | `/api/telephony-config/<i>` | A(csrf) | – | `status,slot` | none |
| GET | `/api/did-mapping` | A(read) | – | `mappings` | telephony modal, DID table |
| PUT | `/api/did-mapping` | A(csrf) | `did,extension` | `status,did,extension` | DID table |
| DELETE | `/api/did-mapping` | A(csrf) | `did` (in the body) | `status,did` | DID table |
| GET | `/api/trunk` | A(read) | – | `host,port,proxyHost,proxyPort,fromUser,callerId,authUser,hasPassword,enabled` | `/setup/trunk` page |
| POST | `/api/trunk` | A(csrf) | `host,port,proxyHost,proxyPort,fromUser,callerId,authUser,pass,clearPassword,enabled` | `status,config` | `/setup/trunk` page |
| GET | `/api/multicast-paging` | A(read) | – | `enabled,group,port` | none |
| PUT | `/api/multicast-paging` | A(csrf) | `enabled,group,port` | JSON | none |
| GET | `/api/moh` | A(read) | – | `supported,loaded,seconds,listeners,preview` | PBX modal, polled every 3 s while open |
| POST | `/api/moh/upload` | A(csrf), raw body | raw WAV, `application/octet-stream`, X-CSRF | `status,bytes,seconds…`; the UI handles 422, 413 and 501 | PBX modal (XHR) |
| POST | `/api/moh/preview` | A(csrf) | `extension` | `status,message` | PBX modal |
| POST | `/api/moh/preview/stop` | A(csrf) | – | `status,message` | PBX modal |
| POST | `/api/media-tx` | A(csrf), Owner | `nodelay` | `status,nodelay` | none |
| GET | `/api/registrar` | A(read) | – | `attached,mode,devices[]: mac,extension,state,online,locked,shared,assigned` | admin, registrar/Learn |
| POST | `/api/registrar` | A(csrf) | `mode,confirm`; 409 when moving to Secure would lock everyone out, then resend with `confirm=LOCKOUT` | JSON | admin, registrar/Learn |
| POST | `/api/registrar/device` | A(csrf) | `action` (secure/forget), `target` (MAC) | JSON | registrar device table |
| POST | `/api/registrar/forget-learned` | A(csrf) | – | same shape as GET `/api/registrar` | none |
| GET | `/api/pnp` | A(read) | – | `attached,mode,listening,socketErrno,netmask,rx,…,devices[]: mac,vendor,model,version,ip,seen,lastSeen,notified` | none |
| POST | `/api/pnp` | A(csrf) | `mode` | JSON | none |
| GET | `/api/zero-touch` | A(read) | – | `attached,open,lo,hi,secondsLeft,unclaimed,free,lastRefusal,refusals,learnOnly` | none |
| POST | `/api/zero-touch` | A(csrf) | `open,lo,hi,minutes` | JSON | none |
| GET | `/api/ap-security` | A(read) | – | `secure,psk` (the PSK comes back in clear) | admin, AP security |
| POST | `/api/ap-security` | A(csrf) | `secure,psk,regenerate` | JSON | admin, AP security |
| GET | `/api/wifi/scan` | open | – | `networks[]: ssid,rssi,encryption`, `note` | WiFi modal |
| POST | `/api/wifi/connect` | A(csrf) | `ssid,password` | `status,message` | WiFi modal |
| POST | `/api/wifi/mode_ap` | A(csrf) | – | `status,message` | WiFi modal |
| POST | `/api/configuring` | A(csrf) | – | `status,message` | "I'm Configuring" button |
| POST | `/api/factory-reset` | A(csrf), Owner | `confirm` (the UI sends `ERASE`) | `status,failed,message` | WiFi modal reset |
| GET | `/api/email` | A(read) | – | `host,port,mode,auth,user,from,to,gsaEmail,hasPassword,hasGsaKey,insecure,hasCaPem` | `/setup/email` page |
| POST | `/api/email` | A(csrf) | `host,port,mode,auth,user,pass,from,to,gsaEmail,gsaKey,insecure,caPem` | `status,config` | `/setup/email` page |
| POST | `/api/email/test` | A(csrf) | `to` | `ok,error,resultCode,smtpReplyCode` | terminal `email test`; `/setup/email` `sendTest` |
| GET | `/api/syslog` | A(read) | – | `supported,enabled,host,port` | none |
| POST | `/api/syslog` | A(csrf) | `host,port` | `status,message` | none |
| GET | `/api/cdr` | A(read) | – | `[]: caller,callee,startMs,ageSec,duration,result` | `fetchCdr`, polled every 5 s |
| GET | `/api/trace` | A(read) | – | `[]: seq,tsUs,dir,peer,text,truncated` | trace modal / terminal, polled every 1.5 s while on |
| GET | `/api/pcap` | A(read) | – | `application/vnd.tcpdump.pcap` | trace modal link |
| GET | `/api/diagnostics/pcap` | A(read) | – | same as `/api/pcap` | none |
| GET | `/api/coredump/info` | A(read) | – | `supported,present,size,valid,task,pc,elfSha,reason` | none |
| GET | `/api/coredump` | A(read), Owner | – | `application/octet-stream` | none |
| POST | `/api/coredump/erase` | A(csrf) | – | `erased` | none |
| GET | `/api/ota/status` | open | – | `running,runningPartition,inProgress,boot,next,pendingVerify,otaSupported` | OTA section, polled every 15 s |
| POST | `/api/ota/upload` | A(csrf), Owner, raw body | raw image, octet-stream, X-CSRF; `Content-Length` required (411 when 0) | JSON | OTA upload (XHR) |
| POST | `/api/ota/reboot` | A(csrf) | `confirm` (the UI sends `1`) | `status,staged,message,simulated` | OTA |
| GET | `/api/config/export` | A(read) | – | plaintext export JSON (`extensions,ringGroups,forwards,dialPlan,didMappings,trunk,email,…,schemaVer,exportVer`) | none |
| POST | `/api/config/export` | A(csrf); Owner when `password` is non-empty (12 characters minimum, else 400) | `password` | export JSON plus `secretsEnc{kdf,iter,salt,nonce,ct}` | none |
| POST | `/api/config/import` | A(csrf); Owner when `password` is non-empty | `blob,password,confirm` | `status,applied,skipped` | none |
| GET/POST | `/api/bench/fault` | A (CSRF on POST), Owner; **only built with `POCKETDIAL_ANCHOR_BENCH_PROBE` on ESP** | `fault,value,ballast,deadman` | JSON | none |
| * | anything else | – | – | 404 | – |

## 2. Server routes the current UI never calls

| Route | Note for the new UI |
|---|---|
| `GET /config/<file>` | Phone provisioning. It is not a UI route; at most, show the URL pattern in Devices. |
| `GET /metrics` | Prometheus text. You could link to it from Maintenance; the UI should not poll it. |
| `POST /api/admin/set-owner-credential` | **There is no UI path that creates an Owner today**, yet OTA upload, factory reset, coredump download, media-tx and the encrypted export/import all require Owner. The new UI needs this form. |
| `DELETE /api/telephony-config/<i>` | Clear a slot. |
| `GET/PUT /api/multicast-paging` | Paging config. It has no UI today. |
| `POST /api/registrar/forget-learned` | Bulk forget of learned devices. |
| `GET/POST /api/pnp` | SIP PnP listener status, mode and the discovered-device list. |
| `GET/POST /api/zero-touch` | Zero-touch claim window (`lo..hi` extension range, `minutes`). |
| `POST /api/media-tx` | Owner-only `nodelay` toggle for the media TX path. |
| `GET/POST /api/syslog` | Remote syslog target. |
| `GET /api/coredump/info`, `GET /api/coredump`, `POST /api/coredump/erase` | Crash dump. `/api/status.coredump` already carries a flag. |
| `GET /api/diagnostics/pcap` | Alias of `/api/pcap`. Use one of the two. |
| `GET/POST /api/config/export`, `POST /api/config/import` | Backup and restore. |
| `GET/POST /api/bench/fault` | Bench builds only. **Leave it out of the production UI.** |

## 3. UI calls the server does not serve

**None.** Every one of the 37 call shapes in the UI map matches a server route by method and path. Checking request fields against the server field lists also turned up no mismatches. Some details are still **unverified**, because the server map lists only field names and not the values it accepts:
- the literal values `confirm=ERASE` (factory reset), `confirm=1` (OTA reboot), `confirm=LOCKOUT` (registrar) and `regenerate=1` (AP security)
- the MOH upload error codes 422, 413 and 501

The current UI works against these, so the new UI should send exactly the same values.

## 4. Auth, session and CSRF rules

1. **Session cookie.** Login sets the cookie and the browser stores it. Send every request with `fetch(..., {credentials: "same-origin"})`, or `xhr.withCredentials = true` for the uploads. Page JS never reads or writes the cookie.
2. **CSRF token.** Read it from either source:
   - The server replaces the first occurrence of `"__PD_CSRF__"` in each served page. Keep the declaration `var PD_CSRF="__PD_CSRF__";`, exactly once per page. A page loaded without a session gets an empty token.
   - The `csrf` field of the `POST /api/admin/login` response. Store it straight into `PD_CSRF`, with no reload.
3. **Sending the token.** Every A(csrf) write (POST, PUT, DELETE and both raw uploads) sends the header `X-CSRF: <token>`. GETs send no CSRF header. Login and logout send none.
4. **Same-origin.** `requireSameOrigin()` (L4564) runs before every admin route and before login and logout.
   - Use relative URLs only.
   - Do not set `referrerPolicy: "no-referrer"` and do not add a `<meta name="referrer">` that suppresses the referrer. The map does not say whether the check reads `Origin` or `Referer` (**unverified**), so keep the browser's default fetch shape, which works today.
5. **Status-code handling.** Read the body as text, then parse it as JSON; error bodies are not guaranteed to be JSON.

   | Code | Meaning | UI action |
   |---|---|---|
   | 401 | session expired | Clear the auth state, show "SESSION: EXPIRED", re-lock controls, open login |
   | 403 | cross-origin or stale CSRF | Tell the user to reload the page |
   | 409 | registrar Secure-mode lockout guard | Confirm, then resend with `confirm=LOCKOUT` |
   | 429 | login lockout | Show the lockout |
   | 411 / 413 / 422 / 501 | upload errors | Show them on the upload form |
   | 400 | validation (bad SBC route, export password under 12 characters, …) | Show the error |
6. **Roles.** `role` comes from `/api/admin/status` and the login response. Sysop is the default minimum.
   - Hide or disable Owner-only actions for Sysop sessions:
     - OTA upload
     - factory reset
     - coredump download
     - media-tx
     - set-owner-credential, except for the first-owner bootstrap
     - export or import with a password
   - The current UI ignores `role`. The new UI must not.
7. **Setup lock.** While `needsSetup` is true, the server refuses every `requireAdmin` route except `POST /api/admin/set-credential`.
   - The UI should show only the setup form: username (default `admin`), a password of 8+ characters, and an optional DTMF PIN of 4-16 digits.
   - Show the banner: phones cannot register, and SIP stays off until a real admin login is set.
   - Run every other admin fetch only after setup is done.
8. **Client gate.** Before any write, require `authenticated && !needsSetup`; otherwise open login or setup. This is what the current `gateCheck()` does.
9. **Session timer.** Count `sessionRemainingSec` down locally once a second. Re-sync it from `/api/admin/status` every 15 s.
10. **Ungated data is public.** Anyone on the network can read `/api/status` (without the roster), `/api/admin/status`, `/api/ota/status`, `/api/wifi/scan` and `/metrics`. Show nothing sensitive in the pre-login view beyond what these return.
11. **Secrets.**
    - `GET /api/ap-security` returns the PSK in clear. Mask it by default and reveal it on click.
    - Trunk, email and telephony secrets are write-only: the server returns only the `hasPassword`, `hasGsaKey` and `secretSet` booleans.
    - A blank secret field keeps the stored value. To erase the trunk password, send `clearPassword`.
12. **Captive-portal redirect (ESP).** A GET whose Host is not local is redirected to `http://192.168.4.1/`, except `/api/status` and `/api/wifi/scan`. Use relative URLs and never hard-code a host.
13. **Transport.** There is no WebSocket and no SSE; everything live is polling. Request bodies are capped at 16 KB, except the two upload routes. Large config-import blobs or CA PEMs could hit that cap (**unverified** for real export sizes, and form encoding inflates JSON).
14. **Poll budget.** Stay at or below today's load: status every 2 s, CDR every 5 s, admin/status every 15 s, OTA status every 15 s, trace every 1.5 s only while on, MOH every 3 s only while visible. Poll only for the visible section. `tests/load/http_load.py` `POLLS` and `test_http_load.py::test_the_poll_table_is_index_html_hs` pin the poll table to the file text, so update both together.

## 5. Embedding constraints for `index_html.h`

**Literal caps.** `tools/check_string_literal_caps.py` is the first CI step and runs `--selftest` and then the scan:

| Rule | Value | Effect |
|---|---|---|
| Raw literal content | 16384 bytes | over the cap fails the build |
| Ordinary literal | 16383 decoded characters | over the cap fails the build |
| Line endings | normalized to LF before measuring | – |
| Headroom under 512 bytes (`TIGHT_BYTES`) | – | warning only |
| Adjacent-literal run over 65535 (`RUN_CAP`) | – | warning only |

**Delimiters and structure:**
- Each part is its own `static const char PD_HTML_N[] = R"htmlN(` … `)htmlN";`, with a unique delimiter per part and the opener inline with the content.
- Parts are never concatenated. They stay in flash `.rodata` at zero RAM cost.
- Content must never contain its own closing sequence `)htmlN"`.

**Symbols the unchanged backend still references:**
- `CGA_INDEX_HTML_PARTS`, an ordered array of the SPA parts (each with `sizeof-1`), and `CGA_INDEX_HTML_PART_COUNT`. `sendHtml` streams `/` from these two. The part count can change.
- `PD_HTML_8` (served by `sendEmailSetupHtml`) and `PD_HTML_9` (served by `sendTrunkSetupHtml`).
  - `/setup/email` and `/setup/trunk` remain ungated routes, so both symbols must still exist and compile.
  - If the new SPA absorbs the email and trunk forms, those two parts can shrink to minimal shells, for example a redirect to `/#maintenance` or `/#trunks`.
  - Each must still carry exactly one CSRF marker (next rule).

**CSRF marker:** `__PD_CSRF__` appears exactly once per page (the SPA, the email page, the trunk page) and sits whole inside one part. Only the first occurrence is replaced. `HttpStaticPages_test::EveryPageCarriesExactlyOneCsrfMarker` enforces this. A part split can otherwise fall at any byte.

**Total size:**
- Today the SPA is about 121.9 KB in 8 parts. Five parts have under 800 bytes of headroom.
- No checker caps the total. The practical limit is the app-partition headroom, which is not measured here (**unverified**).
- Target at most today's ~122 KB plus ~18 KB for parts 8 and 9.
- Inline everything: no external CDN, since the device may be in AP mode with no internet.
- Minify, but keep it human-diffable.

**Tests that `#include "index_html.h"` and assert on its text:**
- `AdminHttpGate_test`
- `DashboardA11yText`
- `DashboardE911Form`
- `DashboardLearnText`
- `DashboardResetText`
- `DashboardRosterText`
- `DashboardSetupBanner`
- `EmergencyRoute`
- `HttpStaticPages`
- `HttpTraceCommand` (references the file in comments only)
- `tests/tools/test_http_load.py`, which reads the poll table

Rewrite these tests alongside the UI. They are test code, not backend. Keep the safety-relevant assertions: E911 form, setup banner, Learn/lockout text, reset confirmation, and the CSRF marker.

## 6. Section-to-route mapping

None of the ten sections lacks a backing route. Features within a section that have no route are marked **no API: omit**.

| Section | Routes | Notes |
|---|---|---|
| **Overview** | GET `/api/status` (version, uptime, heap, stack HWM, clientCount, sessionCount, parkedCount, coredump flag, mediaTx); GET `/api/admin/status`; GET `/api/ota/status` (running partition, pendingVerify); GET `/api/cdr` (recent calls); GET `/api/e911-config` (feeds the "E911 not configured" banner, which is expected in SBC mode); GET `/api/sbc-mode` | Pre-login view: only the ungated fields. |
| **Extensions** | GET `/api/status` (`clients`, `dnd`, `voicemail`, `forwards`, `sessions`; needs a session); POST `/api/dnd`, `/api/voicemail`, `/api/forward`, `/api/kill` | Create, rename or delete an extension, and set per-extension SIP passwords: **no API: omit**. Extensions come from registrar Learn and zero-touch. |
| **Devices** | GET/POST `/api/registrar`; POST `/api/registrar/device` (secure/forget); POST `/api/registrar/forget-learned`; GET/POST `/api/pnp`; GET/POST `/api/zero-touch`; `/config/<file>` (show the URL patterns only) | The per-device "Secure" action needs a SIP password, which is not supported. Keep it disabled with that explanation. Pushing per-device provisioning config: **no API: omit**. |
| **Trunks & numbers** | GET/POST `/api/trunk`; GET `/api/telephony-config`; PUT/DELETE `/api/telephony-config/<i>`; POST `.../<i>/activate`; POST `.../<i>/test`; GET/PUT/DELETE `/api/did-mapping` | Trunk registration status: the map shows no route for it beyond `enabled` (**unverified**), so **no API: omit** unless `/api/status` carries it. |
| **Routing** | POST `/api/dialplan` (rule list read from `/api/status.dialplan`); GET/PUT `/api/sbc-mode` (route = telephony slot index, bounded by `maxRoute`); GET/PUT `/api/e911-config` | Reserved extension ranges (700-709 park, 980-989 page) are fixed in firmware and can be shown as read-only text: **no API: omit** editing. |
| **Call handling** | POST `/api/group`, with groups read from `/api/status.groups`; POST `/api/forward`, with the forward overview from `/api/status.forwards`; GET/PUT `/api/multicast-paging`; parked calls read-only from `/api/status.parkedCalls/parkedCount`; POST `/api/kill` | Park, unpark, transfer and hold from the UI: **no API: omit**. |
| **Audio** | GET `/api/moh`; POST `/api/moh/upload` (XHR, raw WAV); POST `/api/moh/preview`, `/api/moh/preview/stop`; POST `/api/media-tx` (Owner) | Codec selection, gain and jitter-buffer settings: **no API: omit**. |
| **Security** | GET `/api/admin/status`; POST `/api/admin/login`, `/logout`, `/set-credential` (password, DTMF PIN); POST `/api/admin/set-owner-credential` (**new in the UI**); GET/POST `/api/ap-security`; registrar mode (Learn/Secure) cross-linked from Devices | User list and multi-user management: **no API: omit**. Audit log: **no API: omit**. |
| **Maintenance** | See the grouped list below the table. | Wipe the factory-reset confirm field after use. |
| **Live console** | GET `/api/trace` (poll every 1.5 s while on, keyed on `seq`); GET `/api/pcap` (download link); GET `/api/status` (live sessions); GET `/api/cdr`; console commands such as `email test <addr>` map onto the routes above | Polling only, because the server has no WebSocket or SSE. A true streaming log or server-side shell: **no API: omit**. |

Maintenance routes by group:
- **Firmware:** GET `/api/ota/status`; POST `/api/ota/upload` (Owner, XHR, Content-Length required); POST `/api/ota/reboot`
- **Backup:** GET/POST `/api/config/export`; POST `/api/config/import`
- **Reset:** POST `/api/factory-reset` (Owner)
- **Network:** GET `/api/wifi/scan`; POST `/api/wifi/connect`, `/api/wifi/mode_ap`, `/api/configuring`
- **Notifications:** GET/POST `/api/email`, POST `/api/email/test`
- **Logging:** GET/POST `/api/syslog`
- **Crash:** GET `/api/coredump/info`; GET `/api/coredump` (Owner); POST `/api/coredump/erase`
- **Capture:** GET `/api/pcap`
- **Metrics:** link to `/metrics`

`/api/bench/fault` is bench-only: **omit from the production UI**.
