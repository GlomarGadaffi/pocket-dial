# Firmware Security Audit & Threat Model Report

Project: pocket-dial (ESP32 VoIP PBX Firmware)  
Date: June 1, 2026  
Auditor: AgencyAuditSpecialist  
Status: Complete, Post-Refactor Review & Threat Evaluation  

> [!CAUTION]
> **This is a point-in-time record. It is not a description of the firmware as it ships today.**
>
> | | |
> |---|---|
> | Originally written | 2026-06-01, against commits `8be61da` / `f919178` |
> | Partially amended | 2026-09-03 (`e631fc2`), SEC-04 re-marked Resolved, registrar modes + CSRF |
> | Banner added | 2026-09-13, HEAD `fbad51b` |
> | Re-audited since? | **No.** No fresh security audit has been run against the current tree. |
>
> **Read these four corrections before acting on anything below.**
>
> 1. **The "dark by default" HTTP transport in SEC-04's remediation table is GONE
>    (`de1a36e`, 2026-09-13).** The dashboard listen socket is always bound and the
>    dashboard is **always reachable**. There is no `*4887` star code, no DTMF-opened
>    admission window, and no grace period; those mechanisms were deleted, not
>    merely defaulted off. That table row is struck through in place below. Any
>    operator procedure that says "reopen the web UI with a star code" is wrong and
>    will waste your time on a device that is already listening.
> 2. **The admin credential is a username + password, not a PIN.** `AdminAuth` ships
>    a default `admin`/`admin` with a *forced* first-use change (`AdminAuth::needsInitialSetup()`,
>    gated in [HttpServer.cpp:1868](../src/Helpers/HttpServer.cpp#L1868)); the routes are
>    `POST /api/admin/set-credential` ([HttpServer.cpp:668](../src/Helpers/HttpServer.cpp#L668))
>    and `POST /api/admin/login` ([HttpServer.cpp:678](../src/Helpers/HttpServer.cpp#L678)).
>    A **separate** numeric DTMF PIN still exists for the phone-keypad admin menu
>    (`*PIN#code`); it is unrelated to the web session and unlocks no HTTP.
> 3. **INVITE *is* now independently challenged in Secure mode**: the residual-risk
>    paragraph under SEC-04 that says otherwise is stale. See
>    [RequestsHandler.cpp:1195-1206](../src/SIP/RequestsHandler.cpp#L1195-L1206).
> 4. **The shipped default registrar mode is still `open`.** A fresh board accepts any
>    REGISTER and any INVITE until an operator changes `reg_mode`. Digest auth and the
>    Learn-mode TOFU/ARP MAC-lock are implemented; they are simply not on by default.
>
> Line numbers quoted throughout this document predate the decomposition of
> `RequestsHandler` into `CallForker` / `CallPickup` / `ParkOrbit` / `BlfSubscriptions` /
> `DtmfFeatureCodes` / `CdrRing` and are stale unless a correction note says otherwise.

## Executive Summary

This security audit and threat model report evaluates the network-facing and local attack surfaces of the **pocket-dial** ESP32 PBX firmware codebase (`GlomarGadaffi/pocket-dial`). The primary objectives are to analyze entry points, assess the robustness of parsers, review access control mechanisms, and classify findings using CVE-class severity ratings and CVSS v3.1 scoring vectors.

> [!WARNING]
> **Summary of Findings:** The firmware has successfully mitigated two high-risk vulnerabilities (**Host/Origin Validation (DNS Rebinding)** and **SIP Signaling Input Injection**) via the recently integrated security patches. 
> However, significant physical and local network security gaps remain. **SEC-04 has since been
> remediated** on both planes: see its entry below. The most critical outstanding issue is now
> **Cleartext WiFi Credentials Storage in Flash NVS (SEC-03, Low/Medium Severity)**, whose durable
> fix is flash encryption + Secure Boot v2. The dominant *residual* risk is no longer an
> authentication gap but the **open SoftAP link** itself; WPA2 for it now ships but defaults to
> off for fleet compatibility, so it protects only deployments that enable it (see
> [THREAT_MODEL.md](THREAT_MODEL.md) §6 and TB-1).

## System Attack Surface Map

The pocket-dial PBX exposes multiple UDP/TCP listening services and interacts directly with non-volatile flash storage:

```
                              [ ATTACK VECTORS ]
                                      │
         ┌────────────────────────────┼────────────────────────────┐
         ▼                            ▼                            ▼
   [ Port 53 UDP ]              [ Port 5060 UDP ]            [ Port 80 TCP ]
      DnsServer                   UdpServer (SIP)               HttpServer
   (DNS Redirection)            (Signaling Parser)         (CGA Admin Dashboard)
         │                            │                            │
         ▼                            ▼                            ▼
 ┌──────────────────┐         ┌──────────────────┐         ┌──────────────────┐
 │ Captive Portal   │         │ RequestsHandler  │         │ Detached HTTP    │
 │ Host Redirection │         │ Pre-Allocated    │         │ Client Threads   │
 └────────┬─────────┘         └────────┬─────────┘         └────────┬─────────┘
          │                            │                            │
          │                            ▼                            │
          └───────────────────► [ NVS Storage ] ◄───────────────────┘
                                 SSID & Password
                                (Cleartext Flash)
```

1. HttpServer (Port 80/TCP): Exposes the admin dashboard, network scanning endpoints, and session teardown controls. Dispatches connections to detached thread contexts.
2. SIP UDP Server (Port 5060/UDP): Listens for SIP registration, call invites, session control signaling, and OPTIONS pings.
3. DNS Redirect Server (Port 53/UDP): Runs in captive portal mode to resolve all domain queries to the ESP32’s local IP address.
4. NVS Storage (Flash Partition): Stores plain text WiFi STA credentials and device system flags.
5. BLE (Bluetooth Low Energy): *Not currently implemented*. Custom GATT characteristics and bonding key security are threat-modeled below for future revisions.

## Issue Severity Summary Table

| ID | Finding Title | CVSS v3.1 Vector | Severity | Status |
| :--- | :--- | :--- | :---: | :---: |
| **SEC-01** | Host/Origin Header Validation Bypass (DNS Rebinding) | `CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H` | **Mitigated** | **Resolved** |
| **SEC-02** | Missing Request Parsing Validation on SIP Signaling | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N` | **Mitigated** | **Resolved** |
| **SEC-03** | Cleartext WiFi Credentials Storage in Flash NVS | `CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` | **Low/Medium (4.6)** | **Active** |
| **SEC-04** | Lack of Authentication on Admin HTTP and SIP Interfaces| `CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` | **Mitigated** | **Resolved** |

## Detailed Vulnerability Findings & Verifications

### SEC-01: Host/Origin Header Validation Bypass (DNS Rebinding)
* Classification: CWE-346: Origin Validation Error
* Vulnerable Component: `HttpServer::isSameOrigin` in [HttpServer.cpp](../src/Helpers/HttpServer.cpp#L514-L544).

#### Previous Behavior
`isSameOrigin()` previously checked mutating POST requests (`/api/kill`, `/api/wifi/connect`) by verifying that the `Origin` header matched the incoming `Host` header. Because it did not validate that the `Host` header was an authorized local interface, an attacker could mount a **DNS Rebinding Attack**. 

By resolving a malicious domain (e.g., `attacker.com`) to the ESP32's IP (`192.168.4.1`) with a low TTL, malicious javascript executed in a victim's browser could send requests with `Host: attacker.com` and `Origin: http://attacker.com`. The comparison returned `true`, bypassing CSRF protections and allowing unauthorized configuration writes.

#### Resolution Verification
The newly merged security patches successfully resolve this vulnerability. The updated `isSameOrigin()` helper strictly validates the scheme-stripped `Host` header against an authorized allowlist of local interfaces and mDNS hostnames:

```cpp
// Verified in HttpServer.cpp lines 535-542:
std::string cleanOrigin = stripPort(originHost);
std::string cleanHost = stripPort(req.host);

// Host header must be our local IP or local mDNS hostname or localhost
std::string activeIp = (_ip == "0.0.0.0") ? getPrimaryLocalIP() : _ip;
bool hostValid = (cleanHost == activeIp || 
                  cleanHost == "192.168.4.1" || 
                  cleanHost == "pocketdial.local" ||
                  cleanHost == "localhost" ||
                  cleanHost == "127.0.0.1");

return hostValid && (cleanOrigin == cleanHost);
```
Under this enforcement, a rebinding request carrying a foreign host header (such as `Host: attacker.com`) is rejected immediately with a `403 Forbidden` response.

### SEC-02: Missing Request Parsing Validation on SIP Signaling
* Classification: CWE-20: Improper Input Validation
* Vulnerable Component: `RequestsHandler::handle` in [RequestsHandler.cpp](../src/SIP/RequestsHandler.cpp#L59-L88).

#### Previous Behavior
The `SipMessage` class defines `isValidMessage()` to verify that mandatory headers (`Via`, `To`, `From`, `Call-ID`, `CSeq`) are present. However, this validator was never called inside `RequestsHandler::handle`. Malformed or truncated UDP packets returned empty headers upon parsing. 

Subsequent header mutation calls (such as `setVia()` or `setFrom()`) ran `.find("")` on empty member variables, which returned index `0`, prepending modified values at the very beginning of the packet and corrupting the SIP Request-Line.

#### Resolution Verification
The security patches successfully enforce validation at the signaling entry point. `RequestsHandler::handle` now immediately drops null or structurally malformed packets:

```cpp
// Verified in RequestsHandler.cpp lines 59-66:
void RequestsHandler::handle(std::shared_ptr<SipMessage> request)
{
    // Input validation: Drop null or structurally malformed packets instantly (SEC-02)
    if (!request || !request->isValidMessage())
    {
        _packetsDropped.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    // ...
}
```
This validation is backed by the per-source IP rate limiter, which acts as a secondary layer to drop packet floods lock-free.

### SEC-03: Cleartext WiFi Credentials Storage in Flash NVS
* Classification: CWE-312: Cleartext Storage of Sensitive Information
* Severity: **Low/Medium (CVSS v3.1 Score: 4.6)**
* Vector: `CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`
* Vulnerable Component: `HttpServer::sendApiWifiConnect` in [HttpServer.cpp](../src/Helpers/HttpServer.cpp#L704) and [esp_main_display.cpp](../main/esp_main_display.cpp#L432).

#### Description
When standard STA credentials are saved via the onboarding captive portal, the HTTP handler commits them directly to Espressif NVS Flash in cleartext under the `"storage"` namespace key `"wifi_pass"`. Similarly, the display boot path reads this value and registers it with the network stack. 

Because Flash Encryption is disabled by default, an attacker with physical access to the device can hook up to the UART programming pins and dump the raw SPI flash contents to extract the WiFi network password.

#### Proof of Concept (Attack Scenario)
1. An attacker gains physical access to the PBX hardware.
2. They connect a standard USB-to-UART bridge to the TX/RX/GND pinout of the ESP32.
3. They boot the ESP32 into flash download mode and dump the SPI flash contents:
   ```bash
   esptool.py --port COM3 --baud 921600 read_flash 0 0x1000000 flash_dump.bin
   ```
4. They run a strings extraction search on the binary dump to expose the cleartext password:
   ```bash
   strings flash_dump.bin | grep -A 2 wifi_ssid
   ```

#### Remediation
1. Enable Flash Encryption: Enforce compile-time Espressif Hardware Flash Encryption (via `menuconfig` or `sdkconfig.defaults`) to encrypt the partition tables, NVS, and application firmware partitions using an AES-256 key burned directly into the eFuse blocks.
2. Credential Obfuscation: Encrypt passwords prior to writing them to NVS using a symmetric algorithm (such as AES-CTR) with a key derived from the device-unique MAC address combined with compile-time salts.

### SEC-04: Lack of Authentication / Access Control on HTTP APIs and SIP Server

> **Status: RESOLVED.** Both planes described below have since been given real
> authentication. The description and proof-of-concept are kept verbatim as the
> historical record of the finding; see **Remediation status** at the end of this entry
> for what actually shipped and what residual risk remains.

* Classification: CWE-306: Missing Authentication for Critical Function
* Severity: **Medium (CVSS v3.1 Score: 6.5)**, as originally scored
* Vector: `CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N`
* Vulnerable Component: `HttpServer` routing & `RequestsHandler` registrations.

#### Description
1. Admin Dashboard: The administration panel does not require any credentials. Any device connected to the local network or Access Point can query `/api/status` to view active calls and registered extension numbers, or make POST requests to `/api/kill` to terminate active calls.
2. SIP Registrar: The SIP engine does not implement authentication challenges. Any softphone client can register arbitrary extensions without entering a password, allowing an attacker to intercept incoming and outgoing voice calls.

#### Proof of Concept (Attack Scenario)
1. An attacker joins the `esp32-sipserver` network.
2. They launch a standard softphone client (such as Linphone or MicroSIP).
3. They register as extension `100` targeting SIP proxy `192.168.4.1`.
4. Because the PBX does not issue a `401 Unauthorized` challenge, the registration succeeds instantly, evicting the legitimate extension from the registrar.
5. Alternatively, the attacker issues a simple curl request to disconnect calls:
   ```bash
   curl -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "extension=101" http://192.168.4.1/api/kill
   ```

#### Remediation status (what shipped)

| Plane | Shipped control |
|---|---|
| HTTP admin | Admin credential + server-side session (128-bit token, `HttpOnly`/`SameSite=Strict` `pd_session` cookie) on every mutating endpoint; brute-force lockout with exponential backoff and an aggregate backstop (**global, not per-client**, the per-IP key is never supplied on the login path, `HttpServer.cpp:2720-2732`; see [THREAT_MODEL.md](THREAT_MODEL.md) D-3); per-session CSRF token required in `X-CSRF`; same-origin checking; security response headers. All admission decisions go through one [`HttpServer::requireAdmin()`](../src/Helpers/HttpServer.cpp#L1828). |
| HTTP transport | ~~**Dark by default**: on a provisioned device the listen socket is not bound at all except inside a bounded window opened by a source-IP-verified DTMF code, a fresh-provisioning grace period, or an authenticated keepalive. An attacker usually cannot even reach the login endpoint.~~ |
| SIP registrar | Digest authentication (RFC 2617, MD5, `qop=auth`) challenging `REGISTER`, with runtime-selectable `open` / `learn` / `secure` modes and a per-extension HA1 secret store. **But `secure` is not deployable** since nothing in the firmware calls `SipSecretStore::setSecret()`, so no extension can be given a secret, `Registrar::secure()` refuses, and `secure` mode rejects every phone instead of authenticating it. `learn` (TOFU + ARP MAC lock) is the strongest mode that can actually be run, see [THREAT_MODEL.md](THREAT_MODEL.md) §9 and [LEARN_MODE.md](LEARN_MODE.md) Step 4. |

> [!IMPORTANT]
> **Correction, 2026-09-13: the "HTTP transport" row above is obsolete and is struck
> through for that reason.** The dark-by-default listener was removed in `de1a36e`
> ("the dashboard must always be reachable, not dark-by-default once provisioned").
> There is no unbound-listener state, no `grantAdminHttpGraceWindow`, and no `*4887`
> star code anywhere in `src/`; grep confirms zero hits. **The listener is always
> bound and the dashboard is always reachable on a provisioned device.**
>
> What this means for the threat model: the login endpoint is now always exposed to
> anyone with link-layer reach, so the *entire* HTTP-plane defence is the credential,
> the session cookie, the CSRF token and the lockout; the "attacker usually cannot
> even reach the login endpoint" mitigation no longer applies and must not be counted
> in any residual-risk calculation made from this document.
>
> Also corrected in that row: the credential is a **username + password** (`AdminAuth`),
> not a PIN. The numeric PIN that still exists is the *DTMF* PIN for the phone-keypad
> admin menu (`*PIN#code`) and grants no HTTP access.

Residual risk, stated plainly *(as amended 2026-09-13)*: the **first-run window is still
open by design**: a factory-fresh device ships `admin`/`admin` with a forced change on
first use, so onboarding stays possible (THREAT_MODEL §5.1); the registrar's **default
mode is still `open`**, so the digest control protects only deployments that switch it;
and the stored HA1 is a bearer credential at rest, which is what makes SEC-03's
flash-encryption fix matter. See [THREAT_MODEL.md](THREAT_MODEL.md) §5 and §9.

> [!NOTE]
> **No longer residual:** this paragraph previously read "INVITE is not independently
> challenged in the current phase". That gap has since been closed; in Secure mode the
> INVITE is challenged with the same digest machinery as REGISTER, verified against the
> `INVITE` method taken from the request line
> ([RequestsHandler.cpp:1195-1206](../src/SIP/RequestsHandler.cpp#L1195-L1206)). Learn
> mode keeps TOFU semantics and Open mode still never challenges, which, given that
> Open is the shipped default, is the part that actually matters on a fresh board.

#### Original remediation guidance (historical)
1. HTTP Authentication: Implement standard HTTP Basic Authentication or token-based session cookies for all web endpoints.
2. SIP Digest Authentication: Implement standard MD5 Digest Authentication (RFC 3261 §22) inside `onRegister` and `onInvite` handlers to challenge registrations and outbound invites against a static list of authorized extension passwords:
   ```cpp
   // Recommended SIP Digest Challenge pseudocode inside onRegister:
   if (!hasAuthorizationHeader(data)) {
       auto challenge = build401UnauthorizedChallenge(data);
       _outbox.emplace_back(data->getSource(), challenge);
       return;
   }
   if (!verifyDigestResponse(data, extPassword)) {
       auto forbidden = build403Forbidden(data);
       _outbox.emplace_back(data->getSource(), forbidden);
       return;
   }
   ```

## Architectural & BLE Security Hardening

### Bluetooth Low Energy (BLE) Threat Model
While the current firmware does not use Bluetooth, if BLE is added in future revisions for easier mobile onboarding or remote provisioning, the following threats and security mitigations must be addressed:

```
[ Attack Vector: BLE Sniffing ] ──────► ( Over-the-Air Capture ) ──────► Unencrypted Credentials Leak
[ Attack Vector: Just-Works MITM ] ───► ( Bypass Pairing Verification ) ──► Unauthorized WiFi Config Write
```

1. Just-Works Pairing Vulnerability: By default, BLE "Just Works" pairing uses an unauthenticated protocol exchange, leaving it completely vulnerable to active Man-in-the-Middle (MITM) hijacking.
   * *Hardening:* Enforce **BLE Passkey Entry** or **Numeric Comparison** pairing mechanisms using Out-of-Band (OOB) QR codes rendered on the 3.5" LCD screen.
2. Eavesdropping of Custom GATT Characteristics: Provisioning clients writing passwords to standard unencrypted GATT characteristics expose credentials to OTA sniffing.
   * *Hardening:* Require secure connections (**LE Secure Connections** with AES-CCM encryption) and restrict read/write permissions on custom SSID/Password characteristics to authenticated, bonded links.
3. Storage of Bonding Keys: Bonding keys must be stored securely in an encrypted NVS partition to prevent extraction.
