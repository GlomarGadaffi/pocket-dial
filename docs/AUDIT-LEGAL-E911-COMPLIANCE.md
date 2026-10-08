# Legal & Regulatory Audit: E911 Compliance under Programmable Media Anchors

## Executive Summary
This audit evaluates the compliance of the **Pocket-dial** embedded PBX firmware with United States Federal Communications Commission (FCC) emergency calling regulations, specifically:
1. **Kari's Law** (47 U.S.C. § 623, codified at 47 CFR § 9.16)
2. **RAY BAUM'S Act Section 506** (codified at 47 CFR Part 9)
3. **FCC Interconnected VoIP Rules** (47 CFR Part 9)

Following the strategic transition from traditional ITSP SIP trunks to **Cloud Media Anchors** (3CX, Apidaze, CPaaS platforms per ADR-002), this document outlines how emergency call signaling, on-site notification, dispatchable location, and public safety answering point (PSAP) callback obligations are satisfied.

---

## 1. Statutory & Regulatory Framework

### 1.1 Kari's Law (Multi-Line Telephone Systems - MLTS)
Kari's Law applies to any Multi-Line Telephone System (MLTS) manufactured, imported, sold, leased, or installed after February 16, 2020. It establishes two non-negotiable requirements:
1. **Direct Dialing (47 CFR § 9.16(b)(1))**: The MLTS must be configured so that any user can dial 911 directly from any station without dialing an outside-line access code, trunk prefix (such as '9'), or any other prefix.
2. **On-Site Notification (47 CFR § 9.16(b)(2))**: The MLTS must initiate contemporaneous notification to a central location at the facility where the system is installed (e.g., front desk, security office, or administrative staff) or an off-site location designated by the system operator. The notification must indicate that a 911 call has been made, provide a valid callback number, and convey the caller's location to the extent technically feasible. Crucially, the notification **must not delay the 911 call itself**.

### 1.2 RAY BAUM'S Act Section 506 (Dispatchable Location)
RAY BAUM'S Act mandates that all 911 calls from MLTS and interconnected VoIP systems provide a **dispatchable location** to the PSAP:
- **Definition**: A dispatchable location consists of the validated street address of the calling party, plus additional information such as suite, room, floor, or building wing necessary to locate the caller in a reasonable amount of time.
- **Fixed vs. Non-Fixed Endpoints**:
  - *Fixed Endpoints (desk phones)*: Automated dispatchable location must be delivered with each call.
  - *Non-Fixed Endpoints (softphones, wireless SIP phones)*: Must provide automated dispatchable location where technically feasible, or allow customer-provided/updated manual location entry.

---

## 2. Pocket-dial Architecture & Compliance Assessment

### 2.1 Direct Dialing & Dial-Plan Isolation (Compliant)
- **Direct 911 Execution**: Evaluated in `src/SIP/EmergencyCall.hpp` (`pbx::classifyEmergencyDial`). Exact string matching detects `911` and `933` (carrier E911 test service).
- **Trunk Prefix Tolerance (`9911`)**: While direct dialing is standard, users who reflexively dial `9-9-11` out of habit are protected: the PBX strips the single leading `9` and routes `911` immediately (FCC 19-76 compliance).
- **Pre-Dialplan Priority Bypass**:
  ```
  Incoming INVITE -> Capability Gate (Codec/Registration) -> classifyEmergencyDial() -> routeEmergencyCall()
                                                                       |
                                                               (Normal Call Flow)
                                                                       v
                                                           DialPlan / RingGroups / DND
  ```
  Emergency classification runs strictly **before** operator-configured dial plans (`DialPlan.hpp`), ring groups, speed dials, and policy locks. An operator rule such as `9*` (strip 1 digit) cannot intercept or rewrite `911` into `11`.
- **Policy Gate Bypass**: The call bypasses Do-Not-Disturb (DND), call forwarding (CFNA/CFU), and administrative PIN authentication.

### 2.2 On-Site Notification (Compliant)
- **Zero-Delay Invariant**: Implemented in `src/SIP/EmergencyNotifier.hpp`.
  - The emergency call leg is allocated and enqueued in the SIP outbox **first**.
  - `EmergencyNotifier::notify()` executes only *after* `originateAnchorCall()` has successfully claimed the leg.
  - No notification error (pool exhaustion, unregistered notification extensions) can block, delay, or fail the emergency call leg.
- **Contemporaneous Dispatch**: Because the emergency INVITE and notification messages share the same dispatch batch (`RequestsHandler::drainOutbox()`), the notification leaves simultaneously with the call.
- **Notification on Call Failure**: If an emergency call fails (e.g. no outside line reachable), `EmergencyNotifier::notify()` triggers immediately with failure attribution so on-site staff can take manual action.

### 2.3 RAY BAUM'S Act under Cloud Media Anchors (Architecture Mapping)
In traditional SIP trunks, the local PBX was required to assemble SIP `Geolocation` headers or `PIDF-LO` XML bodies. Under the **Cloud Media Anchor architecture** (ADR-002, 3CX / Apidaze):
1. **Delegation to Interconnected VoIP Edge**:
   - The cloud media anchor provider (Apidaze, 3CX, VoIP Innovations) acts as the interconnected VoIP carrier with direct integration into the National Emergency Service Routing Proxy (ESRP) network.
2. **Civic Address Registration**:
   - Every outbound DID / CLI provisioned on the cloud media anchor must have an associated, MSAG-validated (Master Street Address Guide) address stored in the provider's E911 registry.
3. **Fixed MLTS Deployments**:
   - For single-site deployments where Pocket-dial controls extensions at a known physical facility, assigning the facility's registered DID to the outside anchor leg satisfies the dispatchable location mandate.
4. **Multi-Station / Room Level Granularity**:
   - In facilities requiring room/floor granularity under RAY BAUM'S Act:
     - Administrators must assign individual sub-account DIDs or location IDs to specific station profiles, or
     - Utilize cloud anchor APIs supporting per-call location parameter overrides (e.g., Apidaze custom SIP headers / REST parameters).

### 2.4 PSAP Callback Window (Compliant)
- **30-Minute Protective Window (`src/SIP/EmergencyCall.hpp`)**:
  - `pbx::kEmergencyCallbackWindow` defines a 30-minute window.
  - When an extension dials 911 or 933, its station mark is recorded in fixed internal memory.
  - Any incoming call delivering to that extension during the next 30 minutes is automatically promoted to an emergency session (`Session::isEmergency() = true`).
  - This prevents an incoming 911 callback from being deflected to voicemail, rejected by DND, or preempted by call waiting.

### 2.5 Outage & Failover Protocols
- **Provider Readiness Check (`telephonyProviderPlacesRealCalls()`)**:
  - Evaluated in `src/SIP/TelephonyProvider.hpp`. Simulated providers (such as `LoopbackAnchorClient`) explicitly report `false` and are barred from receiving 911 routing.
- **Network Outage Signalling**:
  - If the cloud media anchor is disconnected or the WAN is down, the PBX immediately returns SIP `503 Service Unavailable` with clear cause headers so compliant handsets can trigger local cellular fallback or prompt the caller to use an alternate device.

---

## 3. Compliance Summary & Operator Checklist

| Regulatory Requirement | Statute / Rule | Firmware Mechanism | Status |
|---|---|---|---|
| Direct 911 dialing (no prefix) | 47 CFR § 9.16(b)(1) | `pbx::classifyEmergencyDial` | **COMPLIANT** |
| Single-prefix tolerance (`9911`) | FCC 19-76 | Leading '9' strip in `classifyEmergencyDial` | **COMPLIANT** |
| Dial plan & policy bypass | 47 CFR § 9.16(b)(1) | Pre-dialplan routing in `onInvite()` | **COMPLIANT** |
| On-site notification | 47 CFR § 9.16(b)(2) | `EmergencyNotifier` | **COMPLIANT** |
| Notification zero-delay guarantee | 47 CFR § 9.16(b)(2) | Outbox ordering & best-effort notification | **COMPLIANT** |
| PSAP Callback protection | 47 CFR § 9.16 | `EmergencyCallbacks` 30-min window | **COMPLIANT** |
| Dispatchable Location | 47 CFR Part 9 | Cloud Media Anchor DID MSAG registration | **COMPLIANT (Operator Config)** |
| 933 Carrier Test Calling | Industry Standard | Dedicated `kEmergencyTestNumber` path | **COMPLIANT** |

### Operator Configuration Checklist
For enterprise operators deploying Pocket-dial with Cloud Media Anchors:
1. **Register E911 Address**: Ensure all outside-line DIDs configured in the Apidaze/3CX portal have a verified, active civic street address.
2. **Designate On-Site Notification Target**: Configure `emergency_notify_extension` in the PBX configuration pointing to the front desk, security console, or administrative ring group.
3. **Verify with 933 Test**: Dial `933` from a provisioned handset. Confirm the carrier's automated service reads back the expected callback number and address. Never dial a live `911` for testing.
