# ADR-002: Programmable Media Anchor Interface for PSTN Interconnect

## Status
Accepted (Part of #920, Epic #381)

## Context
Pocket-dial's initial outside-line interconnect architecture attempted to maintain two distinct paths:
1. **ITSP SIP Trunks (`SipTrunk`)**: Direct SIP signaling (RFC 3261) and RTP media relay over UDP to carrier Session Border Controllers (SBCs).
2. **Media Anchors (`TelephonyAnchorClient`)**: Asynchronous cloud B2BUA call control and bidirectional audio streaming, originally implemented against the 3CX Call Control API.

Field deployments and soak testing revealed critical structural limitations with direct ITSP SIP trunks on resource-constrained embedded nodes:
- **Residential NAT / CGNAT / SIP ALG Drop Modes**: Carrier-facing SIP over UDP suffers silent INVITE drops whenever SDP bodies exceed MTU or encounter stateful middleboxes / SIP ALGs (#618, #919).
- **Embedded Task & Memory Exhaustion**: Running dual B2BUA SIP transactions, digest authentication, registration state machines, and dual raw RTP relay buffers on ESP32-S3 consumes over 12 KB of critical internal DRAM and multiple FreeRTOS task stacks.
- **Carrier Interop & PSTN Compliance Complexity**: In-dialog variations across Tier-1 carriers (#874, #873) and E911 dispatch obligations create immense firmware maintenance overhead.

To resolve this, the project executed a strategic pivot: **shelve traditional ITSP SIP trunks behind Milestone 11** and standardize entirely on **cloud media anchors and programmable telephony paths** for PSTN interconnect.

## Decision

We define a standardized, decoupled **Programmable Media Anchor Interface** that isolates the PBX engine from specific cloud provider implementations:

```
+--------------------------------------------------------------------+
|                         Pocket-dial PBX                            |
|                                                                    |
|  [ Handset SIP Dialogs ] <---> [ RequestsHandler / Session ]       |
|                                         |                          |
|                                  [ MediaBridge ]                   |
|                                 (PCM-16 / 8kHz)                    |
+-----------------------------------------|--------------------------+
                                          |
                      +-------------------+-------------------+
                      |   IAnchorProvider (C++ Interface)     |
                      +-------------------+-------------------+
                                          |
             +----------------------------+----------------------------+
             |                                                         |
+---------------------------+                             +---------------------------+
|    3CX Anchor Adapter     |                             |   Apidaze Anchor Adapter  |
|  (TelephonyAnchorClient)  |                             |   (REST + AudioSocket)    |
|                           |                             |                           |
| - REST Call Control       |                             | - REST: /calls, /hangup   |
| - WebSocket Events        |                             | - AudioSocket: TCP / WSS  |
| - PCM Stream Endpoint     |                             | - Type 0x10 PCM16 8kHz    |
+---------------------------+                             +---------------------------+
```

### 1. Provider Control Plane Contract (`IAnchorProvider`)
The control plane manages outside-line call lifecycles through an asynchronous REST/HTTP client abstraction:
- `makeCall(e164, handsetCallId, options)` -> Initiates outbound PSTN call.
- `hangup(anchorCallId)` -> Terminates anchor leg.
- `answer(anchorCallId)` -> Accepts an inbound PSTN call.
- `mute(anchorCallId, muted)` -> Toggles audio transmission.
- `dtmf(anchorCallId, digit)` -> Transmits out-of-band DTMF digits to the cloud provider.

### 2. Provider Media Plane Contract (AudioSocket Streaming)
The media plane connects to Pocket-dial's internal `MediaBridge` (which already synthesizes and mixes 8 kHz, 16-bit signed linear PCM audio):
- Standardized on the open **AudioSocket** binary framing protocol:
  - **3-byte framing header**:
    - `uint8_t  type`:
      - `0x01` (`UUID`): Initial 16-byte call identifier handshake.
      - `0x10` (`Audio`): Linear signed 16-bit PCM @ 8000 Hz, mono (320 bytes = 20ms).
      - `0x00` (`Hangup`): Remote disconnect notification.
      - `0xFF` (`Error`): Provider or bridge error.
    - `uint16_t length`: Big-endian payload size (e.g. 320 for 20ms audio frame).
  - **Payload**: Raw 16-bit PCM samples or binary UUID.
- Connection transport: Outbound TCP or TLS/WebSocket client initiated by the PBX node to the cloud provider's edge relay, bypassing all residential NAT/CGNAT ingress barriers.

### 3. Apidaze CPAAS Mapping (Issue #920)
Apidaze (VoIP Innovations) serves as the reference secondary anchor beside 3CX:
- **Signaling / Call Control**:
  - `POST /{api_key}/calls`: Dispatches outbound PSTN calls authenticated by API key and secret.
  - `DELETE /{api_key}/calls/{uuid}`: Hangs up call.
  - `POST /{api_key}/calls/{uuid}/message`: Dispatches DTMF (`{"type":"dtmf_event","data":"X"}`) and control signals into the active audio socket.
- **Media**: Outbound AudioSocket connection streaming bidirectional PCM16 audio.
- **Inbound DID routing**: Webhook triggering external script directing call to the board's secure socket stream.

### 4. Compile-Out & Resource Invariants (#731)
- When compiling production constrained builds or anchor-only profiles:
  - `POCKETDIAL_HAS_ANCHOR = 1`
  - `POCKETDIAL_HAS_TRUNK = 0`
  - `POCKETDIAL_MAX_TRUNK_CALLS = 0`
- `SipTrunk.cpp` is wrapped and completely compiled out.
- Zero `SipTrunk` symbols are emitted into the firmware image.
- Internal DRAM task stack slots for trunk RTP receivers are freed, preserving ~12 KB of internal RAM and saving over 35 KB of application partition flash.

### 5. Emergency (E911) Policy
- All programmable media anchor providers must register emergency caller service profiles.
- If an anchor provider does not support Kari's Law / RAY BAUM'S Act compliant emergency routing, the PBX enforces local dispatch notification and fallback routing per Rule 5.

## Consequences

### Positive
- **Guaranteed Middlebox Traversal**: No UDP packet loss, no SIP ALG tampering, no residential router NAT timeouts. Outbound TLS/WSS connections remain resilient.
- **Zero Carrier Signaling Drift**: Dialplan logic, carrier-specific headers, and re-INVITE handling are delegated to the cloud CPAAS platform.
- **Significant RAM and CPU Savings**: Firmware eliminates dual SIP UAS/UAC transaction tracking for PSTN legs.

### Trade-offs & Mitigations
- **Requires Outbound Cloud Connectivity**: The node requires active internet connectivity to communicate with the cloud anchor. (Mitigation: Local extension-to-extension calls, intercom, paging, and local voicemail operate 100% autonomously without cloud connectivity).
- **Provider API Dependency**: Requires configured API credentials with 3CX or Apidaze. (Mitigation: Modular provider adapter pattern allows adding alternative CPAAS providers like Telnyx or Asterisk AudioSocket without modifying PBX core).
