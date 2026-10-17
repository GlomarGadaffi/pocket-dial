# pocket-dial SBC fork — architecture statement (owner's, 2026-10-16)

Goal: **outcome parity** with the 3CX Pi SBC, not tunnel parity. Phones sit on a LAN box; the extensions, their status, BLF and voicemail state live in 3CX and follow the 3CX user.

## Shape
- **South (phones): SIP.** Phones register to pocket-dial as today (local registrar, Learn/Secure). Everything a phone learns comes from pocket-dial as SIP: dialog-info/presence NOTIFY for BLF, message-summary NOTIFY for MWI, 1xx/2xx for calls.
- **North (3CX): API only.** Three channels, nothing else:
  1. Call Control API over HTTPS — actions (makecall, answer, drop, divert, route, transfer; no hold/resume).
  2. Call Control API WebSocket — call/participant events.
  3. XAPI (OData) — user, profile status / forwarding profile, voicemail counts, directory.
  No 3CX tunnel. No upstream SIP registration of phones to 3CX. Media stays on the anchor path ADR-002 defines.
- **Middle: sync machines.** One per domain, each: 3CX state in (event where the API pushes it, poll where it does not) → local state → SIP NOTIFY out and /api/status fields. Rules from CONTRIBUTING_FIRMWARE.md apply: no heap in the packet path, short locks, bounded pools, clocked by the 1 Hz tick; polling cadences are per-machine constants.

## Machines (to be confirmed by scratchpad fresh/3cx-api-surface.md and sbc-state-machines.md)
| Machine | In | Out | Exists today |
|---|---|---|---|
| Call state relay | WS participant events | call legs, UI | AnchorClient (yes) |
| Profile status sync | XAPI (poll or event) | DND/forward state per extension; UI | no |
| Remote BLF | WS/XAPI extension state | dialog-info NOTIFY to subscribed phones | BlfSubscriptions covers local only |
| Remote MWI | XAPI voicemail counts | message-summary NOTIFY | MWI covers local only |
| Registration / survivability | local SIP; API reachability | /api/status, alarm banner | registrar yes; survivability rules to define |

## UI consequence
The SBC profile's MAIN annunciator gets tiles for API WS, XAPI, and each sync machine (nominal grey; P2 when a poll is stale; P1 when the WS is down), and the status strip shows the last successful sync per machine as a well with a seconds unit.

## Out of scope
The 3CX tunnel protocol; anything that needs 3CX-private interfaces. Say so in the profile's copy.
