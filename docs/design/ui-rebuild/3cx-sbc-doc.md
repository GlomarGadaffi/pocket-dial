# 3CX SBC — what the vendor page says (captured 2026-10-16)

Source: https://www.3cx.com/docs/3cx-tunnel-session-border-controller/ (page states "last updated 10 September 2026"). Captured from the rendered page because WebFetch returned only the title. Paraphrased; short quotes only.

## What it is
- A software service installed in the local network that lets IP phones connect to a 3CX instance in the cloud or a remote on-premise 3CX.
- It "combines all SIP (signaling) and RTP (media) VoIP Packets from one location and delivers them to 3CX" — i.e. a tunnel/aggregator, overcoming firewall and NAT issues. (The page does not state the port, transport or encryption.)
- Must run on a machine with a static LAN IP and "must be running all the time".
- Recommended when a site has more than 10 phones. Under 10, 3CX recommends an SBC-capable "router phone" (listed Fanvil, Snom and Yealink models) instead; a single remote phone should use the 3CX apps.

## How it is set up
- Platforms: Raspberry Pi 5 (own guide), Windows 10 / Server 2016+, Debian via the 3CX ISO.
- In the 3CX Admin Console: Voice & Chat → Add SBC → choose machine type. 3CX creates the SBC record and shows install instructions, a **Provisioning URL** and an **Authentication Key ID**.
- Installer asks for the Provisioning URL and the Authentication Key ID. After install, "the SBC will now be listed when a user creates a normal phone that requires a router phone or an SBC".
- Phones are then provisioned through 3CX's normal phone provisioning (separate guide). The phones are 3CX extensions; the SBC has no local PBX role.

## What the page does NOT say
- Tunnel port/protocol, encryption details, phone limits, bandwidth, local survivability, status/monitoring API, update mechanism. Treat all of those as unconfirmed from this page.

## Implication for pocket-dial
- The Pi SBC is a transport aggregator for phones that belong to 3CX. pocket-dial is a local registrar: phones belong to pocket-dial and outside calls are anchored via the 3CX Call Control API. These are different models; "parity" with the tunnel itself needs the 3CX tunnel protocol, which is not published.
- A non-tunnel route to the same user outcome (phones on a LAN box, extensions living in 3CX) would be pocket-dial as a per-extension SIP B2BUA/proxy registering upstream to 3CX over plain SIP (TLS/SRTP), using the existing trunk engine rather than the anchor. Not blocked, but a different product than SBC mode.
