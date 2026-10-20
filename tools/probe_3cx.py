#!/usr/bin/env python3
"""3CX API probe for the SBC profile scope. stdlib only; run with -I.

Reads PBX, CLIENT_ID, SECRET, TEST_DN from an env-style file (argv[1]).
Writes everything to the out dir (argv[2]) and never prints the secret or token.

Steps (each tolerant of failure, all recorded in report.md):
  1. POST /connect/token (client_credentials)           -> token.json (expires_in, token_type, scopes; token itself masked)
  2. GET  /xapi/v1/$metadata                             -> metadata.xml (+ entity/property summary for User, ActiveCall, SipDevice, Sbc)
  3. GET  /xapi/v1/Users?$select=...&$top=200             -> users.json (numbers + profile names only; names masked)
  4. GET  /xapi/v1/Users({id}) for TEST_DN                -> user_before.json
  5. PATCH /xapi/v1/Users({id}) {CurrentProfileName: other} then PATCH back -> patch.json (status codes, before/after)
  6. GET  /callcontrol                                    -> callcontrol_dns.json (DNs the SP may see)
  7. WS   wss://PBX/callcontrol/ws, Bearer, listen LISTEN_S seconds -> ws_events.jsonl (raw frames, 30 s)
"""
import sys, os, json, ssl, socket, base64, time, re, http.client, urllib.parse

LISTEN_S = 30

def load_env(p):
    env = {}
    with open(p, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            env[k.strip()] = v.strip().strip('"').strip("'")
    for k in ("PBX", "TEST_DN"):
        if not env.get(k):
            sys.exit(f"probe.env missing {k}")
    if not env.get("ACCESS_TOKEN") and not (env.get("CLIENT_ID") and env.get("SECRET")):
        sys.exit("probe.env needs ACCESS_TOKEN, or CLIENT_ID + SECRET")
    return env

def conn(host):
    ctx = ssl.create_default_context()
    return http.client.HTTPSConnection(host, 443, timeout=20, context=ctx)

def req(host, method, path, body=None, headers=None, raw=False):
    c = conn(host)
    h = {"Accept": "application/json"}
    if headers:
        h.update(headers)
    data = None
    if body is not None:
        if isinstance(body, (dict, list)):
            data = json.dumps(body).encode()
            h["Content-Type"] = "application/json"
        else:
            data = body if isinstance(body, bytes) else body.encode()
    try:
        c.request(method, path, body=data, headers=h)
        r = c.getresponse()
        b = r.read()
        c.close()
        if raw:
            return r.status, dict(r.getheaders()), b
        try:
            return r.status, dict(r.getheaders()), json.loads(b.decode("utf-8", "replace")) if b else None
        except Exception:
            return r.status, dict(r.getheaders()), b.decode("utf-8", "replace")[:2000]
    except Exception as e:
        return -1, {}, f"EXC {type(e).__name__}: {e}"

def mask(s):
    if not isinstance(s, str) or len(s) < 8:
        return "***"
    return s[:4] + "…" + s[-2:] + f" (len {len(s)})"

def main():
    env = load_env(sys.argv[1]); out = sys.argv[2]; os.makedirs(out, exist_ok=True)
    host = env["PBX"].replace("https://", "").rstrip("/")
    rep = [f"# 3CX probe — {host} — {time.strftime('%Y-%m-%d %H:%M:%S')}", ""]
    def w(name, obj):
        with open(os.path.join(out, name), "w", encoding="utf-8") as f:
            if isinstance(obj, (dict, list)): json.dump(obj, f, indent=1)
            else: f.write(obj if isinstance(obj, str) else obj.decode("utf-8", "replace"))

    # 1. token — either provided (admin-level, owner-supplied) or client_credentials for a Service Principal
    if env.get("ACCESS_TOKEN"):
        token = env["ACCESS_TOKEN"].strip()
        if token.lower().startswith("bearer "):
            token = token[7:].strip()
        w("token.json", {"source": "ACCESS_TOKEN provided by owner (admin-level)", "access_token": mask(token)})
        rep.append("1. token: provided by owner (ADMIN-LEVEL). Results below may exceed what the box's Service Principal token can do; re-run with CLIENT_ID+SECRET for the SP-scoped answer.")
    else:
        form = urllib.parse.urlencode({"client_id": env["CLIENT_ID"], "client_secret": env["SECRET"], "grant_type": "client_credentials"})
        st, hd, tok = req(host, "POST", "/connect/token", form, {"Content-Type": "application/x-www-form-urlencoded"})
        token = tok.get("access_token") if isinstance(tok, dict) else None
        w("token.json", {"source": "client_credentials", "status": st, "keys": list(tok.keys()) if isinstance(tok, dict) else str(tok)[:300],
                         "expires_in": tok.get("expires_in") if isinstance(tok, dict) else None,
                         "token_type": tok.get("token_type") if isinstance(tok, dict) else None,
                         "scope": tok.get("scope") if isinstance(tok, dict) else None, "access_token": mask(token or "")})
        rep.append(f"1. token: HTTP {st}; expires_in={tok.get('expires_in') if isinstance(tok, dict) else '?'}; token {'ok' if token else 'MISSING'}")
    if not token:
        rep.append("   stop: no token"); w("report.md", "\n".join(rep)); return
    auth = {"Authorization": f"Bearer {token}"}

    # 2. $metadata
    st, hd, meta = req(host, "GET", "/xapi/v1/$metadata", headers={"Authorization": auth["Authorization"], "Accept": "application/xml"}, raw=True)
    w("metadata.xml", meta if isinstance(meta, (bytes, str)) else str(meta))
    summary = {}
    if isinstance(meta, bytes) and st == 200:
        txt = meta.decode("utf-8", "replace")
        for ent in ("User", "ActiveCall", "SipDevice", "Sbc", "ForwardingProfile", "Voicemail", "Queue"):
            m = re.search(r'<EntityType Name="%s"[^>]*>(.*?)</EntityType>' % ent, txt, re.S)
            if m:
                props = re.findall(r'<Property Name="([^"]+)" Type="([^"]+)"', m.group(1))
                navs = re.findall(r'<NavigationProperty Name="([^"]+)"', m.group(1))
                summary[ent] = {"properties": props, "navigation": navs}
        # writability hints
        summary["_annotations_mentioning_Computed_or_Immutable"] = re.findall(r'<Annotation Term="Org\.OData\.Core\.V1\.(Computed|Immutable)"[^>]*>', txt)[:50]
        summary["_has_CurrentProfileName"] = "CurrentProfileName" in txt
        summary["_entitysets"] = re.findall(r'<EntitySet Name="([^"]+)"', txt)[:200]
    w("metadata_summary.json", summary)
    rep.append(f"2. $metadata: HTTP {st}; {len(meta) if isinstance(meta, bytes) else 0} bytes; entity sets {len(summary.get('_entitysets', []))}; User has CurrentProfileName: {summary.get('_has_CurrentProfileName')}")

    # 3. users
    sel = "Id,Number,CurrentProfileName,IsRegistered,Enabled"
    st, hd, users = req(host, "GET", f"/xapi/v1/Users?$select={sel}&$expand=ForwardingProfiles($select=Id,Name)&$top=100", headers=auth)
    rows = users.get("value", []) if isinstance(users, dict) else []
    w("users.json", {"status": st, "count": len(rows), "value": rows, "error": None if rows else str(users)[:500]})
    rep.append(f"3. GET /Users ($top=100): HTTP {st}; {len(rows)} users")
    test = next((u for u in rows if str(u.get("Number")) == str(env["TEST_DN"])), None)
    if not test:
        stf, hdf, one = req(host, "GET", f"/xapi/v1/Users?$filter=Number eq '{env['TEST_DN']}'&$select={sel}&$expand=ForwardingProfiles($select=Id,Name)", headers=auth)
        frows = one.get("value", []) if isinstance(one, dict) else []
        rep.append(f"   $filter=Number eq '{env['TEST_DN']}': HTTP {stf}; {len(frows)} match")
        test = frows[0] if frows else None
    if not test:
        rep.append(f"   TEST_DN {env['TEST_DN']} not found among returned users; skipping 4-5")
    else:
        uid = test["Id"]
        st, hd, before = req(host, "GET", f"/xapi/v1/Users({uid})?$select={sel}&$expand=ForwardingProfiles($select=Id,Name)", headers=auth)
        w("user_before.json", {"status": st, "user": before})
        cur = before.get("CurrentProfileName") if isinstance(before, dict) else None
        profiles = [p.get("Name") for p in (before.get("ForwardingProfiles") or [])] if isinstance(before, dict) else []
        other = next((p for p in profiles if p and p != cur), None)
        rep.append(f"4. test user {env['TEST_DN']}: HTTP {st}; CurrentProfileName={cur!r}; profiles={profiles}")
        if other:
            st1, hd1, r1 = req(host, "PATCH", f"/xapi/v1/Users({uid})", {"CurrentProfileName": other}, auth)
            st2, hd2, mid = req(host, "GET", f"/xapi/v1/Users({uid})?$select=CurrentProfileName", headers=auth)
            st3, hd3, r3 = req(host, "PATCH", f"/xapi/v1/Users({uid})", {"CurrentProfileName": cur}, auth)
            st4, hd4, after = req(host, "GET", f"/xapi/v1/Users({uid})?$select=CurrentProfileName", headers=auth)
            midv = mid.get("CurrentProfileName") if isinstance(mid, dict) else None
            aftv = after.get("CurrentProfileName") if isinstance(after, dict) else None
            w("patch.json", {"set_to": other, "patch1": [st1, str(r1)[:300]], "read_mid": [st2, midv], "patch_back": [st3, str(r3)[:300]], "read_after": [st4, aftv]})
            verdict = "WRITABLE" if (st1 in (200, 204) and midv == other) else "NOT WRITABLE / REJECTED"
            restored = "restored" if aftv == cur else f"NOT RESTORED (now {aftv!r}, was {cur!r}) — FIX BY HAND"
            rep.append(f"5. PATCH CurrentProfileName -> {other!r}: HTTP {st1}; read back {midv!r} => {verdict}; back to {cur!r}: HTTP {st3}; {restored}")
        else:
            rep.append("5. PATCH skipped: no second profile name to switch to")

    # 6. callcontrol DNs
    st, hd, cc = req(host, "GET", "/callcontrol", headers=auth)
    w("callcontrol_dns.json", {"status": st, "body": cc})
    dns = [d.get("dn") for d in cc] if isinstance(cc, list) else []
    rep.append(f"6. GET /callcontrol: HTTP {st}; DNs visible to the SP: {dns if dns else str(cc)[:200]}")

    # 7. websocket listen
    frames = []
    try:
        ctx = ssl.create_default_context()
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        s = ctx.wrap_socket(socket.create_connection((host, 443), timeout=10), server_hostname=host)
        key = base64.b64encode(os.urandom(16)).decode()
        hs = (f"GET /callcontrol/ws HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
              f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\nAuthorization: Bearer {token}\r\n\r\n")
        s.sendall(hs.encode())
        resp = b""
        while b"\r\n\r\n" not in resp:
            chunk = s.recv(4096)
            if not chunk: break
            resp += chunk
        status_line = resp.split(b"\r\n", 1)[0].decode("utf-8", "replace")
        rep.append(f"7. WS handshake: {status_line}")
        if " 101 " in status_line:
            s.settimeout(1.0)
            end = time.time() + LISTEN_S
            buf = resp.split(b"\r\n\r\n", 1)[1]
            while time.time() < end:
                try:
                    chunk = s.recv(65536)
                    if not chunk: break
                    buf += chunk
                except socket.timeout:
                    continue
                while len(buf) >= 2:
                    b0, b1 = buf[0], buf[1]
                    op = b0 & 0x0F; ln = b1 & 0x7F; i = 2
                    if ln == 126: ln = int.from_bytes(buf[2:4], "big"); i = 4
                    elif ln == 127: ln = int.from_bytes(buf[2:10], "big"); i = 10
                    if len(buf) < i + ln: break
                    payload = buf[i:i+ln]; buf = buf[i+ln:]
                    if op == 0x9:  # ping -> pong (masked)
                        m = os.urandom(4); s.sendall(bytes([0x8A, 0x80 | len(payload)]) + m + bytes(b ^ m[j % 4] for j, b in enumerate(payload)))
                    elif op in (0x1, 0x2):
                        frames.append({"t": round(time.time(), 3), "op": op, "text": payload.decode("utf-8", "replace")[:4000]})
                    elif op == 0x8:
                        frames.append({"t": round(time.time(), 3), "op": "close"}); end = 0
            s.close()
        rep.append(f"   frames received in {LISTEN_S}s: {len(frames)} (shapes in ws_events.jsonl)")
    except Exception as e:
        rep.append(f"7. WS: EXC {type(e).__name__}: {e}")
    with open(os.path.join(out, "ws_events.jsonl"), "w", encoding="utf-8") as f:
        for fr in frames: f.write(json.dumps(fr) + "\n")

    w("report.md", "\n".join(rep))
    print("\n".join(rep))

if __name__ == "__main__":
    main()
