#!/usr/bin/env python3
"""Headless-Chrome walk of the pocket-dial web UI over the DevTools protocol. stdlib only; run with -I.

usage: python -I pd_shots.py http://127.0.0.1:8080 OUTDIR [--setup] [--width 1280] [--height 900]
  --setup : if the box reports needsSetup, complete it with the factory login and a throwaway password
            (host/desktop test binary only; the password is never printed)
Produces OUTDIR/<nn>-<section>.png, OUTDIR/console.jsonl (exceptions + console errors), OUTDIR/walk.md.
"""
import sys, os, json, time, subprocess, http.client, urllib.parse, socket, base64, struct, tempfile, shutil, secrets

CHROME = r"C:\Program Files\Google\Chrome\Application\chrome.exe"
SECTIONS = ["overview", "extensions", "devices", "trunks-numbers", "routing", "call-handling", "audio", "security", "maintenance", "console"]

def http_json(base, method, path, body=None, headers=None, cookie=None):
    u = urllib.parse.urlparse(base)
    c = http.client.HTTPConnection(u.hostname, u.port or 80, timeout=10)
    h = {"Accept": "application/json"}
    if body is not None:
        h["Content-Type"] = "application/x-www-form-urlencoded"
    if headers: h.update(headers)
    if cookie: h["Cookie"] = cookie
    c.request(method, path, body=body, headers=h)
    r = c.getresponse(); raw = r.read(); c.close()
    setc = r.getheader("Set-Cookie")
    try: j = json.loads(raw.decode("utf-8", "replace"))
    except Exception: j = raw.decode("utf-8", "replace")[:300]
    return r.status, j, setc

def login(base, do_setup):
    st, j, setc = http_json(base, "POST", "/api/admin/login", "username=admin&password=admin")
    cookie = setc.split(";", 1)[0] if setc else None
    note = [f"login admin/admin -> {st} needsSetup={j.get('needsSetup') if isinstance(j, dict) else '?'} role={j.get('role') if isinstance(j, dict) else '?'}"]
    if isinstance(j, dict) and j.get("needsSetup") and do_setup:
        pw = "T" + secrets.token_hex(12) + "a!"
        st2, j2, _ = http_json(base, "POST", "/api/admin/set-credential", "username=admin&password=" + urllib.parse.quote(pw), {"X-CSRF": j.get("csrf", "")}, cookie)
        note.append(f"set-credential -> {st2} {j2 if isinstance(j2, dict) else ''}")
        st3, j3, setc3 = http_json(base, "POST", "/api/admin/login", "username=admin&password=" + urllib.parse.quote(pw))
        if setc3: cookie = setc3.split(";", 1)[0]
        note.append(f"re-login -> {st3} role={j3.get('role') if isinstance(j3, dict) else '?'}")
    return cookie, note

# --- minimal CDP client -------------------------------------------------------------------------
class CDP:
    def __init__(self, wsurl):
        u = urllib.parse.urlparse(wsurl)
        self.s = socket.create_connection((u.hostname, u.port), timeout=30)
        key = base64.b64encode(os.urandom(16)).decode()
        self.s.sendall((f"GET {u.path} HTTP/1.1\r\nHost: {u.hostname}:{u.port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                        f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n").encode())
        buf = b""
        while b"\r\n\r\n" not in buf: buf += self.s.recv(4096)
        self.buf = buf.split(b"\r\n\r\n", 1)[1]; self.id = 0; self.events = []
    def send(self, method, params=None):
        self.id += 1; mid = self.id
        data = json.dumps({"id": mid, "method": method, "params": params or {}}).encode()
        mask = os.urandom(4); hdr = bytearray([0x81])
        n = len(data)
        if n < 126: hdr.append(0x80 | n)
        elif n < 65536: hdr += bytes([0x80 | 126]) + struct.pack(">H", n)
        else: hdr += bytes([0x80 | 127]) + struct.pack(">Q", n)
        self.s.sendall(bytes(hdr) + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(data)))
        return self.wait(mid)
    def _frame(self):
        while True:
            if len(self.buf) >= 2:
                b0, b1 = self.buf[0], self.buf[1]; op = b0 & 0x0F; ln = b1 & 0x7F; i = 2
                if ln == 126: ln = struct.unpack(">H", self.buf[2:4])[0]; i = 4
                elif ln == 127: ln = struct.unpack(">Q", self.buf[2:10])[0]; i = 10
                if len(self.buf) >= i + ln:
                    payload = self.buf[i:i+ln]; self.buf = self.buf[i+ln:]
                    if op == 0x1: return json.loads(payload.decode("utf-8", "replace"))
                    if op == 0x9:
                        m = os.urandom(4); self.s.sendall(bytes([0x8A, 0x80 | len(payload)]) + m + bytes(b ^ m[j % 4] for j, b in enumerate(payload)))
                    continue
            chunk = self.s.recv(1 << 16)
            if not chunk: raise RuntimeError("cdp socket closed")
            self.buf += chunk
    def wait(self, mid):
        while True:
            msg = self._frame()
            if msg.get("id") == mid: return msg.get("result", msg)
            if "method" in msg: self.events.append(msg)
    def pump(self, seconds):
        end = time.time() + seconds; self.s.settimeout(0.2)
        while time.time() < end:
            try:
                msg = self._frame()
                if "method" in msg: self.events.append(msg)
            except socket.timeout: pass
            except Exception: break
        self.s.settimeout(30)

def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")   # status glyphs (◆ ▲ ■ ·) on a cp1252 console
    except Exception:
        pass
    base = sys.argv[1].rstrip("/"); out = sys.argv[2]; os.makedirs(out, exist_ok=True)
    do_setup = "--setup" in sys.argv
    width = int(sys.argv[sys.argv.index("--width") + 1]) if "--width" in sys.argv else 1280
    height = int(sys.argv[sys.argv.index("--height") + 1]) if "--height" in sys.argv else 900
    cookie, notes = login(base, do_setup)
    prof = tempfile.mkdtemp(prefix="pdshots-")
    port = 9333
    proc = subprocess.Popen([CHROME, "--headless=new", "--disable-gpu", "--no-first-run", "--no-default-browser-check", "--disable-extensions",
                             f"--remote-debugging-port={port}", f"--user-data-dir={prof}", f"--window-size={width},{height}", "about:blank"],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        ws = None
        for _ in range(50):
            try:
                c = http.client.HTTPConnection("127.0.0.1", port, timeout=2); c.request("GET", "/json"); tabs = json.loads(c.getresponse().read()); c.close()
                page = next(t for t in tabs if t.get("type") == "page"); ws = page["webSocketDebuggerUrl"]; break
            except Exception: time.sleep(0.2)
        if not ws: raise RuntimeError("no devtools target")
        cdp = CDP(ws)
        cdp.send("Runtime.enable"); cdp.send("Log.enable"); cdp.send("Page.enable"); cdp.send("Network.enable")
        cdp.send("Emulation.setDeviceMetricsOverride", {"width": width, "height": height, "deviceScaleFactor": 1, "mobile": width < 600})
        u = urllib.parse.urlparse(base)
        if cookie:
            name, value = cookie.split("=", 1)
            cdp.send("Network.setCookie", {"name": name, "value": value, "domain": u.hostname, "path": "/"})
        walk = [f"# pocket-dial walk — {base} — {time.strftime('%Y-%m-%d %H:%M:%S')} — {width}x{height}", "", *notes, ""]
        for n, sec in enumerate(SECTIONS, 1):
            cdp.send("Page.navigate", {"url": f"{base}/#{sec}"}); cdp.pump(2.5)
            info = cdp.send("Runtime.evaluate", {"expression": """(()=>{const b=document.documentElement.getAttribute('data-booted');const s=document.getElementById('sec-%s');const h=s?!s.hidden:null;const cur=document.querySelector('[aria-current]');const al=document.querySelector('.alarm-bar');return JSON.stringify({booted:b,sectionPresent:!!s,sectionShown:h,current:cur?cur.textContent.trim().slice(0,40):null,alarm:al?al.textContent.trim().slice(0,80):null,title:document.title,scrollW:document.documentElement.scrollWidth,innerW:innerWidth,tiles:[...document.querySelectorAll('.annunciator .tile')].map(t=>(t.hidden?'[hidden]':'')+t.id+'='+t.textContent.trim().replace(/\\s+/g,' '))})})()""" % sec, "returnByValue": True})
            val = info.get("result", {}).get("value", "{}")
            shot = cdp.send("Page.captureScreenshot", {"format": "png"})
            with open(os.path.join(out, f"{n:02d}-{sec}.png"), "wb") as f: f.write(base64.b64decode(shot["data"]))
            walk.append(f"{n:02d} {sec}: {val}")
        errs = [e for e in cdp.events if e["method"] in ("Runtime.exceptionThrown",) or (e["method"] == "Log.entryAdded" and e["params"]["entry"].get("level") == "error") or (e["method"] == "Runtime.consoleAPICalled" and e["params"].get("type") == "error")]
        with open(os.path.join(out, "console.jsonl"), "w", encoding="utf-8") as f:
            for e in errs: f.write(json.dumps(e)[:2000] + "\n")
        walk += ["", f"console errors/exceptions: {len(errs)}"]
        for e in errs[:10]:
            d = e["params"]; txt = d.get("exceptionDetails", {}).get("exception", {}).get("description") or d.get("entry", {}).get("text") or json.dumps(d.get("args", []))[:200]
            walk.append("  - " + str(txt)[:300].replace("\n", " "))
        with open(os.path.join(out, "walk.md"), "w", encoding="utf-8") as f: f.write("\n".join(walk))
        print("\n".join(walk))
    finally:
        proc.terminate()
        try: proc.wait(5)
        except Exception: proc.kill()
        shutil.rmtree(prof, ignore_errors=True)

if __name__ == "__main__":
    main()
