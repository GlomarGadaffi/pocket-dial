#!/usr/bin/env python3
"""Peak concurrent /api requests the page holds open while it loads, per section. stdlib only; run with -I.

usage: python -I pd_inflight_check.py http://127.0.0.1:8080 [--setup]

The board serves 3 connections and refuses a source that holds more than 2 (HttpServer
kMaxConnectionsPerSource, #529), so the page must never have more than 2 requests in flight.
Exit 1 if any section peaks above 2 or any response is a 503.
--setup completes first-time setup on a host/desktop binary with a throwaway password (see pd_shots.py).
"""
import sys, os, json, time, http.client, urllib.parse, subprocess, tempfile, shutil
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pd_shots as P

SECTIONS = ["overview", "extensions", "trunks-numbers", "routing", "security", "maintenance", "console"]


def main():
    base = sys.argv[1].rstrip("/")
    cookie, _ = P.login(base, "--setup" in sys.argv)
    prof = tempfile.mkdtemp(prefix="pdinflight-")
    port = 9337
    proc = subprocess.Popen([P.CHROME, "--headless=new", "--disable-gpu", "--no-first-run", "--disable-extensions",
                             f"--remote-debugging-port={port}", f"--user-data-dir={prof}", "--window-size=1280,900", "about:blank"],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        ws = None
        for _ in range(50):
            try:
                c = http.client.HTTPConnection("127.0.0.1", port, timeout=2); c.request("GET", "/json")
                tabs = json.loads(c.getresponse().read()); c.close()
                ws = next(t for t in tabs if t.get("type") == "page")["webSocketDebuggerUrl"]; break
            except Exception:
                time.sleep(0.2)
        if not ws:
            raise RuntimeError("no devtools target")
        cdp = P.CDP(ws)
        for m in ("Runtime.enable", "Page.enable", "Network.enable"):
            cdp.send(m)
        u = urllib.parse.urlparse(base)
        if cookie:
            name, value = cookie.split("=", 1)
            cdp.send("Network.setCookie", {"name": name, "value": value, "domain": u.hostname, "path": "/"})
        cdp.send("Network.setCacheDisabled", {"cacheDisabled": True})
        worst = 0
        statuses = {}
        for sec in SECTIONS:
            cdp.send("Page.navigate", {"url": "about:blank"}); cdp.pump(0.5)
            cdp.events.clear()
            cdp.send("Page.navigate", {"url": base + "/?v=" + sec + "#" + sec}); cdp.pump(5.0)
            live = {}; peak = 0
            for e in cdp.events:
                m = e["method"]; p = e["params"]
                if m == "Network.requestWillBeSent" and "/api/" in p["request"]["url"]:
                    live[p["requestId"]] = p["request"]["url"].split("/api/")[1][:24]
                    peak = max(peak, len(live))
                elif m in ("Network.loadingFinished", "Network.loadingFailed"):
                    live.pop(p["requestId"], None)
                elif m == "Network.responseReceived" and "/api/" in p["response"]["url"]:
                    s = p["response"]["status"]; statuses[s] = statuses.get(s, 0) + 1
            worst = max(worst, peak)
            print(f"{sec}: peak in-flight /api requests = {peak}")
        ok = worst <= 2 and 503 not in statuses
        print("WORST", worst, "statuses", statuses)
        print("PASS" if ok else "FAIL")
        return 0 if ok else 1
    finally:
        proc.terminate()
        try:
            proc.wait(5)
        except Exception:
            proc.kill()
        shutil.rmtree(prof, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
