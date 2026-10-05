#!/usr/bin/env python3
"""
pocket-dial SIP load / stress tester  (stdlib-only, no deps)

Registers virtual SIP user-agents and places echo-test (777) calls against a
pocket-dial registrar, measuring registration + call-setup latency, throughput,
and the static-pool / rate-limit ceilings. Also samples the HTTP /api/status
endpoint for server-side packet & pool counters.

NOTE: pocket-dial rate-limits per SOURCE IP (token bucket, ~40 burst / 20 pkt/s
sustained, Issue #38 -- keyed purely on the IPv4 address, `RequestsHandler::
allowPacket`'s `_rateBuckets` map is `unordered_map<uint32_t, RateBucket>` with
no port in the key). Every virtual UA here defaults to one shared source IP
(whatever the OS picks for the route to --host), so a single default run cannot
exceed that budget no matter how many UAs you spin up -- that is by design (DoS
protection), not a bug in this tool. Pace accordingly; the tool reports drops so
you can see the limiter engage.

Issue #79: to measure the registrar's ceiling *past* the per-IP limiter, drive
UAs from multiple distinct source IPs with --source-ips / --source-ip-base +
--source-ip-count (see --help). Because the bucket keys on address only (not
port), this is a real bypass, not a workaround for a weaker check -- any of the
following genuinely produce distinct buckets:
  * separate physical/VM hosts (the real target for a production capacity claim)
  * Linux network namespaces / extra interface addresses (`ip addr add`)
  * multiple secondary IPs bound on ONE host's loopback range -- e.g. Windows
    treats the entire 127.0.0.0/8 block as loopback with zero configuration
    (unlike Linux, which by default only brings up 127.0.0.1), so
    `--source-ip-base 127.0.0. --source-ip-count 40` works out of the box on a
    single Windows box for a same-host sanity run. This still shares one NIC,
    one kernel network stack, and one physical host with the process under
    test, so it is NOT a substitute for a real multi-host run when the question
    is production capacity under real network conditions -- see
    docs/SCALING.md for what was actually measured this
    way vs. what a real multi-host run still needs to confirm.

Usage:
  python sip_stress.py --host 192.168.12.159 --clients 30 --echo-calls 8
  python sip_stress.py --host pocketdial.local --register-only --clients 40
  # Bypass the per-IP limiter using 40 loopback-range source addresses:
  python sip_stress.py --host 127.0.0.1 --clients 40 --echo-calls 12 \\
      --source-ip-base 127.0.0. --source-ip-count 40 --hold-ms 300
  # Or an explicit list (real interface IPs / netns addresses for a real run):
  python sip_stress.py --host 10.0.0.1 --clients 4 --source-ips 10.0.1.1,10.0.1.2

Issue #401: `--profile <name>` runs a scheduled multi-scenario load instead
(registrations, 777 bursts, extension calls, 888, park + MoH) from the table in
load_profile.py; `--profile rc1 --dry-run ...` prints the plan and sends nothing.
See load_profile.py for its options and its safety refusals.

Issue #384: `--scenario <name>` runs one named anchor scenario (e.g.
x4_cancel_ringing) from anchor_scenarios.py, which holds its refusals.
"""
import argparse, socket, threading, time, random, re, statistics, sys, json
import urllib.request

def _hex(n): return ''.join(random.choice('0123456789abcdef') for _ in range(n))

def local_ip_for(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((host, port)); return s.getsockname()[0]
    except Exception:
        return '0.0.0.0'
    finally:
        s.close()

def resolve_source_ips(args, default_ip):
    """Returns the list of local source IPs to round-robin virtual UAs across.

    Explicit --source-ips wins; otherwise --source-ip-base/--source-ip-count
    auto-generates addresses (base + str(2), base + str(3), ... -- skipping
    '1' since that's commonly the host's own primary address); with neither,
    falls back to the single implicit `default_ip` (today's behavior,
    unchanged, so a plain run without these flags is bit-for-bit the same
    single-source test it always was).
    """
    if args.source_ips:
        return [ip.strip() for ip in args.source_ips.split(',') if ip.strip()]
    if args.source_ip_count > 0:
        return [f"{args.source_ip_base}{i + 2}" for i in range(args.source_ip_count)]
    return [default_ip]

class UA:
    """One virtual SIP user-agent on its own UDP port, optionally bound to a
    specific local source IP (Issue #79) so it draws from its own per-IP token
    bucket rather than sharing the OS-chosen default source address."""
    def __init__(self, ext, host, port, local_ip, timeout=4.0):
        self.ext, self.host, self.port, self.lip = ext, host, port, local_ip
        self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.s.bind((local_ip if local_ip != '0.0.0.0' else '', 0))
        self.s.settimeout(timeout)
        self.lport = self.s.getsockname()[1]
        self.callid = f"{_hex(16)}@{local_ip}"
        self.tag = _hex(8); self.cseq = 0

    def _via(self):
        return f"SIP/2.0/UDP {self.lip}:{self.lport};branch=z9hG4bK{_hex(10)};rport"

    @staticmethod
    def _status(resp):
        if not resp: return None
        m = re.match(r'SIP/2\.0 (\d{3})', resp)
        return int(m.group(1)) if m else None

    def _txn(self, msg, want_final=True):
        """Send, then read until a final (>=200) response or timeout. Returns (status, ms)."""
        t = time.time()
        try:
            self.s.sendto(msg.encode(), (self.host, self.port))
        except Exception:
            return (None, 0.0)
        st = None
        for _ in range(4):
            try:
                data, _a = self.s.recvfrom(8192)
            except socket.timeout:
                break
            st = self._status(data.decode('utf-8', 'replace'))
            if st and (st >= 200 or not want_final):
                break
        return (st, (time.time() - t) * 1000.0)

    def register(self, expires=3600):
        self.cseq += 1
        m = (f"REGISTER sip:{self.host} SIP/2.0\r\n"
             f"Via: {self._via()}\r\n"
             f"Max-Forwards: 70\r\n"
             f"From: \"{self.ext}\" <sip:{self.ext}@{self.host}>;tag={self.tag}\r\n"
             f"To: <sip:{self.ext}@{self.host}>\r\n"
             f"Call-ID: {self.callid}\r\n"
             f"CSeq: {self.cseq} REGISTER\r\n"
             f"Contact: <sip:{self.ext}@{self.lip}:{self.lport}>\r\n"
             f"Expires: {expires}\r\n"
             f"User-Agent: pd-stress\r\nContent-Length: 0\r\n\r\n")
        return self._txn(m)

    def _sdp(self):
        return (f"v=0\r\no={self.ext} 0 0 IN IP4 {self.lip}\r\ns=pd\r\n"
                f"c=IN IP4 {self.lip}\r\nt=0 0\r\n"
                f"m=audio {10000 + (self.lport % 5000)} RTP/AVP 0 8 101\r\n"
                f"a=rtpmap:0 PCMU/8000\r\na=rtpmap:8 PCMA/8000\r\n")

    def echo_call(self, hold_ms=0.0):
        """INVITE the 777 echo extension -> expect 200 -> ACK -> [hold] -> BYE.
        `hold_ms`, if >0, sleeps between ACK and BYE so this session actually
        occupies a Session-pool slot concurrently with other UAs' calls --
        without a hold, a fast localhost round trip completes and frees the
        slot before other threads' INVITEs even land, which would understate
        real concurrent-session pressure (Issue #79). Returns (setup_status, ms)."""
        self.cseq += 1
        cid = f"{_hex(16)}@{self.lip}"
        sdp = self._sdp()
        inv = (f"INVITE sip:777@{self.host} SIP/2.0\r\n"
               f"Via: {self._via()}\r\n"
               f"Max-Forwards: 70\r\n"
               f"From: \"{self.ext}\" <sip:{self.ext}@{self.host}>;tag={self.tag}\r\n"
               f"To: <sip:777@{self.host}>\r\n"
               f"Call-ID: {cid}\r\n"
               f"CSeq: {self.cseq} INVITE\r\n"
               f"Contact: <sip:{self.ext}@{self.lip}:{self.lport}>\r\n"
               f"Content-Type: application/sdp\r\n"
               f"Content-Length: {len(sdp)}\r\n\r\n{sdp}")
        st, ms = self._txn(inv)
        if st and 200 <= st < 300:
            self.cseq += 1
            ack = (f"ACK sip:777@{self.host} SIP/2.0\r\n"
                   f"Via: {self._via()}\r\nMax-Forwards: 70\r\n"
                   f"From: \"{self.ext}\" <sip:{self.ext}@{self.host}>;tag={self.tag}\r\n"
                   f"To: <sip:777@{self.host}>\r\nCall-ID: {cid}\r\n"
                   f"CSeq: {self.cseq - 1} ACK\r\nContent-Length: 0\r\n\r\n")
            try: self.s.sendto(ack.encode(), (self.host, self.port))
            except Exception: pass
            if hold_ms > 0: time.sleep(hold_ms / 1000.0)
            self.cseq += 1
            bye = (f"BYE sip:777@{self.host} SIP/2.0\r\n"
                   f"Via: {self._via()}\r\nMax-Forwards: 70\r\n"
                   f"From: \"{self.ext}\" <sip:{self.ext}@{self.host}>;tag={self.tag}\r\n"
                   f"To: <sip:777@{self.host}>\r\nCall-ID: {cid}\r\n"
                   f"CSeq: {self.cseq} BYE\r\nContent-Length: 0\r\n\r\n")
            self._txn(bye)
        return (st, ms)

    def close(self):
        try: self.s.close()
        except Exception: pass

def pct(xs, p):
    if not xs: return 0.0
    xs = sorted(xs); k = (len(xs) - 1) * p / 100.0
    f = int(k); c = min(f + 1, len(xs) - 1)
    return xs[f] + (xs[c] - xs[f]) * (k - f)

def summarize(name, lat, codes):
    ok = sum(1 for c in codes if c and 200 <= c < 300)
    print(f"\n  {name}: {len(codes)} attempts, {ok} ok ({100.0*ok/max(1,len(codes)):.0f}%)")
    from collections import Counter
    print("    status codes: " + ", ".join(f"{k}:{v}" for k, v in sorted(Counter(codes).items(), key=lambda x: str(x[0]))))
    if lat:
        print(f"    latency ms  min={min(lat):.1f} p50={pct(lat,50):.1f} p95={pct(lat,95):.1f} max={max(lat):.1f} mean={statistics.mean(lat):.1f}")

def api_status(host):
    try:
        with urllib.request.urlopen(f"http://{host}/api/status", timeout=3) as r:
            return json.loads(r.read().decode())
    except Exception as e:
        return {"_error": str(e)}

def main(argv=None):
    argv = sys.argv[1:] if argv is None else list(argv)
    if any(a == "--profile" or a.startswith("--profile=") for a in argv):
        # #401: a scheduled, multi-scenario load (load_profile.py). The legacy
        # options below are not used on that path.
        import load_profile
        return load_profile.main(argv)
    if any(a == "--scenario" or a.startswith("--scenario=") for a in argv):
        # #384: a named anchor scenario (anchor_scenarios.py), with its own refusals.
        import anchor_scenarios
        return anchor_scenarios.main(argv)
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="192.168.12.159")
    ap.add_argument("--port", type=int, default=5060)
    ap.add_argument("--clients", type=int, default=30)
    ap.add_argument("--echo-calls", type=int, default=8)
    ap.add_argument("--ext-base", type=int, default=1000)
    ap.add_argument("--register-only", action="store_true")
    ap.add_argument("--pace", type=float, default=0.0, help="seconds between launches (0 = full parallel)")
    ap.add_argument("--source-ips", default="",
                     help="Issue #79: comma-separated local IPs to round-robin UAs across, "
                          "bypassing the per-source-IP token bucket (Issue #38). For a real "
                          "measurement these should be genuinely distinct hosts/netns/interface "
                          "addresses -- see the module docstring.")
    ap.add_argument("--source-ip-base", default="127.0.0.",
                     help="Prefix used with --source-ip-count to auto-generate source IPs "
                          "(default targets Windows's unconfigured 127.0.0.0/8 loopback range).")
    ap.add_argument("--source-ip-count", type=int, default=0,
                     help="Auto-generate this many source IPs as <source-ip-base><2..N+1> "
                          "instead of the single default OS-chosen source address. 0 (default) "
                          "keeps the original single-source behavior.")
    ap.add_argument("--hold-ms", type=float, default=0.0,
                     help="Hold each echo call open this long between ACK and BYE, so "
                          "concurrent calls actually overlap in the Session pool instead of "
                          "each completing before the next INVITE lands (Issue #79).")
    args = ap.parse_args(argv)

    default_lip = local_ip_for(args.host, args.port)
    source_ips = resolve_source_ips(args, default_lip)
    print(f"pocket-dial SIP stress  ->  {args.host}:{args.port}")
    print(f"source IPs ({len(source_ips)}): {source_ips}")
    print(f"before: {api_status(args.host)}")

    uas = [UA(str(args.ext_base + i), args.host, args.port, source_ips[i % len(source_ips)])
           for i in range(args.clients)]

    # ---- Phase 1: registration storm ----
    reg_lat, reg_codes = [], []
    lock = threading.Lock()
    def do_reg(ua):
        st, ms = ua.register()
        with lock:
            reg_codes.append(st)
            if st: reg_lat.append(ms)
    t0 = time.time()
    threads = []
    for ua in uas:
        th = threading.Thread(target=do_reg, args=(ua,)); th.start(); threads.append(th)
        if args.pace: time.sleep(args.pace)
    for th in threads: th.join()
    reg_dur = time.time() - t0
    summarize("REGISTER storm", reg_lat, reg_codes)
    print(f"    throughput: {len(reg_codes)/max(1e-6,reg_dur):.1f} reg/s over {reg_dur:.2f}s")

    # ---- Phase 2: concurrent echo (777) calls ----
    if not args.register_only and args.echo_calls > 0:
        call_lat, call_codes = [], []
        def do_call(ua):
            st, ms = ua.echo_call(hold_ms=args.hold_ms)
            with lock:
                call_codes.append(st)
                if st: call_lat.append(ms)
        callers = uas[:args.echo_calls]
        t0 = time.time(); threads = []
        for ua in callers:
            th = threading.Thread(target=do_call, args=(ua,)); th.start(); threads.append(th)
            if args.pace: time.sleep(args.pace)
        for th in threads: th.join()
        call_dur = time.time() - t0
        summarize(f"ECHO calls (777) x{args.echo_calls} concurrent", call_lat, call_codes)
        print(f"    throughput: {len(call_codes)/max(1e-6,call_dur):.1f} calls/s over {call_dur:.2f}s")

    time.sleep(0.5)
    print(f"\nafter:  {api_status(args.host)}")
    for ua in uas: ua.close()

if __name__ == "__main__":
    sys.exit(main())
