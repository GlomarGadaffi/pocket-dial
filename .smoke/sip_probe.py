#!/usr/bin/env python3
"""Pocket-Dial SIP smoke probe.

Sends a SIP REGISTER (and OPTIONS as a fallback) over UDP to a target
PBX and reports any response. Pure stdlib — no deps.

Usage:
    python sip_probe.py <ip> [port]      # default port 5060

Exit code 0 if any SIP response is received, 1 otherwise.
A received status line (e.g. "SIP/2.0 200 OK", "401 Unauthorized",
"403 Forbidden") all count as "the stack is alive and parsing".
"""
import socket
import sys
import time

def build_register(local_ip, target_ip, port, ext="9001"):
    branch = "z9hG4bK-smoke-%d" % int(time.time())
    call_id = "smoke-%d@%s" % (int(time.time()), local_ip)
    return (
        "REGISTER sip:%s SIP/2.0\r\n"
        "Via: SIP/2.0/UDP %s:5061;branch=%s\r\n"
        "Max-Forwards: 70\r\n"
        "From: <sip:%s@%s>;tag=smoke%d\r\n"
        "To: <sip:%s@%s>\r\n"
        "Call-ID: %s\r\n"
        "CSeq: 1 REGISTER\r\n"
        "Contact: <sip:%s@%s:5061>\r\n"
        "Expires: 60\r\n"
        "Content-Length: 0\r\n\r\n"
        % (target_ip, local_ip, branch, ext, target_ip, int(time.time()),
           ext, target_ip, call_id, ext, local_ip)
    ).encode()

def build_options(local_ip, target_ip, port):
    branch = "z9hG4bK-opt-%d" % int(time.time())
    call_id = "opt-%d@%s" % (int(time.time()), local_ip)
    return (
        "OPTIONS sip:%s SIP/2.0\r\n"
        "Via: SIP/2.0/UDP %s:5061;branch=%s\r\n"
        "Max-Forwards: 70\r\n"
        "From: <sip:smoke@%s>;tag=opt%d\r\n"
        "To: <sip:%s>\r\n"
        "Call-ID: %s\r\n"
        "CSeq: 1 OPTIONS\r\n"
        "Content-Length: 0\r\n\r\n"
        % (target_ip, local_ip, branch, local_ip, int(time.time()),
           target_ip, call_id)
    ).encode()

def local_ip_for(target_ip):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((target_ip, 5060))
        return s.getsockname()[0]
    except OSError:
        # No route: never fall back to the wildcard address (it would bind every
        # interface). Loopback keeps the probe running; the send then fails and
        # is reported as a socket error, same as any unreachable target.
        return "127.0.0.1"
    finally:
        s.close()

def probe(target_ip, port):
    local_ip = local_ip_for(target_ip)
    print("[probe] local %s -> target %s:%d" % (local_ip, target_ip, port))
    for name, builder in (("REGISTER", build_register), ("OPTIONS", build_options)):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(3.0)
        try:
            sock.bind((local_ip, 5061))
        except OSError:
            sock.bind((local_ip, 0))   # 5061 busy: same interface, any free port
        msg = builder(local_ip, target_ip, port) if name == "REGISTER" \
            else build_options(local_ip, target_ip, port)
        try:
            sock.sendto(msg, (target_ip, port))
            print("[probe] sent %s (%d bytes)" % (name, len(msg)))
            data, addr = sock.recvfrom(4096)
            first = data.split(b"\r\n", 1)[0].decode(errors="replace")
            print("[probe] RESPONSE to %s from %s: %s" % (name, addr, first))
            print("------ full response ------")
            print(data.decode(errors="replace"))
            return True
        except socket.timeout:
            print("[probe] %s: no response within 3s" % name)
        except OSError as e:
            print("[probe] %s: socket error %s" % (name, e))
        finally:
            sock.close()
    return False

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(2)
    ip = sys.argv[1]
    pt = int(sys.argv[2]) if len(sys.argv) > 2 else 5060
    ok = probe(ip, pt)
    print("[probe] RESULT:", "ALIVE" if ok else "NO RESPONSE")
    sys.exit(0 if ok else 1)
