#!/usr/bin/env python3
"""Policy for tools/soak/rig_checkout.sh (#401 release harness, item 0.3).

The shell script owns the locks and runs the commands. Every decision lives
here, where it can be unit-tested:

  window START END [--tz TZ]      exit 1 if [START, END] crosses glolab's 03:30
                                  auto-reboot (03:25-03:45 local, #451 S-rows)
  epoch ISO                       print an ISO-8601 time (with a zone) as epoch seconds
  ssh-check [--flash-step] [--abort-path] -- ARGV...
                                  exit 1 unless ARGV may run on glolab (allowlist)
  redact [--secrets-file F]       stdin -> stdout with secrets masked
  scan FILE... [--secrets-file F] exit 1 if any FILE holds a secret (fail closed;
                                  prints where, never the secret itself)
  checkout-text / checkin-text    the #428 CHECK-OUT and CHECK-IN posts

stdlib only.
"""
import argparse
import datetime
import os
import re
import sys

try:
    from zoneinfo import ZoneInfo
except ImportError:  # Python < 3.9
    ZoneInfo = None

REBOOT_WINDOW = ((3, 25), (3, 45))     # glolab reboots itself at 03:30 local

# What may run on glolab through the wrapper. Scripts match by basename, so a
# checkout under ~/ota or ~/pd both work. Extend here, never by editing argv.
ALLOWED_PROGRAMS = {
    "status_logger.sh", "remote_ota.sh", "rig_checkout.sh",
    "curl", "sha256sum", "ls", "cat", "mkdir", "tar", "gzip", "kill", "pgrep",
    "date", "uptime", "true", "test",
    "esptool", "esptool.py",            # --flash-step only
    "uhubctl",                          # --abort-path only
}
ALLOWED_PY_SCRIPTS = {"sip_stress.py", "soak_verdict.py"}
CURL_WRITES = {"-X", "--request", "-d", "--data", "--data-binary", "--data-raw",
               "--data-urlencode", "-F", "--form", "-T", "--upload-file"}
EMERGENCY = ("911", "933", "112")
IPV4 = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")

SECRET_PATTERNS = [
    ("auth header", re.compile(r"(?i)\b(authorization|proxy-authorization|cookie|set-cookie|x-csrf)"
                               r"(\s*:\s*)[^\r\n]*"), lambda m: m.group(1) + m.group(2) + "***"),
    ("key=value secret", re.compile(r"(?i)\b(password|passwd|pass|secret|token|pd_ota_pass|"
                                    r"pd_ota_user|api_?key)(\s*=\s*)[^\s&;,\"']+"),
     lambda m: m.group(1) + m.group(2) + "***"),
    ("json secret", re.compile(r"(?i)\"(password|passwd|secret|token|csrf|api_?key|ha1)\""
                               r"(\s*:\s*)\"[^\"]*\""), lambda m: '"%s"%s"***"' % (m.group(1), m.group(2))),
    ("github token", re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b"),
     lambda m: "***"),
    ("url credentials", re.compile(r"(?<=://)[^/\s:@]+:[^/\s@]+@"), lambda m: "***@"),
    ("phone number in a URI", re.compile(r"(?i)\b(sips?|tel):\+?[0-9]{7,15}"),
     lambda m: m.group(1) + ":***"),
    ("E.164 number", re.compile(r"\+[0-9]{10,15}\b"), lambda m: "+***"),
    ("private key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), lambda m: "***PRIVATE KEY***"),
]


# ---------------------------------------------------------------- time
def _zone(tz):
    if not tz:
        return None
    if ZoneInfo is None:
        raise SystemExit("rig_policy: --tz needs Python 3.9+ (zoneinfo)")
    return ZoneInfo(tz)


def fmt(epoch, tz=None):
    zone = _zone(tz)
    if zone is None:
        return datetime.datetime.fromtimestamp(epoch).strftime("%Y-%m-%d %H:%M local")
    return datetime.datetime.fromtimestamp(epoch, zone).strftime("%Y-%m-%d %H:%M %Z")


def utc(epoch):
    return datetime.datetime.fromtimestamp(epoch, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%MZ")


def reboot_conflict(start, end, tz=None):
    """A reason the window [start, end] crosses glolab's 03:30 reboot, or None."""
    zone = _zone(tz)
    day = datetime.datetime.fromtimestamp(start, zone).date() - datetime.timedelta(days=1)
    last = datetime.datetime.fromtimestamp(end, zone).date() + datetime.timedelta(days=1)
    (h0, m0), (h1, m1) = REBOOT_WINDOW
    while day <= last:
        ws = datetime.datetime(day.year, day.month, day.day, h0, m0, tzinfo=zone).timestamp()
        we = datetime.datetime(day.year, day.month, day.day, h1, m1, tzinfo=zone).timestamp()
        if start < we and end > ws:
            return ("the window %s - %s crosses glolab's 03:30 auto-reboot (%s %02d:%02d-%02d:%02d "
                    "glolab time): end before %02d:%02d or start after %02d:%02d"
                    % (fmt(start, tz), fmt(end, tz), day, h0, m0, h1, m1, h0, m0, h1, m1))
        day += datetime.timedelta(days=1)
    return None


def parse_iso(text):
    s = (text or "").strip()
    if s[-1:] in ("Z", "z"):
        s = s[:-1] + "+00:00"
    try:
        dt = datetime.datetime.fromisoformat(s)
    except ValueError:
        return None
    return None if dt.tzinfo is None else int(dt.timestamp())


# ---------------------------------------------------------------- ssh allowlist
def _emergency_in(arg):
    for run in re.findall(r"[0-9]+", IPV4.sub(" ", arg)):
        if run in EMERGENCY or (len(run) in (4, 5) and run[-3:] in ("911", "933")):
            return True
    return False


def ssh_problems(argv, flash_step=False, abort_path=False):
    """Every reason ARGV may not run on glolab, or []."""
    if not argv:
        return ["no remote command"]
    problems = []
    prog = argv[0]
    base = os.path.basename(prog)
    if base in ("python3", "python"):
        script = os.path.basename(argv[1]) if len(argv) > 1 else ""
        if script not in ALLOWED_PY_SCRIPTS:
            problems.append("python3 %s is not on the allowlist (%s)"
                            % (script or "<nothing>", ", ".join(sorted(ALLOWED_PY_SCRIPTS))))
    elif base not in ALLOWED_PROGRAMS:
        problems.append("%s is not on the glolab allowlist" % prog)
    esptool = base.startswith("esptool")
    serial = any("/dev/tty" in a or "/dev/serial" in a for a in argv)
    if esptool and not flash_step:
        problems.append("esptool runs only inside a flash step (--flash-step)")
    if flash_step and not esptool:
        problems.append("--flash-step is for esptool only")
    if esptool and flash_step and not any(a == "--after" and b == "no_reset"
                                          for a, b in zip(argv, argv[1:])) \
            and "--after=no_reset" not in argv:
        problems.append("a flash step must pass --after no_reset (#338: parks the chip in the ROM loader)")
    if serial and not (flash_step and esptool):
        problems.append("a serial port is opened only by esptool in a flash step "
                        "(opening it resets the board)")
    if base == "uhubctl" and not abort_path:
        problems.append("uhubctl runs only in the abort path (--abort-path)")
    if abort_path and base != "uhubctl":
        problems.append("--abort-path is for uhubctl only")
    if base == "curl" and any(a in CURL_WRITES or a.startswith("--data") for a in argv[1:]):
        problems.append("curl through the wrapper is read-only (no -X, -d, -F, -T)")
    if any(_emergency_in(a) for a in argv):
        problems.append("an argument names an emergency number (911/933/112): refused")
    return problems


# ---------------------------------------------------------------- secrets
def literal_secrets(path):
    """Literal secrets to mask, one per line. A configured file that cannot be
    read is an error (fail closed), never 'no secrets'."""
    if not path:
        return []
    with open(path, encoding="utf-8") as f:
        return sorted({ln.strip() for ln in f if len(ln.strip()) >= 4}, key=len, reverse=True)


def redact(text, literals=()):
    for lit in literals:
        text = text.replace(lit, "***")
    for _, rx, sub in SECRET_PATTERNS:
        text = rx.sub(sub, text)
    return text


def find_secrets(text, literals=()):
    """[(line number, kind)] -- never the secret itself."""
    found = []
    for n, line in enumerate(text.splitlines(), 1):
        for lit in literals:
            if lit in line:
                found.append((n, "a literal from the secrets file"))
        for kind, rx, _ in SECRET_PATTERNS:
            for m in rx.finditer(line):
                if redact(m.group(0)) != m.group(0):      # an already-masked value is not a hit
                    found.append((n, kind))
    return found


# ---------------------------------------------------------------- posts
def checkout_text(holder, purpose, resources, start, end, tz=None):
    return ("**CHECK-OUT** %s by **%s**\n\n"
            "- purpose: %s\n"
            "- from %s until **%s** (expiry; glolab time %s)\n"
            "- clear of glolab's 03:30 auto-reboot (03:25-03:45 glolab time)\n"
            "- a CHECK-IN with the verdict follows when the run ends, also on an abort\n"
            % (", ".join("`%s`" % r for r in resources), holder, purpose, utc(start), utc(end),
               fmt(end, tz)))


def checkin_text(holder, resources, start, now, verdict, evidence="", note=""):
    lines = ["**CHECK-IN** %s released by **%s**" % (", ".join("`%s`" % r for r in resources), holder),
             "",
             "- verdict: **%s**" % verdict,
             "- held %s to %s" % (utc(start) if start else "(no check-out on record)", utc(now))]
    if evidence:
        lines.append("- evidence: %s" % evidence)
    if note:
        lines.append("- note: %s" % note)
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------- CLI
def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    w = sub.add_parser("window")
    w.add_argument("start", type=int)
    w.add_argument("end", type=int)
    w.add_argument("--tz", default=None)
    e = sub.add_parser("epoch")
    e.add_argument("iso")
    s = sub.add_parser("ssh-check")
    s.add_argument("--flash-step", action="store_true")
    s.add_argument("--abort-path", action="store_true")
    s.add_argument("--secrets-file", default=None)
    s.add_argument("argv", nargs=argparse.REMAINDER)
    r = sub.add_parser("redact")
    r.add_argument("--secrets-file", default=None)
    c = sub.add_parser("scan")
    c.add_argument("files", nargs="+")
    c.add_argument("--secrets-file", default=None)
    co = sub.add_parser("checkout-text")
    co.add_argument("--holder", required=True)
    co.add_argument("--purpose", required=True)
    co.add_argument("--resources", required=True)
    co.add_argument("--start", type=int, required=True)
    co.add_argument("--end", type=int, required=True)
    co.add_argument("--tz", default=None)
    ci = sub.add_parser("checkin-text")
    ci.add_argument("--holder", required=True)
    ci.add_argument("--resources", required=True)
    ci.add_argument("--start", type=int, default=0)
    ci.add_argument("--now", type=int, required=True)
    ci.add_argument("--verdict", required=True)
    ci.add_argument("--evidence", default="")
    ci.add_argument("--note", default="")
    a = ap.parse_args(argv)

    if a.cmd == "window":
        why = reboot_conflict(a.start, a.end, a.tz)
        if why:
            print("REFUSED: " + why, file=sys.stderr)
            return 1
        return 0
    if a.cmd == "epoch":
        t = parse_iso(a.iso)
        if t is None:
            print("REFUSED: %r is not ISO-8601 with a zone" % a.iso, file=sys.stderr)
            return 1
        print(t)
        return 0
    if a.cmd == "ssh-check":
        args = a.argv[1:] if a.argv[:1] == ["--"] else a.argv
        problems = ssh_problems(args, a.flash_step, a.abort_path)
        try:
            literals = literal_secrets(a.secrets_file)
        except OSError as err:
            literals = []
            problems.append("cannot read the secrets file (%s): failing closed" % err.strerror)
        if find_secrets("\n".join(args), literals):
            problems.append("an argument holds a secret: a credential never goes on an argv")
        for p in problems:
            print("REFUSED: " + p, file=sys.stderr)
        return 1 if problems else 0
    try:
        literals = literal_secrets(getattr(a, "secrets_file", None))
    except OSError as err:
        print("REFUSED: cannot read the secrets file (%s): failing closed" % err.strerror, file=sys.stderr)
        return 2
    if a.cmd == "redact":
        sys.stdout.write(redact(sys.stdin.read(), literals))
        return 0
    if a.cmd == "scan":
        bad = 0
        for path in a.files:
            try:
                with open(path, encoding="utf-8", errors="replace") as f:
                    hits = find_secrets(f.read(), literals)
            except OSError as err:
                print("REFUSED: cannot read %s (%s): failing closed" % (path, err.strerror), file=sys.stderr)
                return 2
            for n, kind in hits:
                print("SECRET: %s:%d: %s" % (path, n, kind), file=sys.stderr)
            bad += len(hits)
        return 1 if bad else 0
    if a.cmd == "checkout-text":
        sys.stdout.write(checkout_text(a.holder, a.purpose, a.resources.split(","), a.start, a.end, a.tz))
        return 0
    if a.cmd == "checkin-text":
        sys.stdout.write(checkin_text(a.holder, a.resources.split(","), a.start, a.now, a.verdict,
                                      a.evidence, a.note))
        return 0
    return 2


if __name__ == "__main__":
    sys.exit(main())
