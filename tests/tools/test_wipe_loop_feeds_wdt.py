"""#993: the factory reset's SD sweeps run on sip_server_task (5 s task
watchdog) since #992, so every readdir loop in the two archive wipes must feed
the watchdog once per entry via resetguard::sweepTick(). Those loops are
ESP-only (PD_ETH_HAS_SD), so no host test can run them; this pins the call."""
import os
import re
import unittest

SRC_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "src", "SIP")
FILES = ["CdrArchive.cpp", "VoicemailArchive.cpp"]
READDIR = re.compile(r"\bwhile\s*\(.*::readdir\s*\(")
FEED = "resetguard::sweepTick()"


def loop_body(lines, start):
    """Text of the brace-delimited block that follows lines[start]."""
    depth = 0
    seen_open = False
    body = []
    for line in lines[start:]:
        code = line.split("//")[0]
        body.append(code)
        for ch in code:
            if ch == "{":
                depth += 1
                seen_open = True
            elif ch == "}":
                depth -= 1
        if seen_open and depth == 0:
            return "\n".join(body)
    return "\n".join(body)


class WipeLoopFeedsWdtTest(unittest.TestCase):
    def test_every_readdir_loop_feeds_the_watchdog(self):
        found = 0
        for name in FILES:
            path = os.path.join(SRC_DIR, name)
            lines = open(path, encoding="utf-8").read().split("\n")
            for i, line in enumerate(lines):
                if not READDIR.search(line.split("//")[0]):
                    continue
                found += 1
                self.assertIn(FEED, loop_body(lines, i),
                              "%s:%d readdir loop does not feed the watchdog" % (name, i + 1))
        self.assertEqual(found, 3, "expected 3 readdir loops (1 CDR, 2 voicemail); the pattern is stale")


if __name__ == "__main__":
    unittest.main()
