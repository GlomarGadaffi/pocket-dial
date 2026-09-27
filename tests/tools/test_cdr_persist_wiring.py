"""#476 review: pin the ESP-only wiring of CdrRing::persist(), which no host
test can reach. The predicate is host-tested; this checks persist() calls it
before enqueueing, and enqueues with xQueueOverwrite, never xQueueSend."""
import os
import re
import unittest

SRC = os.path.join(os.path.dirname(__file__), "..", "..", "src", "SIP", "CdrRing.cpp")


class CdrPersistWiringTest(unittest.TestCase):
    def test_persist_consults_the_predicate_before_overwriting(self):
        src = open(SRC, encoding="utf-8").read()
        m = re.search(r"void CdrRing::persist\(\)\s*\{(.*?)\n\}", src, re.S)
        self.assertIsNotNone(m, "CdrRing::persist() not found")
        body = re.sub(r"//[^\n]*", "", m.group(1))   # code only, not comments
        self.assertIn("persistAction(", body)
        self.assertIn("xQueueOverwrite(", body)
        self.assertLess(body.index("persistAction("), body.index("xQueueOverwrite("))
        self.assertNotIn("xQueueSend(", body)


if __name__ == "__main__":
    unittest.main()
