"""#479 review: every raw task create in TelephonyAnchorClient.cpp must bump
psram::dynamicTaskCreates(), or be listed below with a reason. The anchor client
is ESP-only, so no host test can reach these creates; this pins the wiring."""
import os
import re
import unittest

SRC = os.path.join(os.path.dirname(__file__), "..", "..", "src", "SIP", "TelephonyAnchorClient.cpp")
CREATE = re.compile(r"\bxTaskCreate(?:PinnedToCore)?\s*\(")
COUNTED = "dynamicTaskCreates().fetch_add("
WINDOW = 12   # lines after the create call to find the increment
# task name -> why it is not counted
EXEMPT = {}


class AnchorTaskCreateCountedTest(unittest.TestCase):
    def test_every_raw_create_is_counted(self):
        lines = open(SRC, encoding="utf-8").read().split("\n")
        found = []
        for i, line in enumerate(lines):
            code = re.sub(r'"(?:\\.|[^"\\])*"', '""', line.split("//")[0])   # no strings or comments
            if not CREATE.search(code):
                continue
            name = re.search(r'"([^"]+)"', line)
            name = name.group(1) if name else "line %d" % (i + 1)
            found.append(name)
            if name in EXEMPT:
                continue
            after = "\n".join(lines[i:i + WINDOW])
            self.assertIn(COUNTED, after,
                          "%s (TelephonyAnchorClient.cpp:%d) is not counted in dynamicTaskCreates" % (name, i + 1))
        self.assertTrue(found, "no raw task creates found; the pattern is stale")


if __name__ == "__main__":
    unittest.main()
