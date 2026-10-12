"""#986: source-level pins on EmergencyNotifier::flushStaged(), for the two
interleavings no host test can build deterministically (the staged-slot recheck
window is a few instructions wide and has no seam). The behaviour around it is
covered by the E911AlertStage gtests; this pins the lines those tests cannot
distinguish from a harmless rewrite."""
import os
import re
import unittest

SRC = os.path.join(os.path.dirname(__file__), "..", "..", "src", "SIP", "EmergencyNotifier.cpp")


def flush_body():
    with open(SRC, encoding="utf-8") as f:
        src = f.read()
    m = re.search(r"void EmergencyNotifier::flushStaged\(\)\s*\{(.*?)\n\}\n", src, re.S)
    assert m, "EmergencyNotifier::flushStaged() not found"
    return re.sub(r"//[^\n]*", "", m.group(1))   # code only, not comments


class FlushStagedPinTest(unittest.TestCase):
    def test_the_took_it_branch_rechecks_instead_of_leaving(self):
        body = flush_body()
        # The only early return is the try_lock failure; the "another flusher took it"
        # branch must `continue` so the loop condition looks at _staged again, or a
        # frame staged in that window is stranded until the next pass.
        self.assertEqual(len(re.findall(r"\breturn\b", body)), 1, body)
        self.assertRegex(body, r"owns_lock\(\)\)\s*\{\s*return;\s*\}")
        self.assertRegex(body, r"if \(!_staged\.load\(\)\)\s*\{\s*continue;\s*\}")

    def test_the_slot_is_emptied_under_its_lock_before_the_send(self):
        body = flush_body()
        self.assertEqual(body.count("Syslog::send("), 1)
        self.assertEqual(body.count("_staged.store(false)"), 1)
        self.assertLess(body.index("_slotMutex"), body.index("_staged.store(false)"))
        self.assertLess(body.index("_staged.store(false)"), body.index("Syslog::send("))
        # The send is outside the slot-lock block: nothing waits on it under that lock.
        slot_block_end = body.index("}", body.index("_staged.store(false)"))
        self.assertLess(slot_block_end, body.index("Syslog::send("))

    def test_a_second_flusher_never_waits_behind_the_send(self):
        body = flush_body()
        self.assertIn("std::try_to_lock", body)
        self.assertNotRegex(body, r"lock_guard<std::mutex>\s+\w+\(_sendMutex")


if __name__ == "__main__":
    unittest.main()
