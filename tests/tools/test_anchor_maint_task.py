"""#658: tel_restart, tel_rewarm and tel_reconcile run on one persistent tel_maint
task that tick() wakes with a notify bit. tick() must create no task, the maint
task is created once, and no maintenance body deletes the task it runs on. The
anchor client is ESP-only, so no host test can reach tick(); this pins the wiring."""
import os
import re
import unittest

SRC = os.path.join(os.path.dirname(__file__), "..", "..", "src", "SIP", "TelephonyAnchorClient.cpp")
CREATE = re.compile(r"\bxTaskCreate\w*\s*\(|createTaskPreferPsram\s*\(")


def body_of(src, signature):
    start = src.rindex(signature)   # the last definition: the first is the host stub
    brace = src.index("{", start)
    depth = 0
    for i in range(brace, len(src)):
        if src[i] == "{":
            depth += 1
        elif src[i] == "}":
            depth -= 1
            if depth == 0:
                return src[brace:i + 1]
    raise AssertionError("unbalanced body for " + signature)


def code_only(text):
    return "\n".join(line.split("//")[0] for line in text.split("\n"))


class AnchorMaintTaskTest(unittest.TestCase):
    def setUp(self):
        self.src = open(SRC, encoding="utf-8").read()

    def test_tick_creates_no_task(self):
        tick = code_only(body_of(self.src, "void TelephonyAnchorClient::tick("))
        self.assertIn("_reconcileInFlight", tick, "positive control: this is the tick() that arms reconcile")
        self.assertIsNone(CREATE.search(tick), "tick() must wake tel_maint, not create a task")

    def test_maint_task_created_once(self):
        sites = [l for l in code_only(self.src).split("\n") if CREATE.search(l) and '"tel_maint"' in l]
        self.assertEqual(len(sites), 1, "exactly one tel_maint create site")
        for name in ("tel_restart", "tel_rewarm", "tel_reconcile"):
            self.assertNotIn('"%s"' % name, code_only(self.src), name + " is no longer its own task")

    def test_maintenance_bodies_do_not_self_delete(self):
        for fn in ("restartTaskTrampoline", "rewarmTaskTrampoline", "reconcileTaskTrampoline"):
            body = code_only(body_of(self.src, "void TelephonyAnchorClient::%s(" % fn))
            self.assertIn("InFlight.store(false", body, "positive control: %s clears its gate" % fn)
            self.assertFalse("vTaskDelete" in body, fn + " runs on tel_maint and must return")


if __name__ == "__main__":
    unittest.main()
