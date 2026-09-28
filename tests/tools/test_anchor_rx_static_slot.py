"""#479 (part A) source gate: the anchor's per-call tel_media_rx task runs on its
call slot's boot-allocated static stack + TCB, and is reaped without freeing it.

Fails when tel_media_rx is created any way other than xTaskCreateStaticPinnedToCore
on CallSlot::rxMem, or when reapParkedRxLocked() deletes it with pd::deleteTask
(which would free the slot's memory). Source-level, like test_rtp_static_slots.py:
the anchor client is a stub on the host, so no host run can see the create.
"""
import os
import re
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
CPP = "src/SIP/TelephonyAnchorClient.cpp"
HPP = "src/SIP/TelephonyAnchorClient.hpp"

CREATE = re.compile(r"\b(xTaskCreate\w*|pd::createTask\w*)\s*\(")


def code(path):
    with open(os.path.join(ROOT, path), encoding="utf-8") as f:
        return "".join(ln.split("//")[0] for ln in f)


def rx_creates(text):
    """[(create function, call text)] for every task create naming tel_media_rx."""
    out = []
    for m in CREATE.finditer(text):
        call = text[m.start():text.index(";", m.end())]
        if '"tel_media_rx"' in call:
            out.append((m.group(1), call))
    return out


def body_of(text, signature):
    start = text.index(signature)
    return text[start:re.search(r"\n\}\n", text[start:]).end() + start]


class AnchorRxStaticSlot(unittest.TestCase):
    def test_gate_catches_the_dynamic_create(self):
        # Red check for the gate itself: the pre-#479 line is a dynamic create.
        old = ('BaseType_t rc = pd::createTaskPreferPsram(&TelephonyAnchorClient::rxTaskTrampoline, '
               '"tel_media_rx", 6144, arg, 6, &slot->rxTaskHandle, 1);')
        self.assertEqual([f for f, _ in rx_creates(old)], ["pd::createTaskPreferPsram"])
        self.assertEqual(rx_creates('xTaskCreate(&f, "other", 6144, a, 6, &h);'), [])

    def test_tel_media_rx_is_static_on_the_call_slot(self):
        creates = rx_creates(code(CPP))
        self.assertEqual(len(creates), 1, "exactly one tel_media_rx create site")   # positive control
        fn, call = creates[0]
        self.assertEqual(fn, "xTaskCreateStaticPinnedToCore", call)
        self.assertRegex(call, r"slot->rxMem\.stack,\s*slot->rxMem\.tcb")

    def test_slot_memory_is_allocated_once_at_construction(self):
        self.assertRegex(code(HPP), r"pd::StaticTaskSlot\s+rxMem;")
        ctor = body_of(code(CPP), "TelephonyAnchorClient::TelephonyAnchorClient()\n{")
        self.assertRegex(ctor, r"rxMem\.alloc\(\"tel_media_rx\"")

    def test_reap_does_not_free_the_slot(self):
        reap = body_of(code(CPP), "pd::ReapDecision TelephonyAnchorClient::reapParkedRxLocked(")
        self.assertIn("eSuspended", reap)   # still reaps only a parked task (#553/#608)
        self.assertNotRegex(reap, r"\bpd::deleteTask\s*\(")
        self.assertRegex(reap, r"\bvTaskDelete\(slot\.rxTaskHandle\);")


if __name__ == "__main__":
    unittest.main()
