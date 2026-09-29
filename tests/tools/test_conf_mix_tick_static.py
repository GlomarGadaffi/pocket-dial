"""#479 source gate: the conference room's conf_mix_tick task runs on the room's
boot-allocated static stack + TCB, is created once, and parks between conferences.

Fails when conf_mix_tick is created any way other than xTaskCreateStaticPinnedToCore
on ConferenceRoom::_driverMem, when it deletes itself (a static task's memory would
then be reused while the idle task may still be cleaning up the old TCB), or when it
is counted as a dynamic create again. Source-level, like test_rtp_static_slots.py:
the ESP path never runs on the host.
"""
import os
import re
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
CPP = "src/SIP/ConferenceRoom.cpp"
HPP = "src/SIP/ConferenceRoom.hpp"

CREATE = re.compile(r"\b(xTaskCreate\w*|pd::createTask\w*)\s*\(")


def code(path):
    with open(os.path.join(ROOT, path), encoding="utf-8") as f:
        return "".join(ln.rstrip("\r\n").split("//")[0] + "\n" for ln in f)


def mix_creates(text):
    """[(create function, call text)] for every task create naming conf_mix_tick."""
    out = []
    for m in CREATE.finditer(text):
        call = text[m.start():text.index(";", m.end())]
        if '"conf_mix_tick"' in call:
            out.append((m.group(1), call))
    return out


def body_of(text, signature):
    start = text.index(signature)
    return text[start:re.search(r"\n\}\n", text[start:]).end() + start]


class ConfMixTickStatic(unittest.TestCase):
    def test_gate_catches_the_dynamic_create(self):
        # Red check for the gate itself: the pre-#479 line is a dynamic create.
        old = ('BaseType_t ok = xTaskCreatePinnedToCore('
               '&ConferenceRoom::taskTrampoline, "conf_mix_tick", 3072, this, 6, nullptr, 0);')
        self.assertEqual([f for f, _ in mix_creates(old)], ["xTaskCreatePinnedToCore"])
        self.assertEqual(mix_creates('xTaskCreate(&f, "other", 3072, a, 6, &h);'), [])

    def test_conf_mix_tick_is_static_on_the_room_slot(self):
        creates = mix_creates(code(CPP))
        self.assertEqual(len(creates), 1, "exactly one conf_mix_tick create site")   # positive control
        fn, call = creates[0]
        self.assertEqual(fn, "xTaskCreateStaticPinnedToCore", call)
        self.assertRegex(call, r"_driverMem\.stack,\s*_driverMem\.tcb")

    def test_slot_memory_is_allocated_once_at_construction(self):
        self.assertRegex(code(HPP), r"pd::StaticTaskSlot\s+_driverMem;")
        ctor = body_of(code(CPP), "ConferenceRoom::ConferenceRoom()\n{")
        self.assertRegex(ctor, r"_driverMem\.alloc\(\"conf_mix_tick\",\s*pd::rtpslots::kConfMixStackBytes")

    def test_task_parks_and_never_deletes_itself(self):
        cpp = code(CPP)
        tramp = body_of(cpp, "void ConferenceRoom::taskTrampoline(")
        self.assertIn("ulTaskNotifyTake(", tramp)   # parked between conferences
        self.assertIn("runDriver()", tramp)         # positive control: it still runs the session
        self.assertNotRegex(cpp, r"\bvTaskDelete(WithCaps)?\s*\(\s*(nullptr|NULL)\s*\)")
        start = body_of(cpp, "void ConferenceRoom::startDriver()")
        self.assertIn("xTaskNotifyGive(_driverTask)", start)
        self.assertLess(start.index("xTaskCreateStaticPinnedToCore"), start.index("xTaskNotifyGive"))

    def test_static_create_is_not_counted_as_dynamic(self):
        self.assertNotIn("dynamicTaskCreates", code(CPP))

    def test_stack_matches_the_task_table(self):
        slots = code("src/SIP/RtpTaskSlots.hpp")
        stack = int(re.search(r"kConfMixStackBytes\s*=\s*(\d+);", slots).group(1))
        self.assertEqual(stack, 3072)   # MixBus scratch is a member since #498; HWM 2,172 B free on .244


if __name__ == "__main__":
    unittest.main()
