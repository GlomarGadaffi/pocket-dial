"""#479 source gate: the RTP media tasks run on per-slot static stacks.

Fails when RtpSender/RtpReceiver create a task any way other than
xTaskCreateStaticPinnedToCore on the slot's boot-allocated memory, delete one
with a heap-freeing call, or when the conference room (whose legs own slots)
is built anywhere but the RequestsHandler constructor. Source-level, like the
other tests/tools gates: the ESP paths it guards never run on the host.
"""
import os
import re
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

# Any task create; std::thread is the host-only (#elif __linux__) path.
CREATE = re.compile(r"\b(xTaskCreate\w*|pd::createTask\w*)\s*\(")
FORBIDDEN = re.compile(r"\bpd::deleteTask\s*\(|\bvTaskDelete(WithCaps)?\s*\(\s*(nullptr|NULL)\s*\)")


def code(path):
    with open(os.path.join(ROOT, path), encoding="utf-8") as f:
        return [ln.split("//")[0] for ln in f]


def violations(lines):
    """Bad task creates/deletes in one file's code lines."""
    bad = []
    for n, ln in enumerate(lines, 1):
        m = CREATE.search(ln)
        if m and m.group(1) != "xTaskCreateStaticPinnedToCore":
            bad.append((n, m.group(1)))
        if FORBIDDEN.search(ln):
            bad.append((n, FORBIDDEN.search(ln).group(0)))
    return bad


class RtpStaticSlots(unittest.TestCase):
    def test_gate_catches_a_dynamic_create(self):
        # Red check for the gate itself.
        self.assertTrue(violations(['  xTaskCreatePinnedToCore(&f, "rtp_media_tx", 6144, this, 6, nullptr, 0);']))
        self.assertTrue(violations(["  pd::createTaskPreferPsram(&f, \"rtp_media_rx\", 6144, this, 6, &h, 0);"]))
        self.assertTrue(violations(["  vTaskDelete(nullptr);"]))
        self.assertFalse(violations(["  h = xTaskCreateStaticPinnedToCore(&f, \"x\", n, this, 6, s, t, 0);"]))

    def test_rtp_tasks_are_static_on_the_slot(self):
        for path in ("src/SIP/RtpSender.cpp", "src/SIP/RtpReceiver.cpp"):
            lines = code(path)
            self.assertEqual(violations(lines), [], path)
            text = "".join(lines)
            self.assertEqual(len(re.findall(r"\bxTaskCreateStaticPinnedToCore\s*\(", text)), 1, path)
            self.assertRegex(text, r"_taskMem\.stack,\s*_taskMem\.tcb", path)
            self.assertRegex(text, r"_taskMem\.alloc\(", path)
            self.assertRegex(text, r"pd::reapParkedStaticTask\(", path)

    def test_conference_slots_are_built_at_boot(self):
        text = "".join(code("src/SIP/RequestsHandler.cpp"))
        sites = [m.start() for m in re.finditer(r"make_unique<ConferenceRoom>", text)]
        self.assertEqual(len(sites), 1)
        ctor = text.index("RequestsHandler::RequestsHandler(")
        after_ctor = re.search(r"\n\}\n", text[ctor:]).end() + ctor
        self.assertTrue(ctor < sites[0] < after_ctor, "ConferenceRoom must be built in the constructor")
        # ... and only when the build has a conference (POCKETDIAL_CONFERENCE).
        guard = text.rfind("#if", ctor, sites[0])
        self.assertRegex(text[guard:sites[0]], r"^#if POCKETDIAL_CONFERENCE\b")
        self.assertNotIn("#endif", text[guard:sites[0]])

    def test_constrained_has_no_conference_and_fits_72kb(self):
        with open(os.path.join(ROOT, "main", "CMakeLists.txt"), encoding="utf-8") as f:
            cm = f.read()
        block = cm[cm.index("if(SIP_CONSTRAINED)"):]
        block = block[:block.index("endif()")]
        caps = dict(re.findall(r"(POCKETDIAL_(?:MAX_ANCHOR_CALLS|MAX_VOICEMAIL_LEGS|MAX_TRUNK_CALLS|CONFERENCE))=(\d+)", block))
        self.assertEqual(caps.get("POCKETDIAL_CONFERENCE"), "0", "constrained must build no conference room")
        a, v, t = (int(caps[k]) for k in ("POCKETDIAL_MAX_ANCHOR_CALLS", "POCKETDIAL_MAX_VOICEMAIL_LEGS",
                                         "POCKETDIAL_MAX_TRUNK_CALLS"))
        tx, rx = 1 + a + v, a + v + 2 * t
        # No PSRAM: every slot is internal, fixed at boot. Stated cost: 7 x 6 KB = 42 KB.
        self.assertLessEqual((tx + rx) * 6144, 72 * 1024)

    def test_mix_ports_follow_the_conference_legs(self):
        text = "".join(code("src/SIP/MixBus.hpp"))
        self.assertRegex(text, r"MAX_PORTS\s*=\s*POCKETDIAL_CONF_LEGS\s*;")


if __name__ == "__main__":
    unittest.main()
