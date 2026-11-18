"""#1162: the anchor's HTTP and WebSocket clients are created inside a psram::MallocScope, so
their 4096 B buffers come from PSRAM and not from internal DRAM. The anchor client compiles only
on the device, so no host test reaches these two calls; this pins the source. The scope's own
numbers are pinned by PsramMallocScope_test.cpp."""
import os
import re
import unittest

ROOT = os.path.join(os.path.dirname(__file__), "..", "..", "src")


def read(*parts):
    with open(os.path.join(ROOT, *parts), encoding="utf-8") as f:
        return "\n".join(line.split("//")[0] for line in f.read().split("\n"))


def block_before(src, call):
    """The text of the innermost block that holds `call`, up to the call."""
    at = src.index(call)
    depth = 0
    for i in range(at - 1, -1, -1):
        if src[i] == "}":
            depth += 1
        elif src[i] == "{":
            if depth == 0:
                return src[i:at]
            depth -= 1
    raise AssertionError("no block holds " + call)


SCOPE = re.compile(r"\bpsram::MallocScope\s+\w+\s*;")


def scope_covers(before):
    """A scope declared in the call's own block, with no block closed between it and the call."""
    last = None
    for last in SCOPE.finditer(before):
        pass
    return last is not None and "}" not in before[last.end():]


class AnchorClientBuffersPsramTest(unittest.TestCase):
    longMessage = False

    def setUp(self):
        self.cpp = read("SIP", "TelephonyAnchorClient.cpp")
        self.hpp = read("Helpers", "PsramAllocator.hpp")

    def test_http_client_is_created_inside_a_scope(self):
        before = block_before(self.cpp, "esp_http_client_init(&config)")
        self.assertTrue(scope_covers(before), "makeAuthedClient creates its client outside a psram::MallocScope")

    def test_websocket_client_is_created_inside_a_scope(self):
        before = block_before(self.cpp, "esp_websocket_client_init(&wsCfg)")
        self.assertTrue(scope_covers(before), "connectWs creates its client outside a psram::MallocScope")

    def test_one_place_creates_each_client(self):
        # Positive control for the two tests above: they look at the only call sites there are.
        self.assertEqual(self.cpp.count("esp_http_client_init("), 1)
        self.assertEqual(self.cpp.count("esp_websocket_client_init("), 1)

    def test_the_buffers_are_the_size_the_scope_moves(self):
        self.assertIn("config.buffer_size = 4096;", self.cpp)
        self.assertIn("wsCfg.buffer_size = 4096;", self.cpp)

    def test_device_arm_sets_and_restores_the_idf_threshold(self):
        self.assertIn("heap_caps_malloc_extmem_enable(", self.hpp)
        self.assertIn("CONFIG_SPIRAM_MALLOC_ALWAYSINTERNAL", self.hpp)
        # The lower threshold while a scope lives, and the board's own when the last one ends.
        self.assertIn("applyMallocInternalLimit(kMallocScopeMinBytes - 1);", self.hpp)
        self.assertIn("applyMallocInternalLimit(kMallocDefaultInternalLimit);", self.hpp)

    def test_a_scope_that_ended_before_the_call_does_not_count(self):
        # Positive control for scope_covers().
        self.assertFalse(scope_covers("{ { psram::MallocScope s; } client = "))
        self.assertTrue(scope_covers("{ psram::MallocScope s; client = "))


if __name__ == "__main__":
    unittest.main()
