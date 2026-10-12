"""#986: pin the display build's log hook, which no host test compiles
(main/esp_main_display.cpp is ESP-only). screen_log_vprintf() hands the same
va_list to vsnprintf() and then to original_log_vprintf(); a va_list is
indeterminate after the first use unless it was va_copy()'d, and vsnprintf()
returns the length it WOULD have written, which the trim loop must not index."""
import os
import re
import unittest

SRC = os.path.join(os.path.dirname(__file__), "..", "..", "main", "esp_main_display.cpp")


def hook_body():
    with open(SRC, encoding="utf-8") as f:
        src = f.read()
    m = re.search(r"int screen_log_vprintf\(const char \*fmt, va_list tag\)\s*\{(.*?)\n    \}\n", src, re.S)
    assert m, "screen_log_vprintf() not found"
    return re.sub(r"//[^\n]*", "", m.group(1))   # code only, not comments


class ScreenLogVaCopyTest(unittest.TestCase):
    def test_vsnprintf_reads_a_copy_and_the_original_stays_intact(self):
        body = hook_body()
        self.assertIn("va_copy(copy, tag)", body)
        self.assertRegex(body, r"vsnprintf\(buf, sizeof\(buf\) - 1, fmt, copy\)")
        self.assertNotRegex(body, r"vsnprintf\([^)]*\btag\b")
        self.assertLess(body.index("va_copy("), body.index("vsnprintf("))
        self.assertLess(body.index("vsnprintf("), body.index("va_end(copy)"))
        self.assertLess(body.index("va_end(copy)"), body.index("original_log_vprintf(fmt, tag)"))

    def test_the_length_is_clamped_to_what_fit_before_the_trim_loop_reads_it(self):
        body = hook_body()
        clamp = re.search(r"if \(len > \(int\)sizeof\(buf\) - 2\) len = \(int\)sizeof\(buf\) - 2;", body)
        self.assertIsNotNone(clamp, "len is not clamped to sizeof(buf) - 2")
        self.assertLess(clamp.start(), body.index("buf[len-1]"))


if __name__ == "__main__":
    unittest.main()
