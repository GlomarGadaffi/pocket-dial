"""Unit tests for tools/ci/app_slot_margin.py (issue #489)."""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "tools", "ci"))
import app_slot_margin as m  # noqa: E402


class ParseSize(unittest.TestCase):
    def test_every_form_gen_esp32part_prints(self):
        self.assertEqual(m.parse_size("6M"), 6 * 1024 * 1024)
        self.assertEqual(m.parse_size("1920K"), 1920 * 1024)
        self.assertEqual(m.parse_size("0x1e0000"), 0x1E0000)
        self.assertEqual(m.parse_size(" 4096 "), 4096)


class AppSlots(unittest.TestCase):
    CSV_4MB = (
        "# ESP-IDF Partition Table\n"
        "# Name, Type, SubType, Offset, Size, Flags\n"
        "nvs,data,nvs,0x9000,24K,\n"
        "otadata,data,ota,0xf000,8K,\n"
        "ota_0,app,ota_0,0x20000,1920K,\n"
        "ota_1,app,ota_1,0x200000,1920K,\n"
    )

    def test_only_app_rows_are_slots(self):
        self.assertEqual(m.app_slots(self.CSV_4MB),
                         [("ota_0", 1920 * 1024), ("ota_1", 1920 * 1024)])

    def test_a_table_with_no_app_is_empty_so_main_fails_closed(self):
        self.assertEqual(m.app_slots("nvs,data,nvs,0x9000,24K,\n"), [])


class Verdict(unittest.TestCase):
    SLOT = 0x1E0000   # the constrained 4 MB layout's slot

    def test_thresholds(self):
        self.assertEqual(m.verdict(self.SLOT - 100 * 1024, self.SLOT), "ok")
        self.assertEqual(m.verdict(self.SLOT - m.WARN_BELOW, self.SLOT), "ok")
        self.assertEqual(m.verdict(self.SLOT - m.WARN_BELOW + 1, self.SLOT), "warn")
        self.assertEqual(m.verdict(self.SLOT - m.FAIL_BELOW, self.SLOT), "warn")
        self.assertEqual(m.verdict(self.SLOT - m.FAIL_BELOW + 1, self.SLOT), "fail")
        self.assertEqual(m.verdict(self.SLOT + 1, self.SLOT), "fail")

    def test_todays_constrained_image_passes(self):
        # 1,890,720 B at #480's head (#489): 75,360 B free, above the 64 KB warning.
        self.assertEqual(m.verdict(1890720, self.SLOT), "ok")


if __name__ == "__main__":
    unittest.main()
