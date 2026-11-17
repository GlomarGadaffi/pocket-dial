"""#1145: the IPv4 input hook's would-drop counters only count.

main/pd_lwip_hooks.c drops in exactly three places (padded frame, tiny
fragment, mDNS fragment), each a pbuf_free(p) then return 1. The #1145
counters must add no fourth: pin both counts, comments stripped so prose
cannot move them, and pin that the counting call sits on the pass path.
"""

import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
HOOKS = ROOT / "main" / "pd_lwip_hooks.c"


def code_only(text):
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return re.sub(r"//[^\n]*", "", text)


def drop_paths(text):
    code = code_only(text)
    return len(re.findall(r"\bpbuf_free\s*\(", code)), len(re.findall(r"\breturn\s+1\s*;", code))


class HookCountOnly(unittest.TestCase):
    def test_no_new_drop_path(self):
        self.assertEqual(drop_paths(HOOKS.read_text(encoding="utf-8")), (3, 3))

    def test_counting_runs_on_the_pass_path(self):
        code = code_only(HOOKS.read_text(encoding="utf-8"))
        self.assertTrue(re.search(r"pd_l2_count\(p, inp\);\s*return 0;", code),
                        "pd_l2_count(p, inp) must sit right before the hook's final return 0")

    def test_an_added_drop_is_caught(self):
        extra = HOOKS.read_text(encoding="utf-8").replace(
            "pd_l2_count(p, inp);", "pd_l2_count(p, inp); pbuf_free(p); return 1;")
        self.assertEqual(drop_paths(extra), (4, 4))


if __name__ == "__main__":
    unittest.main()
