"""#1117: pin the LVGL object-tree depth the recursion_allowlist rows rest on.

The display image's gate rows for LVGL's recursive functions (event_send_core,
refresh_children_style, lv_obj_transform_point) bound their depth by the depth of the
widget tree main/ui/ui.cpp builds, which is the only place the image creates widgets.
Those rows say 6, 6 and 7 (the tree depth, and the tree depth plus LVGL's NULL
activation). This reads ui.cpp's `lv_*_create(parent)` calls, works out the deepest
chain, and fails if the tree gets deeper than the rows say, if a widget is created from
a parent this test cannot trace, or if a widget class other than obj, label or canvas
(which create no children of their own) appears.
"""
import glob
import json
import os
import re
import unittest

REPO = os.path.join(os.path.dirname(__file__), "..", "..")
UI = os.path.join(REPO, "main", "ui", "ui.cpp")
TABLE = os.path.join(REPO, "tools", "ci", "task_stacks.json")
CREATE = re.compile(r"^\s*(?:lv_obj_t\s*\*\s*)?([\w.]+)\s*=\s*lv_(\w+?)_create\(\s*([\w.()]+?)\s*\)\s*;", re.M)
ALLOWED = {"obj", "label", "canvas"}


def code(path):
    with open(path, encoding="utf-8") as f:
        text = f.read()
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return re.sub(r"//[^\n]*", "", text)


def depths():
    """{variable: depth} with lv_scr_act() at depth 1; None for a create this test cannot trace."""
    found = CREATE.findall(code(UI))
    depth = {"lv_scr_act()": 1}
    pending = [(v, t, p) for v, t, p in found if t != "timer"]
    for _ in range(len(pending) + 1):
        for v, t, p in list(pending):
            if p in depth:
                depth[v] = max(depth.get(v, 0), depth[p] + 1)
                pending.remove((v, t, p))
    return depth, pending, found


class UiTreeDepth(unittest.TestCase):
    def test_every_create_has_a_traceable_parent(self):
        depth, pending, found = depths()
        self.assertGreater(len(found), 20, "the pattern stopped matching ui.cpp")
        self.assertEqual(pending, [], "a widget created from a parent this test cannot trace")
        calls = re.findall(r"(?<![\w.])lv_(?!timer)\w+?_create\(", code(UI))
        self.assertEqual(len(calls), len([f for f in found if f[1] != "timer"]), "a create call the pattern missed")

    def test_only_childless_widget_classes_are_created(self):
        _, _, found = depths()
        self.assertLessEqual({t for _, t, _ in found if t != "timer"}, ALLOWED)

    def test_ui_cpp_is_the_only_place_widgets_are_created(self):
        for f in glob.glob(os.path.join(REPO, "main", "**", "*.c*"), recursive=True):
            if os.path.abspath(f) == os.path.abspath(UI):
                continue
            hits = re.findall(r"\blv_(?!timer)\w+_create\(", code(f))
            self.assertEqual(hits, [], os.path.relpath(f, REPO))

    def test_the_recursion_rows_state_this_trees_depth(self):
        depth, _, _ = depths()
        deepest = max(depth.values())
        rows = json.load(open(TABLE, encoding="utf-8"))["recursion_allowlist"]
        self.assertEqual(rows["event_send_core"]["depth"], deepest)
        self.assertEqual(rows["refresh_children_style"]["depth"], deepest)
        self.assertEqual(rows["lv_obj_transform_point"]["depth"], deepest + 1)
        self.assertEqual(deepest, 6)


if __name__ == "__main__":
    unittest.main()
