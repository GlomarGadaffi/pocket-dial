"""#877 follow-up: docs/API.md tells operators to write emergency aliases as literals.

The sentence is only true while the router keeps desmo's #877 decision, "Only wildcard
rules yield": a wildcard Trunk rule whose transform is an emergency number yields to a
registered extension, and a literal one never does. This file pins the three together:

  * the doc sentence and its 11X / 112 example are in docs/API.md;
  * CallForker::matchDialRule() still gates the yield on dialPatternHasWildcard();
  * the gtest that drives the documented example still exists
    (tests/EmergencyDialing_test.cpp), so a behaviour change turns it red.

Run: python3 -m unittest discover -s tests/tools -p "test_*.py"
"""
import os
import re
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, "..", ".."))

DOC = os.path.join("docs", "API.md")
FORKER = os.path.join("src", "SIP", "CallForker.cpp")
GTEST = os.path.join("tests", "EmergencyDialing_test.cpp")
EXAMPLE_TEST = "AWildcardEmergencyAliasLetsARegistrationCaptureItAndALiteralOneDoesNot"


def read(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8", errors="replace") as f:
        return f.read()


def flat(text):
    return re.sub(r"\s+", " ", text)


class EmergencyAliasDocTest(unittest.TestCase):
    def test_the_doc_says_write_emergency_aliases_as_literals(self):
        doc = flat(read(DOC))
        self.assertIn("Emergency aliases: write them as literals.", doc)
        self.assertIn("so a wildcard alias would let a device that registers as 112 capture 112.", doc)
        self.assertIn("Write emergency aliases as literals.", doc)
        self.assertIn("under `11X` -> `911`, a call to a registered `112` rings `112`", doc)
        self.assertIn("`112` -> `911` places the emergency call even when a phone has registered as `112`", doc)

    def test_the_router_still_yields_only_for_a_wildcard_rule(self):
        src = read(FORKER)
        m = re.search(r"CallForker::matchDialRule\(.*?\n\}", src, re.S)
        self.assertIsNotNone(m, "CallForker::matchDialRule() not found")
        body = m.group(0)
        self.assertIn("dialPatternHasWildcard(r.pattern)", body)
        self.assertIn("classifyEmergencyDial(transformed).isEmergency", body)
        self.assertIn("findRegistered(dialed)", body)

    def test_the_documented_example_is_driven_by_a_gtest(self):
        src = read(GTEST)
        self.assertRegex(src, r"TEST\(EmergencyDialing,\s*" + EXAMPLE_TEST + r"\)")
        body = src[src.index(EXAMPLE_TEST):]
        self.assertIn('setDialRule("11X", "trunk", "911", 3)', body)
        self.assertIn('setDialRule("112", "trunk", "911", 3)', body)


if __name__ == "__main__":
    unittest.main()
