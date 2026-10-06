"""#884: the anchor control connection (_ctrlClient) must close (not cleanup)
its transport socket after a successful performCtrl, keeping the handle and
its cached TLS session ticket warm for resumption (~100-150 ms) without leaving
an idle TCP socket that 3CX times out. The anchor client is ESP-only, so no
host C++ test compiles this wiring."""
import os
import re
import unittest

SIP = os.path.join(os.path.dirname(__file__), "..", "..", "src", "SIP")


def body_of(src, signature):
    start = src.rindex(signature)   # the last definition: the ESP arm, not a host stub
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


def read(name):
    with open(os.path.join(SIP, name), encoding="utf-8") as f:
        return f.read()


class AnchorCtrlIdleTest(unittest.TestCase):
    longMessage = False

    def setUp(self):
        raw = read("TelephonyAnchorClient.cpp")
        tac = code_only(raw)
        self.raw_warm = body_of(raw, "void TelephonyAnchorClient::warmCtrlConnection()")
        self.ctrl = body_of(tac, "bool TelephonyAnchorClient::performCtrl(")
        self.warm = body_of(tac, "void TelephonyAnchorClient::warmCtrlConnection()")
        self.make = body_of(tac, "bool TelephonyAnchorClient::makeCall(")

    def test_perform_ctrl_closes_client_on_success(self):
        perform_at = self.ctrl.find("esp_http_client_perform(_ctrlClient)")
        self.assertNotEqual(perform_at, -1, "positive control: performCtrl calls perform")
        ok_block = self.ctrl.find("if (err == ESP_OK)", perform_at)
        self.assertNotEqual(ok_block, -1, "must check err == ESP_OK")
        close_at = self.ctrl.find("esp_http_client_close(_ctrlClient);", ok_block)
        self.assertNotEqual(close_at, -1, "must close (not cleanup) _ctrlClient on success (#884)")
        ret_at = self.ctrl.find("return (status >= 200 && status < 300);", ok_block)
        self.assertLess(close_at, ret_at, "close must happen before returning success")

    def test_perform_ctrl_cleans_up_on_failure_only(self):
        ok_block_start = self.ctrl.find("if (err == ESP_OK)")
        ok_block_end = self.ctrl.find("ESP_LOGW(TAG, \"Control request failed")
        self.assertTrue(0 <= ok_block_start < ok_block_end)
        self.assertNotIn("esp_http_client_cleanup(_ctrlClient);", self.ctrl[ok_block_start:ok_block_end],
                         "success branch must never cleanup the handle or discard its session ticket")
        err_cleanup = self.ctrl.find("esp_http_client_cleanup(_ctrlClient);", ok_block_end)
        self.assertNotEqual(err_cleanup, -1, "failure branch must clean up the broken handle")
        self.assertIn("_ctrlClient = nullptr;", self.ctrl[err_cleanup:err_cleanup + 100],
                      "cleaned-up handle must be reset to nullptr for retry")

    def test_warm_ctrl_primes_session_and_does_not_mention_makecall(self):
        self.assertIn("performCtrl(url, nullptr, \"\", &status);", self.warm)
        # makeCall does not use performCtrl; the comment must not claim it does
        self.assertNotIn("makecall", self.raw_warm.lower(),
                         "warmCtrlConnection does not prime makeCall; comment must not claim so")

    def test_makecall_does_not_use_ctrl_client(self):
        self.assertNotIn("_ctrlClient", self.make, "makeCall must not use _ctrlClient")
        self.assertNotIn("performCtrl(", self.make, "makeCall must not use performCtrl")


if __name__ == "__main__":
    unittest.main()
