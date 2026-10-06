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

    def branches(self):
        ok_at = self.ctrl.index("if (err == ESP_OK)")
        fail_at = self.ctrl.index('ESP_LOGW(TAG, "Control request failed', ok_at)
        return self.ctrl[ok_at:fail_at], self.ctrl[fail_at:]

    def test_close_sits_after_the_status_read_and_only_on_the_success_branch(self):
        ok, fail = self.branches()
        self.assertEqual(self.ctrl.count("esp_http_client_close(_ctrlClient);"), 1,
                         "exactly one close of _ctrlClient in performCtrl")
        close_at = ok.find("esp_http_client_close(_ctrlClient);")
        self.assertNotEqual(close_at, -1, "the one close is on the success branch")
        status_at = ok.find("esp_http_client_get_status_code(_ctrlClient)")
        self.assertNotEqual(status_at, -1, "positive control: the success branch reads the status")
        self.assertLess(status_at, close_at, "read the status before closing the connection")
        self.assertLess(close_at, ok.find("return (status >= 200 && status < 300);"))

    def test_failure_branch_never_closes_a_broken_handle_it_cleans_up_and_nulls_it(self):
        _, fail = self.branches()
        self.assertNotIn("esp_http_client_close(", fail, "a failed handle is destroyed, never closed and reused (#350)")
        cleanup_at = fail.find("esp_http_client_cleanup(_ctrlClient);")
        self.assertNotEqual(cleanup_at, -1)
        self.assertRegex(fail[cleanup_at:], r"cleanup\(_ctrlClient\);\s*_ctrlClient = nullptr;")

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
