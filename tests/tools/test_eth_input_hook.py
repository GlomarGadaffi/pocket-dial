"""#1145: the esp_eth input hook (main/pd_eth_ingress.c) runs only on the ESP
Ethernet images, so no host test can run it; this pins its shape. Every frame
must be forwarded to the netif exactly once and never freed by the hook
(esp_netif_receive owns the buffer on every path), every classification it
counts must reach a counter, and both eth mains must install it between
esp_netif_attach and esp_eth_start."""
import os
import re
import unittest

ROOT = os.path.join(os.path.dirname(__file__), "..", "..")
HOOK_C = os.path.join(ROOT, "main", "pd_eth_ingress.c")
MAINS = ["esp_main_eth.cpp", "esp_main_eth_lan8720.cpp"]
FORWARD = "return esp_netif_receive((esp_netif_t *)priv, buf, len, NULL);"


def code_of(path):
    """The file with // and /* */ comments removed."""
    with open(path, encoding="utf-8") as f:
        text = f.read()
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return re.sub(r"//[^\n]*", "", text)


def body_of(code, name):
    """The brace-delimited body of the function definition `name`."""
    m = re.search(r"\b" + re.escape(name) + r"\s*\([^;{]*\)\s*\{", code)
    if not m:
        raise AssertionError("no definition of %s" % name)
    depth, i = 0, m.end() - 1
    for j in range(i, len(code)):
        depth += {"{": 1, "}": -1}.get(code[j], 0)
        if depth == 0:
            return code[i:j + 1]
    raise AssertionError("unbalanced body of %s" % name)


class EthInputHookTest(unittest.TestCase):
    def setUp(self):
        self.code = code_of(HOOK_C)

    def test_the_hook_forwards_exactly_once_on_its_one_path(self):
        body = body_of(self.code, "pd_eth_ingress_input")
        self.assertEqual(len(re.findall(r"\breturn\b", body)), 1, "the hook must have one return")
        self.assertEqual(body.count("esp_netif_receive("), 1)
        self.assertIn(FORWARD, body)
        self.assertTrue(body.rstrip("} \n\t").endswith(FORWARD),
                        "nothing may run after the frame is forwarded")

    def test_nothing_in_the_file_frees(self):
        self.assertIsNone(re.search(r"\b\w*free\w*\s*\(", self.code))

    def test_every_counted_class_reaches_a_counter(self):
        body = body_of(self.code, "classify")
        for cond, which in (("verdict == PD_L2_WOULD_DROP_LAN_GW_MAC", "PD_ETH_INGRESS_LAN_GW_MAC"),
                            ("gwChanged", "PD_ETH_INGRESS_GW_CHANGED")):
            self.assertRegex(body, r"if \(" + re.escape(cond) + r"\) count\(" + which + r"\);")
        self.assertIn("count(PD_ETH_INGRESS_FRAMES);", body_of(self.code, "observe"))

    def test_martian_and_wan_service_are_left_to_the_ip4_hook(self):
        for cls in ("PD_L2_WOULD_DROP_MARTIAN", "PD_L2_WOULD_DROP_WAN_SERVICE"):
            self.assertNotIn(cls, self.code)

    def test_the_hot_path_is_in_iram(self):
        for fn in ("pd_eth_ingress_input", "observe", "classify"):
            self.assertRegex(self.code, r"IRAM_ATTR " + fn + r"\(")

    def test_both_eth_mains_install_between_attach_and_start(self):
        for name in MAINS:
            code = code_of(os.path.join(ROOT, "main", name))
            attach = code.find("esp_netif_attach(s_eth_netif")
            install = code.find("pd_eth_ingress_install(eth_handle, s_eth_netif)")
            start = code.find("esp_eth_start(eth_handle)")
            self.assertTrue(0 <= attach < install < start, "%s: attach < install < start" % name)
            self.assertIn("ESP_ERROR_CHECK(pd_eth_ingress_install(", code)
            self.assertRegex(code, r"IP_EVENT,\s*IP_EVENT_ETH_LOST_IP,", name)
            self.assertIn("pd_eth_ingress_set_ip(&event->ip_info)", code)
            self.assertIn("pd_eth_ingress_set_ip(nullptr)", code)
            self.assertEqual(code.count("pd_eth_ingress_link_event()"), 2, name)


if __name__ == "__main__":
    unittest.main()
