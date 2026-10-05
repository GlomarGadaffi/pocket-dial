"""#450: pin the ESP-only end of both factory-reset doors, which no host test
reaches. Each must end with nvs_flash_erase() (the whole NVS partition: the
per-key erases leave the old bytes in flash until page GC) and only then
esp_restart(). The HTTP door does it in its restart task, the keypad door
(*<PIN>#999#1) on the SIP thread."""
import os
import re
import unittest

ROOT = os.path.join(os.path.dirname(__file__), "..", "..", "src")


def code(path):
    return re.sub(r"//[^\n]*", "", open(os.path.join(ROOT, path), encoding="utf-8").read())


class ResetNvsEraseWiringTest(unittest.TestCase):
    def assert_erase_then_restart(self, body, door):
        self.assertIn("nvs_flash_erase()", body, door + " no longer erases the whole NVS partition")
        erase = body.index("nvs_flash_erase()")
        self.assertNotEqual(body.find("esp_restart()", erase), -1,
                            door + ": no restart follows the whole-partition erase")

    def test_http_door_ends_with_the_whole_partition_erase(self):
        m = re.search(r"void HttpServer::sendApiFactoryReset\([^)]*\)\s*\{(.*?)\n\}", code("Helpers/HttpServer.cpp"), re.S)
        self.assertIsNotNone(m, "HttpServer::sendApiFactoryReset() not found")
        self.assert_erase_then_restart(m.group(1), "the HTTP door")

    def test_keypad_door_ends_with_the_whole_partition_erase(self):
        src = code("SIP/DtmfFeatureCodes.cpp")
        start = src.find("factory reset confirmed via DTMF")
        self.assertNotEqual(start, -1, "the *<PIN>#999#1 branch not found")
        end = src.find("factory reset aborted", start)
        self.assertNotEqual(end, -1)
        self.assert_erase_then_restart(src[start:end], "the keypad door")


if __name__ == "__main__":
    unittest.main()
