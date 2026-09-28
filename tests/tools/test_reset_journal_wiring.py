"""#595 nits: pin the ESP-only wiring of the reset journal, which no host test
reaches. HttpServer::acceptLoop() primes resetjournal::bootStatus() before its
first accept(), and the load lock asserts its xSemaphoreTake() succeeded."""
import os
import re
import unittest

ROOT = os.path.join(os.path.dirname(__file__), "..", "..", "src", "Helpers")


def code(path):
    return re.sub(r"//[^\n]*", "", open(os.path.join(ROOT, path), encoding="utf-8").read())


class ResetJournalWiringTest(unittest.TestCase):
    def test_accept_loop_primes_boot_status_before_the_first_accept(self):
        m = re.search(r"void HttpServer::acceptLoop\(\)\s*\{(.*?)\n\}", code("HttpServer.cpp"), re.S)
        self.assertIsNotNone(m, "HttpServer::acceptLoop() not found")
        body = m.group(1)
        self.assertIn("resetjournal::bootStatus()", body)
        self.assertIn("accept(", body)
        self.assertLess(body.index("resetjournal::bootStatus()"), body.index("accept("))

    def test_load_lock_asserts_the_take(self):
        self.assertRegex(code("ResetJournal.cpp"),
                         r"(\w+)\s*=\s*xSemaphoreTake\([^;]*portMAX_DELAY\);\s*configASSERT\(\1 == pdTRUE\)")


if __name__ == "__main__":
    unittest.main()
