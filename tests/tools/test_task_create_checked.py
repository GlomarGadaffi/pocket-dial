"""#1006: every xTaskCreate / xTaskCreatePinnedToCore in main/esp_main_*.cpp must
check its return (compare against pdPASS, or assign it so a following line can),
or sit in EXEMPT below with a reason. A create that fails silently leaves the
board half-booted with no log line (seen on hardware: the STA dashboard never
came up). main/ is ESP-only, so no host test can reach these creates; this pins
the shape, as test_anchor_task_create_counted.py does for the anchor client.

The second test pins HttpServer::start(): its accept std::thread must be
constructed inside a try, because std::thread's constructor throws
std::system_error when the pthread cannot be created, and uncaught that aborts
the board. No host seam can force pthread_create to fail, so this is a pin."""
import glob
import os
import re
import unittest

ROOT = os.path.join(os.path.dirname(__file__), "..", "..")
MAIN_GLOB = os.path.join(ROOT, "main", "esp_main*.cpp")
HTTP_SERVER = os.path.join(ROOT, "src", "Helpers", "HttpServer.cpp")
CREATE = re.compile(r"\bxTaskCreate(?:PinnedToCore)?\s*\(")
ASSIGNED = re.compile(r"=\s*xTaskCreate(?:PinnedToCore)?\s*\(")
WINDOW = 3   # lines, from the create call, in which pdPASS must appear
# (file basename, task name) -> why its return is not checked
EXEMPT = {}


def _code(line):
    """The line without string literals or a trailing // comment."""
    return re.sub(r'"(?:\\.|[^"\\])*"', '""', line.split("//")[0])


def _lines(path):
    with open(path, encoding="utf-8") as f:
        return f.read().split("\n")


class TaskCreateCheckedTest(unittest.TestCase):
    def test_every_create_in_main_checks_its_return(self):
        files = sorted(glob.glob(MAIN_GLOB))
        self.assertTrue(files, "no main/esp_main*.cpp found; the glob is stale")
        found = 0
        unchecked = []
        for path in files:
            base = os.path.basename(path)
            lines = _lines(path)
            for i, line in enumerate(lines):
                code = _code(line)
                if not CREATE.search(code):
                    continue
                found += 1
                name = re.search(r'"([^"]+)"', line)
                name = name.group(1) if name else "line %d" % (i + 1)
                if (base, name) in EXEMPT:
                    continue
                window = "\n".join(_code(l) for l in lines[i:i + WINDOW])
                if ASSIGNED.search(code) or "pdPASS" in window:
                    continue
                unchecked.append("%s:%d %s" % (base, i + 1, name))
        self.assertTrue(found, "no task creates found; the pattern is stale")
        self.assertEqual([], unchecked,
                         "%d task create(s) discard their return:\n  %s"
                         % (len(unchecked), "\n  ".join(unchecked)))

    def test_http_server_start_constructs_accept_thread_inside_try(self):
        lines = _lines(HTTP_SERVER)
        begin = next((i for i, l in enumerate(lines) if l.startswith("void HttpServer::start()")), None)
        self.assertIsNotNone(begin, "HttpServer::start() not found; the pin is stale")
        end = next(i for i in range(begin + 1, len(lines)) if lines[i] == "}")
        body = [_code(l).strip() for l in lines[begin:end]]
        thread_at = next((i for i, l in enumerate(body) if "std::thread(" in l), None)
        self.assertIsNotNone(thread_at, "start() no longer constructs a std::thread; the pin is stale")
        try_at = next((i for i, l in enumerate(body) if l == "try" or l.startswith("try ")), None)
        self.assertIsNotNone(try_at,
                             "HttpServer::start() constructs its std::thread with no try: a pthread "
                             "create failure throws std::system_error and aborts the board (#1006)")
        self.assertLess(try_at, thread_at, "the try must open before the std::thread is constructed")
        self.assertTrue(any(l.startswith("catch") and "system_error" in l for l in body[thread_at:]),
                        "start() must catch std::system_error after the std::thread")


if __name__ == "__main__":
    unittest.main()
