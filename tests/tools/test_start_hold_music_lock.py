"""#717: startHoldMusic() runs off the SIP thread and must not touch _logQueue bare.

It is called from the HTTP task (MoH clip upload, boot). _logQueue is swapped out
under _mutex by the SIP thread, so every queueLog() in startHoldMusic() must sit
under a _mutex lock, and the SD-card reads (loadClip/start) must not. The
interleaving cannot be forced on the host, so this pins the source."""
import os
import re
import unittest

SRC = os.path.join(os.path.dirname(__file__), "..", "..", "src", "SIP", "RequestsHandler.cpp")


def body():
    text = re.sub(r"//[^\n]*", "", open(SRC, encoding="utf-8").read())
    m = re.search(r"bool RequestsHandler::startHoldMusic\(.*?\n\}", text, re.S)
    assert m, "startHoldMusic not found"
    return m.group(0)


class StartHoldMusicLockTest(unittest.TestCase):
    def test_queuelog_only_under_mutex(self):
        b = body()
        # positive control: the function still logs and still loads the clip
        self.assertIn("_holdMusic.loadClip(", b)
        self.assertIn("_holdMusic.start()", b)
        self.assertIn("queueLog(", b)
        # every queueLog() is preceded, in its own lambda/block, by a _mutex lock
        for m in re.finditer(r"queueLog\(", b):
            before = b[: m.start()]
            self.assertRegex(before[before.rfind("{"):], r"lock_guard<std::mutex>\s+\w+\(_mutex\)",
                             "queueLog() in startHoldMusic() without _mutex held")

    def test_clip_io_not_under_mutex(self):
        b = body()
        # drop the log lambda (the only place the lock is taken); nothing else
        # in the function may mention _mutex, so the SD reads run unlocked
        rest = re.sub(r"auto log = .*?\n\t\};", "", b, flags=re.S)
        self.assertNotEqual(rest, b, "log lambda not found")
        self.assertIn("_holdMusic.loadClip(", rest)
        self.assertNotIn("_mutex", rest, "clip loading must not run under the SIP lock")


if __name__ == "__main__":
    unittest.main()
