"""#701: MediaBridge::onHandsetRtp runs on the RTP receive task and must not read
_participantId (a std::string the SIP thread clears and reassigns under _mutex)
without the lock. It must snapshot it under _mutex into a fixed buffer, exactly
as feedMohTick() and dtmfSinkTrampoline() do, and hand writeAudio() the copy.
The interleaving cannot be forced on the host, so this pins the source."""
import os
import re
import unittest

SRC = os.path.join(os.path.dirname(__file__), "..", "..", "src", "SIP", "MediaBridge.cpp")


def code():
    return re.sub(r"//[^\n]*", "", open(SRC, encoding="utf-8").read())


def body_of(src, signature):
    start = src.index(signature)
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


class MediaBridgeParticipantIdSnapshotTest(unittest.TestCase):
    def check(self, fn):
        body = body_of(code(), "void MediaBridge::" + fn + "(")
        write = body.find("writeAudio(")
        self.assertNotEqual(write, -1, fn + " no longer calls writeAudio(): positive control lost")
        lock = body.find("std::lock_guard<std::mutex> lock(_mutex)")
        self.assertNotEqual(lock, -1, fn + " reads _participantId with no _mutex hold")
        self.assertLess(lock, write, fn + " takes _mutex after writeAudio(), not before")
        self.assertIn("std::memcpy(participantIdBuf, _participantId.data()", body[lock:write],
                      fn + " does not snapshot _participantId into the fixed buffer under the lock")
        call = body[write:body.find(";", write)]
        self.assertNotIn("_participantId", call, fn + " still hands writeAudio() the shared std::string")

    def test_feedMohTick_is_the_positive_control(self):
        self.check("feedMohTick")

    def test_onHandsetRtp_snapshots_the_id_under_the_lock(self):
        self.check("onHandsetRtp")


if __name__ == "__main__":
    unittest.main()
