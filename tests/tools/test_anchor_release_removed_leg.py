"""#1103: when #1095's post-bind backstop finds that 3CX already removed our leg, the
leg is freed locally (tombstoned, media stopped) with no drop POST. A drop POST
holds _ctrlMutex for its round trip and answerCall() waits on that mutex, so a PSAP
callback answered meanwhile would queue behind a request 3CX refuses (403).
TelephonyAnchorClient's ESP arm is not compiled on the host, so this pins it."""
import os
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
        return code_only(f.read())


class AnchorReleaseRemovedLegTest(unittest.TestCase):
    longMessage = False

    def setUp(self):
        self.client = read("TelephonyAnchorClient.cpp")
        self.handler = read("RequestsHandler.cpp")
        self.run_tel_ctl = body_of(self.handler, "void RequestsHandler::runTelCtl(")

    def release(self):
        sig = "void TelephonyAnchorClient::releaseRemovedLeg("
        self.assertEqual(self.client.count(sig), 2, "a host stub and the ESP arm")
        return body_of(self.client, sig)

    def test_the_esp_release_tombstones_then_stops_media_and_never_posts(self):
        body = self.release()
        lock = body.find("std::lock_guard<std::mutex> lock(_mutex);")
        tomb = body.find("_droppedLegs.add(ownLeg);")
        stop = body.find("stopMediaStreams(ownLeg);")
        self.assertNotEqual(lock, -1, "the tombstone is written under the anchor's _mutex")
        self.assertNotEqual(tomb, -1, "the leg is tombstoned (#554: no late upsert re-keys it)")
        self.assertNotEqual(stop, -1, "the slot makeCall() keyed is freed")
        self.assertLess(lock, tomb)
        self.assertLess(tomb, stop, "tombstone first, then free the slot (#554 (b))")
        for word in ("performCtrl", "_ctrlMutex", "http", "/drop", "dropCall", "new ", "vTaskDelay"):
            self.assertNotIn(word, body, "a local release only, no request: " + word)

    def test_run_tel_ctl_runs_the_release_job_with_no_request(self):
        rel = self.run_tel_ctl.find("if (job.kind == TelCtlJob::Release)")
        self.assertNotEqual(rel, -1, "runTelCtl must run the Release job")
        branch = self.run_tel_ctl[rel:self.run_tel_ctl.index("return;", rel)]
        self.assertIn("_anchorClient->releaseRemovedLeg(job.partId);", branch)
        self.assertNotIn("dropCall", branch)
        self.assertNotIn("_mutex", branch, "called with no engine lock held (it may join the rx task)")

    def test_the_backstop_releases_on_tel_drop_instead_of_dropping(self):
        bind = self.run_tel_ctl.find("bindOutboundParticipant(job.callId, ownLeg)")
        hit = self.run_tel_ctl.find("if (removedBeforeBind)", bind)
        orphan = self.run_tel_ctl.find("else if (!bound && !ownLeg.empty())", hit)
        self.assertNotEqual(hit, -1, "positive control: the #1095 backstop branch")
        self.assertNotEqual(orphan, -1, "positive control: the #379 branch follows it")
        branch = self.run_tel_ctl[hit:orphan]
        self.assertIn("anchorDroppedLocked(ownLeg);", branch, "the caller is still failed")
        self.assertIn("asyncReleaseRemovedLeg(ownLeg);", branch, "the removed leg is freed locally")
        self.assertNotIn("asyncDropCall", branch, "no drop POST to a leg 3CX already removed")
        self.assertNotIn("releaseRemovedLeg(ownLeg)", branch.replace("asyncReleaseRemovedLeg(ownLeg)", ""),
                         "not called inline under the engine's _mutex")
        self.assertIn("asyncDropCall(ownLeg);", self.run_tel_ctl[orphan:],
                      "positive control: the #379 orphan, still live on 3CX, is still dropped")

    def test_the_async_release_posts_to_tel_drop(self):
        body = body_of(self.handler, "void RequestsHandler::asyncReleaseRemovedLeg(")
        self.assertIn("new TelCtlJob{ TelCtlJob::Release, {}, {}, {}, participantId }, kLaneDrop", body,
                      "tel_drop: the stream join never runs on tel_sos or tel_ctl")
        self.assertNotIn("kLaneSos", body)
        self.assertNotIn("dropCall", body)


if __name__ == "__main__":
    unittest.main()
