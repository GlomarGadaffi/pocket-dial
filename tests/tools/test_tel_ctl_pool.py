"""#657 source gate: a real anchor's makeCall/answerCall/dropCall run on the
tel_ctl pool, created once at boot. asyncMakeCall/asyncAnswerCall/asyncDropCall
must post a job and create no task or thread, the pool's workers are created
only in startTelCtl() (called from the constructor), and a worker never deletes
itself. The device path never runs on the host, so this pins the wiring."""
import os
import re
import unittest

SRC = os.path.join(os.path.dirname(__file__), "..", "..", "src", "SIP", "RequestsHandler.cpp")
CREATE = re.compile(r"\bxTaskCreate\w*\s*\(|\bcreateTaskPreferPsram\s*\(|\bstd::j?thread\b|\bspawnAnchorWorker\s*\(")


def body_of(src, signature):
    start = src.find(signature)
    if start < 0:
        raise AssertionError(signature + " not found")
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


class TelCtlPoolTest(unittest.TestCase):
    def setUp(self):
        with open(SRC, encoding="utf-8") as f:
            self.src = code_only(f.read())

    def test_the_gate_sees_a_per_call_create(self):
        self.assertTrue(CREATE.search("if (pd::createTaskPreferPsram([](void* p) {"))
        self.assertTrue(CREATE.search("spawnAnchorWorker([this, participantId]() {"))
        self.assertFalse(CREATE.search("if (!postTelCtl(job, lane))"))

    def test_the_async_wrappers_post_and_create_nothing(self):
        for fn in ("asyncMakeCall", "asyncAnswerCall", "asyncDropCall"):
            body = body_of(self.src, "RequestsHandler::%s(" % fn)
            found = CREATE.search(body)
            self.assertIsNone(found, "%s must post a job, not create a task per call: %s"
                              % (fn, found.group(0) if found else ""))
            self.assertTrue("postTelCtl(" in body, "positive control: %s posts to the pool" % fn)

    def test_the_per_call_task_names_are_gone(self):
        for name in ("tel_makecall", "tel_dropcall", "tel_answer"):
            self.assertFalse('"%s"' % name in self.src, name + " is no longer a task of its own")

    def test_the_pool_is_created_once_from_the_constructor(self):
        start = body_of(self.src, "void RequestsHandler::startTelCtl(")
        self.assertTrue('"tel_ctl"' in start, "positive control: this is the tel_ctl pool")
        self.assertTrue(CREATE.search(start), "positive control: startTelCtl() creates the workers")
        ctor = body_of(self.src, "RequestsHandler::RequestsHandler(")
        self.assertTrue("startTelCtl();" in ctor, "the constructor starts the pool")
        self.assertEqual(self.src.count("startTelCtl();"), 1, "the constructor is the only caller")

    def test_a_worker_never_deletes_itself(self):
        task = body_of(self.src, "void RequestsHandler::telCtlTask(")
        self.assertTrue("xQueueReceive(" in task, "positive control: the worker loops on its queue")
        self.assertIsNone(re.search(r"\bpd::deleteTask\s*\(|\bvTaskDelete\w*\s*\(", task),
                          "a tel_ctl worker outlives every job")


if __name__ == "__main__":
    unittest.main()
