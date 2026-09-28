"""#655 review follow-up: a restart held for a live 911/933 says so, once.

Both deferred-restart tasks (factory reset, OTA reboot) wait while an emergency
call is live. The wait has no upper bound, so each must log once when it starts
holding, before its wait loop, or an operator sees an erased board that never
reboots and no reason why. ESP-only code, so this pins the source."""
import os
import re
import unittest

ROOT = os.path.join(os.path.dirname(__file__), "..", "..", "src", "Helpers")


def code(path):
    return re.sub(r"//[^\n]*", "", open(os.path.join(ROOT, path), encoding="utf-8").read())


def task_body(src, task_name):
    """The lambda body of the xTaskCreate whose task name is `task_name`."""
    for m in re.finditer(r"xTaskCreate\(\[\]\(void\* h\) \{(.*?)\n\t\}, \"(\w+)\"", src, re.S):
        if m.group(2) == task_name:
            return m.group(1)
    return None


class RestartHeldLogTest(unittest.TestCase):
    def check(self, task_name, fn):
        src = code("HttpServer.cpp")
        m = re.search(r"void HttpServer::" + fn + r"\(.*?\n\}", src, re.S)
        self.assertIsNotNone(m, fn + " not found")
        body = task_body(m.group(0), task_name)
        # positive control: the task still waits on the emergency check
        self.assertIsNotNone(body, task_name + " task not found in " + fn)
        self.assertIn("hasLiveEmergencyCall()", body)
        self.assertIn("esp_restart()", body)
        held = body.find("restart held: emergency call in progress")
        self.assertNotEqual(held, -1, task_name + " holds the restart without logging why")
        self.assertLess(held, body.find("vTaskDelay(pdMS_TO_TICKS(1000));\n\t\t\twhile"),
                        task_name + " logs inside the wait loop, not once before it")

    def test_factory_reset_restart_logs_once_when_held(self):
        self.check("restart_task", "sendApiFactoryReset")

    def test_ota_reboot_logs_once_when_held(self):
        self.check("ota_reboot", "sendApiOtaReboot")


if __name__ == "__main__":
    unittest.main()
