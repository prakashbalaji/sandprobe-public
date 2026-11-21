import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from calibration_summary import CASES, CalibrationFailure, summarize


def events():
    result = []
    for case in CASES:
        test = "TestFixtures/" + case
        result.append({"Test": test, "Action": "run"})
        if case != "broken-arch":
            grade, complete = {"clean": ("A", "true"), "holes": ("F", "true"),
                               "net-canary-down": ("C", "false")}[case]
            result.append({"Test": test, "Action": "output",
                           "Output": f"fixtures_test.go:432: grade {grade} complete={complete} unknown=[]"})
        result.append({"Test": test, "Action": "pass"})
    result.append({"Test": "TestFixtures", "Action": "pass"})
    for event in result:
        event["Package"] = "sandprobe/internal/host"
    return result


def encode(items):
    return b"\n".join(json.dumps(item).encode() for item in items)


class CalibrationSummaryTest(unittest.TestCase):
    def test_complete(self):
        result = summarize(encode(events()))
        self.assertEqual([row["legacy_grade"] for row in result], ["A", "F", "C", None])

    def test_fail_closed(self):
        original = events()
        cases = [[], original[:-1], original[1:], original + [original[0]],
                 original + [{"Package": "sandprobe/internal/host", "Action": "fail"}],
                 original + [{"Package": "sandprobe/internal/host", "Action": "skip"}],
                 [dict(item, Package="other") for item in original],
                 [item for item in original if item.get("Action") != "output"]]
        for items in cases:
            with self.subTest(items=len(items)), self.assertRaises(ValueError):
                summarize(encode(items))

    def test_no_raw_output(self):
        items = events()
        items.insert(0, {"Package": "sandprobe/internal/host", "Action": "output",
                         "Output": "DO_NOT_PUBLISH_FAKE_VALUE"})
        self.assertNotIn("DO_NOT_PUBLISH", json.dumps(summarize(encode(items))))

    def test_wrong_or_duplicate_grade(self):
        for replacement in ["grade F complete=true unknown=[]", "grade A complete=false unknown=[]"]:
            items = events()
            items[1]["Output"] = replacement
            with self.assertRaises(ValueError):
                summarize(encode(items))
        items = events()
        items.insert(2, items[1])
        with self.assertRaises(ValueError):
            summarize(encode(items))

    def test_failed_control_has_safe_check_hint(self):
        items = events()
        items.insert(1, {"Package": "sandprobe/internal/host", "Test": "TestFixtures/clean", "Action": "output",
                         "Output": "fixtures_test.go:10: EGR-2: want pass, got DO_NOT_LEAK_SECRET"})
        items[3]["Action"] = "fail"
        with self.assertRaises(CalibrationFailure) as failure:
            summarize(encode(items))
        self.assertEqual(failure.exception.control, "clean")
        self.assertEqual(failure.exception.checks, ["EGR-2"])
        self.assertNotIn("DO_NOT_LEAK", str(failure.exception))

    def test_script_separates_stderr_and_rejects_nonzero_command(self):
        script = Path(__file__).with_name("calibration.sh").resolve()
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            event_path = work / "events.json"
            event_path.write_bytes(encode(events()))
            for name, contents in {
                "docker": "#!/bin/sh\nexit 0\n",
                "go": '#!/bin/sh\ncat "$SANDPROBE_CALIBRATION_TEST_EVENTS"\nprintf "go: downloading DO_NOT_LEAK_STDERR\\n" >&2\nexit "${SANDPROBE_CALIBRATION_TEST_EXIT:-0}"\n',
            }.items():
                path = work / name
                path.write_text(contents)
                path.chmod(0o700)
            env = dict(os.environ, PATH=directory + os.pathsep + os.environ["PATH"],
                       SANDPROBE_CALIBRATION_TEST_EVENTS=str(event_path))
            for status in ("0", "1"):
                with self.subTest(status=status):
                    env["SANDPROBE_CALIBRATION_TEST_EXIT"] = status
                    result = subprocess.run(["sh", str(script)], env=env, capture_output=True, text=True, timeout=10)
                    self.assertEqual(result.returncode, int(status))
                    self.assertNotIn("DO_NOT_LEAK", result.stdout + result.stderr)
                    if status == "0":
                        self.assertEqual(len(json.loads(result.stdout)["cases"]), 4)
                    else:
                        self.assertEqual(result.stdout, "")
                        self.assertIn("go_command_failed", result.stderr)


if __name__ == "__main__":
    unittest.main()
