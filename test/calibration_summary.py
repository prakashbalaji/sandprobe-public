"""CAL-6: fixed synthetic-control summary, never raw probe/test output."""

import json
import re
import sys

CASES = ("clean", "holes", "net-canary-down", "broken-arch")
GRADE = re.compile(r"\bgrade ([ABCDF]) complete=(true|false) unknown=")
LIMIT = 8 << 20
CHECK_FAILURE = re.compile(r"\b(SEC-[1-5]|EGR-[1-6](?:\.(?:22|80|8080|53u))?|PER-[1-5]|AMP-[1-8](?:\.(?:sys|blk))?)(?:: (?:want|unknown|a finding|a two-sided)| should | with the canary down:)")
CHECK_IDS = frozenset("SEC-1 SEC-2 SEC-3 SEC-4 SEC-5 EGR-1 EGR-2 EGR-3 EGR-4 EGR-5.22 EGR-5.80 EGR-5.8080 EGR-5.53u EGR-6 PER-1 PER-2 PER-3 PER-4 PER-5 AMP-1 AMP-2 AMP-3 AMP-4 AMP-5 AMP-6 AMP-7 AMP-8.sys AMP-8.blk".split())


class CalibrationFailure(ValueError):
    def __init__(self, code, control="", checks=()):
        super().__init__(code)
        self.code = code
        self.control = control if control in CASES else ""
        self.checks = sorted(set(checks) & CHECK_IDS)


def summarize(data):
    if len(data) > LIMIT:
        raise CalibrationFailure("oversize_events")
    started, passed, grades, check_hints = set(), set(), {}, {}
    parent_passed = False
    for line in data.splitlines():
        event = json.loads(line)
        if not isinstance(event, dict):
            raise CalibrationFailure("invalid_event")
        test, action = event.get("Test", ""), event.get("Action", "")
        if event.get("Package") != "sandprobe/internal/host":
            raise CalibrationFailure("wrong_package")
        known_case = test.removeprefix("TestFixtures/") if isinstance(test, str) else ""
        if action in ("fail", "skip"):
            raise CalibrationFailure("control_failed" if action == "fail" else "control_skipped",
                                     known_case, check_hints.get(known_case, ()))
        if test == "TestFixtures" and action == "pass":
            parent_passed = True
        if not isinstance(test, str) or not test.startswith("TestFixtures/"):
            continue
        case = test.removeprefix("TestFixtures/")
        if case not in CASES:
            raise CalibrationFailure("unexpected_control")
        if action == "run":
            if case in started:
                raise CalibrationFailure("duplicate_control", case)
            started.add(case)
        elif action == "pass":
            if case not in started or case in passed:
                raise CalibrationFailure("invalid_completion", case)
            passed.add(case)
        elif action == "output":
            check_hints.setdefault(case, set()).update(CHECK_FAILURE.findall(event.get("Output", "")))
            match = GRADE.search(event.get("Output", ""))
            if match:
                if case in grades:
                    raise CalibrationFailure("duplicate_grade", case)
                grades[case] = (match[1], match[2] == "true")
    for case in CASES:
        if case not in started or case not in passed:
            raise CalibrationFailure("missing_control", case)
    if not parent_passed:
        raise CalibrationFailure("missing_parent_pass")
    if set(grades) != set(CASES) - {"broken-arch"}:
        raise CalibrationFailure("missing_or_unexpected_grade")
    for case, correct in (("clean", grades["clean"] == ("A", True)),
                          ("holes", grades["holes"][0] == "F"),
                          ("net-canary-down", not grades["net-canary-down"][1])):
        if not correct:
            raise CalibrationFailure("incorrect_control_outcome", case)
    return [{"control": case, "legacy_grade": grades.get(case, (None, None))[0],
             "selected_complete": grades.get(case, (None, None))[1], "executed_and_passed": True}
            for case in CASES]


def main():
    try:
        if len(sys.argv) not in (2, 3) or (len(sys.argv) == 3 and sys.argv[2] != "--command-failed"):
            raise ValueError("usage")
        with open(sys.argv[1], "rb") as stream:
            data = stream.read(LIMIT + 1)
        cases = summarize(data)
        if len(sys.argv) == 3:
            raise CalibrationFailure("go_command_failed")
    except CalibrationFailure as error:
        detail = {"error": error.code}
        if error.control:
            detail["control"] = error.control
        if error.checks:
            detail["check_hints"] = error.checks
        print(json.dumps(detail), file=sys.stderr)
        return 1
    except (OSError, ValueError, TypeError, AttributeError):
        print("Calibration controls failed or were incomplete; no successful calibration recorded.", file=sys.stderr)
        return 1
    print(json.dumps({"schema": "sandprobe.synthetic-calibration/1", "source": "executed_local_docker_controls",
                      "limits": "Synthetic fixtures, not provider grades or an attestation. Find-only no-finding is not refusal.",
                      "cases": cases}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
