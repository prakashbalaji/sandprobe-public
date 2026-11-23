"""RUN-3: bounded model -> file -> independent outputs -> optional repair."""
import hashlib
import json
import os
from pathlib import Path
import resource
import re
import signal
import subprocess
import sys
import tempfile

PROMPT = '''Implement solution.py for a small CSV inventory project. Return only one JSON object
with exactly one key "solution.py" containing the complete Python source, without markdown.
Export summarize_csv(text): parse CSV with exactly the header item,quantity; strip item whitespace;
aggregate integer quantities by item and return a dict of integer totals. Quoted CSV fields work.
Empty data with the valid header returns {}. Raise ValueError for missing/wrong headers, blank
items, noninteger or negative quantities, missing/extra columns. Use only the Python standard
library. Do not execute shell commands, access the network, or read unrelated files.'''
CASES = [
    ("item,quantity\napple,2\npear,3\napple,5\n", {"ok": {"apple": 7, "pear": 3}}),
    ("item,quantity\n", {"ok": {}}),
    ('item,quantity\n"red, apple",2\n', {"ok": {"red, apple": 2}}),
    ("item,quantity\n pear ,0\npear,3\n", {"ok": {"pear": 3}}),
    ("name,quantity\napple,2\n", {"error": "ValueError"}),
    ("item,quantity\n,2\n", {"error": "ValueError"}),
    ("item,quantity\napple,1.5\n", {"error": "ValueError"}),
    ("item,quantity\napple,-1\n", {"error": "ValueError"}),
    ("item,quantity\napple,2,extra\n", {"error": "ValueError"}),
]


class TaskFailure(Exception):
    pass


FAILURE_STAGES = frozenset({"client_initialization", "model_request", "response_format", "artifact_write",
                            "functional_checks", "execution"})


def failure_document(error, default="execution"):
    # MOD-5: only source-literal categories, never arbitrary SDK/model text.
    stage = str(error) if isinstance(error, TaskFailure) else default
    if stage not in FAILURE_STAGES:
        stage = default
    return {"schema": "sandprobe.agent-task-failure/1",
            "stage": stage if stage in FAILURE_STAGES else "execution"}


def converse_request(model_id, messages):
    request = {"modelId": model_id, "messages": messages,
               "inferenceConfig": {"maxTokens": 2048, "temperature": 0}}
    if model_id == "mistral.ministral-3-3b-instruct":
        # MOD-4: provider grammar enforcement supplements the strict local parser.
        schema = {"type": "object", "properties": {"solution.py": {"type": "string"}},
                  "required": ["solution.py"], "additionalProperties": False}
        request["outputConfig"] = {"textFormat": {"type": "json_schema", "structure": {"jsonSchema": {
            "name": "sandprobe_solution", "schema": json.dumps(schema, sort_keys=True, separators=(",", ":"))}}}}
    return request


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError()
        result[key] = value
    return result


def strict(text, limit=16384):
    if not isinstance(text, str) or len(text.encode("utf-8")) > limit:
        raise ValueError()
    return json.loads(text, object_pairs_hook=unique_object,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))


def model_document(text):
    # MOD-2: bound raw bytes before any whitespace/envelope normalization.
    if not isinstance(text, str) or len(text.encode("utf-8")) > 16384:
        raise ValueError()
    text = text.strip()
    envelope = re.fullmatch(r"```(?:json)?\r?\n(.*)\r?\n```", text, re.DOTALL)
    return strict(envelope.group(1) if envelope else text)


def child_limits():
    resource.setrlimit(resource.RLIMIT_FSIZE, (32768, 32768))
    resource.setrlimit(resource.RLIMIT_CPU, (3, 3))
    resource.setrlimit(resource.RLIMIT_AS, (256 << 20, 256 << 20))


DIAGNOSTIC_KEYS = {"schema", "failure_kind", "outputs_complete", "matched_cases", "expected_cases", "failed_case_ids"}
DIAGNOSTIC_FAILURES = {"passed", "case_mismatch", "checker_setup_failed", "artifact_unverified", "dependency_error", "syntax_error", "memory_error", "execution_error", "child_failed", "deadline", "invalid_output"}


def validated_verification_diagnostic(value):
    # RUN-22: whitelist data, never return an exception, candidate output or source.
    if not isinstance(value, dict) or set(value) != {"functional_tests", "independent_verification", "artifact_sha256", "diagnostics"}:
        raise ValueError("invalid functional diagnostic")
    d = value["diagnostics"]
    if (not isinstance(d, dict) or set(d) != DIAGNOSTIC_KEYS
            or d["schema"] != "sandprobe.functional-diagnostic/1" or not isinstance(d["failure_kind"], str) or d["failure_kind"] not in DIAGNOSTIC_FAILURES
            or type(d["outputs_complete"]) is not bool or type(d["matched_cases"]) is not int
            or type(d["expected_cases"]) is not int or d["expected_cases"] != len(CASES)
            or not isinstance(d["failed_case_ids"], list) or len(d["failed_case_ids"]) > len(CASES)
            or any(type(i) is not int or not 1 <= i <= len(CASES) for i in d["failed_case_ids"])):
        raise ValueError("invalid functional diagnostic")
    ids = d["failed_case_ids"]
    if ids != sorted(set(ids)):
        raise ValueError("invalid functional diagnostic")
    if d["failure_kind"] in {"passed", "case_mismatch"}:
        consistent = (d["outputs_complete"] and d["matched_cases"] == len(CASES) - len(ids)
                      and (d["failure_kind"] == "passed") == (not ids))
    else:
        consistent = not d["outputs_complete"] and d["matched_cases"] == 0 and not ids
    if (not consistent or type(value["functional_tests"]) is not int or value["functional_tests"] != len(CASES)
            or not isinstance(value["independent_verification"], str) or value["independent_verification"] not in {"passed", "failed"}
            or (value["independent_verification"] == "passed") != (d["failure_kind"] == "passed")
            or not isinstance(value["artifact_sha256"], str) or not re.fullmatch("[a-f0-9]{64}", value["artifact_sha256"])):
        raise ValueError("invalid functional diagnostic")
    return {**d, "failed_case_ids": list(ids)}


def functional_checks(workspace, source_sha=None, *, home=None, diagnostics=None):
    # Production invokes this inside the Job only, never in the host runner.
    def finish(kind, matched=0, failed=None, complete=False):
        if diagnostics is not None:
            diagnostics.clear()
            diagnostics.update(schema="sandprobe.functional-diagnostic/1", failure_kind=kind,
                               outputs_complete=complete, matched_cases=matched,
                               expected_cases=len(CASES), failed_case_ids=list(failed or []))
        return kind == "passed"
    try:
        if source_sha is None: # Known local calibration fixtures only.
            fd = os.open(Path(workspace) / "solution.py", os.O_RDONLY | os.O_NOFOLLOW)
            with os.fdopen(fd, "rb") as source:
                source_sha = hashlib.sha256(source.read(16385)).hexdigest()
        with tempfile.TemporaryFile() as output:
            process = subprocess.Popen(
                [sys.executable, "-I", str(Path(__file__).with_name("project_exec.py")),
                 str(Path(workspace) / "solution.py"), source_sha], cwd=workspace,
                env={"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": str(home if home is not None else workspace),
                     "XDG_CACHE_HOME":str(Path(workspace)/'.cache'),
                     "LANG": "C.UTF-8", "PYTHONDONTWRITEBYTECODE": "1"},
                stdin=subprocess.PIPE, stdout=output, stderr=subprocess.DEVNULL,
                start_new_session=True, preexec_fn=child_limits)
            try:
                process.communicate(json.dumps([c[0] for c in CASES]).encode(), timeout=5)
            except subprocess.TimeoutExpired:
                return finish("deadline")
            finally:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait()
            if process.returncode != 0:
                return finish({20:"artifact_unverified", 21:"dependency_error", 22:"syntax_error",
                               23:"memory_error", 24:"execution_error"}.get(process.returncode, "child_failed"))
            output.seek(0)
            try:
                actual = strict(output.read(32769).decode(), 32768)
                if not isinstance(actual, list) or len(actual) != len(CASES):
                    return finish("invalid_output")
                canonical = lambda item: json.dumps(item, sort_keys=True, allow_nan=False)
                failed = [i + 1 for i, (got, case) in enumerate(zip(actual, CASES)) if canonical(got) != canonical(case[1])]
                return finish("case_mismatch" if failed else "passed", len(CASES)-len(failed), failed, True)
            except (ValueError, UnicodeError, TypeError):
                return finish("invalid_output")
    except (OSError, subprocess.SubprocessError):
        return finish("checker_setup_failed")


def perform(client, model_id, workspace, *, home=None):
    messages = [{"role": "user", "content": [{"text": PROMPT}]}]
    path = Path(workspace) / "solution.py"
    identity = None
    for attempt in range(1, 3):
        stage = "model_request"
        try:
            response = client.converse(**converse_request(model_id, messages))
            stage = "response_format"
            blocks = response["output"]["message"]["content"]
            if len(blocks) != 1 or set(blocks[0]) != {"text"}:
                raise ValueError()
            text = blocks[0]["text"]
            document = model_document(text)
            if (not isinstance(document, dict) or set(document) != {"solution.py"}
                    or not isinstance(document["solution.py"], str) or not document["solution.py"]):
                raise ValueError()
            source = document["solution.py"].encode("utf-8")
            if len(source) > 16384:
                raise ValueError()
            stage = "artifact_write"
            flags = os.O_WRONLY | os.O_NOFOLLOW
            if identity is None:
                flags |= os.O_CREAT | os.O_EXCL
            else:
                current = path.lstat()
                if (current.st_dev, current.st_ino) != identity:
                    raise ValueError()
            fd = os.open(path, flags, 0o600)
            with os.fdopen(fd, "wb") as artifact:
                current = os.fstat(artifact.fileno())
                if identity is not None and (current.st_dev, current.st_ino) != identity:
                    raise ValueError()
                identity = (current.st_dev, current.st_ino)
                artifact.truncate(0)
                artifact.write(source)
        except Exception:
            raise TaskFailure(stage) from None
        if functional_checks(workspace, hashlib.sha256(source).hexdigest(), home=home):
            return {"schema": "sandprobe.agent-task/2", "workload": "synthetic-coding-v1",
                    "model_requests": attempt, "functional_tests": len(CASES),
                    "independent_verification": "passed", "artifact": "/workspace/solution.py",
                    "artifact_sha256": hashlib.sha256(source).hexdigest(),
                    "security_grade": "not_assessed"}
        messages.extend([{"role": "assistant", "content": [{"text": text}]},
                         {"role": "user", "content": [{"text": "The fixed functional checks failed. Return corrected solution.py JSON only."}]}])
    raise TaskFailure("functional_checks")
