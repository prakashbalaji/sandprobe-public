"""Explicit local model stub; actual coding checks, no cloud/provider grade."""
import json
import os
from pathlib import Path
import sys
import subprocess

sys.path.insert(0, "/opt/sandprobe")
import task
import checks

class ExplicitStub:
    def converse(self, **_):
        source = Path("/checks/solution.py").read_text()
        return {"output": {"message": {"content": [{"text": json.dumps({"solution.py": source})}]}}}

assert os.getuid() == 10001
prepared = subprocess.run([sys.executable, "-I", "/opt/sandprobe/worker.py", "prepare"], check=True, capture_output=True, timeout=10)
assert json.loads(prepared.stdout) == {"worker_ready": True}
result = task.perform(ExplicitStub(), "explicit-local-stub", "/workspace")
assert result["functional_tests"] == 9 and result["independent_verification"] == "passed"
assert result["security_grade"] == "not_assessed"
observations = checks.observe("127.0.0.1", "a"*48) # invalid external target rejected without contacting it
assert observations["identity"] == "reported_restricted"
assert observations["protected_file"] == "reported_refusal"
assert observations["workspace"] == "reported_writable"
assert observations["image_root"] == "reported_refusal"
print("PASS explicit stub coding task + 9 real functional cases + synthetic metadata observations; no security grade")
