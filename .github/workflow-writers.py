"""REL-3: the only thing in any workflow that may write contents is the release workflow's publish job.

Parses every workflow (.yml and .yaml) as YAML, anchors and aliases resolved, and lists each place that grants
contents write: a workflow's or a job's `permissions` equal to `write-all`, or with `contents: write`. It exits 0 only
when that list is exactly the release workflow's publish job. A workflow that doesn't parse fails the check.
"""
import glob
import sys

import yaml


def writes(p):
    if isinstance(p, str):
        return p.strip().lower() == "write-all"
    if isinstance(p, dict):
        return str(p.get("contents", "")).strip().lower() == "write"
    return False


found = []
for f in sorted(glob.glob(".github/workflows/*.yml") + glob.glob(".github/workflows/*.yaml")):
    with open(f) as fh:
        d = yaml.safe_load(fh) or {}
    if not isinstance(d, dict):
        sys.exit(f"{f}: not a workflow")
    if writes(d.get("permissions")):
        found.append(f"{f}: the whole workflow")
    for name, job in (d.get("jobs") or {}).items():
        if isinstance(job, dict) and writes(job.get("permissions")):
            found.append(f"{f}: job {name}")
print("contents writers:", found)
sys.exit(0 if found == [".github/workflows/release.yml: job publish"] else 1)
