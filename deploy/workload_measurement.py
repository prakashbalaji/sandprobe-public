"""MEAS-6: shared, offline managed-runner workload-host selection."""
import json
from pathlib import Path


def upload_hosts(value):
    allowed = json.loads((Path(__file__).resolve().parents[1] / "internal/catalog/upload_hosts.json").read_text())
    if not isinstance(value, str):
        raise ValueError("invalid workload host selection")
    hosts = value.split(",") if value else []
    if len(hosts) > 4 or len(hosts) != len(set(hosts)) or any(h not in allowed for h in hosts):
        raise ValueError("invalid workload host selection")
    return hosts
