"""RUN-18: explicit shared environment, never inherited from the controller/image."""
import json
from pathlib import Path


def prefix():
    env = json.loads((Path(__file__).resolve().parents[1] / "internal/host/workload_environment.json").read_text())
    return ["/usr/bin/env", "-i"] + [name + "=" + env[name] for name in sorted(env)]
