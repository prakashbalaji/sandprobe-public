"""RUN-18: real Linux host-controller environment, explicit stub and no network."""
from pathlib import Path
import subprocess

from render_profile import WORKLOAD_ENVIRONMENT


root = Path(__file__).resolve().parents[2]
subprocess.run([
    "docker", "run", "--rm", "--network", "none", "--read-only", "--cap-drop", "ALL",
    "--security-opt", "no-new-privileges", "--memory", "256m", "--cpus", "1",
    "--env", "SANDPROBE_TEST_INHERITED_AUTH=synthetic-not-secret",
    "--tmpfs", "/workspace:rw,uid=10001,gid=10001,mode=2770,size=64m",
    "--tmpfs", "/tmp:rw,uid=10001,gid=10001,mode=0700,size=64m",
    "--mount", f"type=bind,src={root}/experiments/eks-agent/container_smoke.py,dst=/checks/smoke.py,readonly",
    "--mount", f"type=bind,src={root}/experiments/eks-agent/fixtures/solution.py,dst=/checks/solution.py,readonly",
    "--entrypoint", WORKLOAD_ENVIRONMENT[0], "sandprobe-agent-local", *WORKLOAD_ENVIRONMENT[1:],
    "python", "-I", "/checks/smoke.py", "--setgid-workspace",
], check=True, timeout=90)
