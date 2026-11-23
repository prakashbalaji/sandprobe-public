"""RUN-3/4: production Job entrypoint; guest claims are never trusted passes."""
import json
import os
from pathlib import Path
import sys
import time
import stat

sys.path.insert(0, str(Path(__file__).resolve().parent))
import checks
import task

try:
    Path('/workspace/.cache').mkdir(mode=0o700,exist_ok=True)
    # RUN-2: do not call the model/run generated code until host verification.
    release = Path("/workspace/.host-release")
    deadline = time.monotonic() + 1200
    while time.monotonic() < deadline:
        try:
            fd = os.open(release, os.O_RDONLY | os.O_NOFOLLOW)
            with os.fdopen(fd, "r") as marker:
                if not stat.S_ISREG(os.fstat(marker.fileno()).st_mode) or marker.read(65) != os.environ["SANDPROBE_RUN_ID"]:
                    raise ValueError()
            break
        except FileNotFoundError:
            time.sleep(1)
    else:
        raise TimeoutError()
    observations = checks.observe(os.environ["SANDPROBE_RECEIVER_IP"], os.environ["SANDPROBE_AGENT_NONCE"])
    failure_stage = "client_initialization"
    try:
        client = task.make_client()
        failure_stage = "execution"
        result = task.perform(client, os.environ["SANDPROBE_MODEL_ID"], "/workspace",home='/opt/sandprobe/home')
        workload = "reported_passed"
    except Exception as error:
        result, workload = task.failure_document(error, failure_stage), "reported_failed"
    print(json.dumps({"schema": "sandprobe.agent-observations/1", "run_id": os.environ["SANDPROBE_RUN_ID"],
                      "pod_uid": os.environ["SANDPROBE_POD_UID"], "config_sha256": os.environ["SANDPROBE_CONFIG_SHA256"],
                      "workload": workload, "task": result, "observations": observations}, sort_keys=True), flush=True)
    # RUN-8: preserve this exact workload container/process for standard grading.
    # The host deletes the original Job after collection; this bound covers host loss.
    time.sleep(600)
except Exception:
    print('{"schema":"sandprobe.agent-observations/1","error":"workload execution failed"}')
    sys.exit(1)
