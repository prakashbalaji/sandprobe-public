"""RUN-6: local Docker receiver calibration, no cloud/model/security grade."""
import json
import re
import secrets
import subprocess
import time

from assessment import evaluate
from checks import PROPERTIES

created = []
network = None


def call(args):
    result = subprocess.run(["docker", *args], capture_output=True, timeout=60)
    if result.returncode or len(result.stdout) > 65536:
        raise RuntimeError("local container command failed")
    return result.stdout.decode().strip()


def create(network_id, command, env=None):
    args = ["create", "--network", network_id, "--read-only", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges", "--memory", "256m", "--cpus", "1",
            "--tmpfs", "/tmp:rw,uid=10001,gid=10001,mode=0700,size=16m",
            "--tmpfs", "/workspace:rw,uid=10001,gid=10001,mode=0700,size=16m", "--entrypoint", "python"]
    for name, value in (env or {}).items():
        args += ["-e", name + "=" + value]
    identity = call([*args, "sandprobe-agent-local", "-I", *command])
    if not re.fullmatch(r"[a-f0-9]{64}", identity):
        raise RuntimeError("no immutable container identity")
    created.append(identity)
    call(["start", identity])
    return identity


def attempt(container, address, nonce):
    text = call(["exec", container, "python", "-I", "/opt/sandprobe/checks.py", "--control", address, nonce])
    return json.loads(text)["control"]


try:
    network = call(["network", "create", "--internal", "sandprobe-calibration-" + secrets.token_hex(8)])
    if not re.fullmatch(r"[a-f0-9]{64}", network):
        raise RuntimeError("no immutable network identity")
    nonces = [secrets.token_hex(24) for _ in range(3)]
    receiver = create(network, ["/opt/sandprobe/receiver.py"], {"SANDPROBE_RECEIVER_NONCES": json.dumps(nonces)})
    address = call(["inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", receiver])
    control = create(network, ["-c", "import time;time.sleep(180)"])
    for _ in range(20):
        if attempt(control, address, nonces[0]) == "reported_delivery":
            break
        time.sleep(0.2)
    else:
        raise RuntimeError("local positive control unavailable")
    isolated = create("none", ["-c", "import time;time.sleep(180)"])
    assert attempt(isolated, address, nonces[1]) != "reported_delivery"
    assert attempt(control, address, nonces[2]) == "reported_delivery"
    context = {"run_id": "a"*16, "pod_uid": isolated, "receiver_uid": receiver,
               "image": "local-calibration-image", "config_sha256": "b"*64}
    guest = json.dumps({"schema": "sandprobe.agent-observations/1", "run_id": context["run_id"],
                       "pod_uid": isolated, "config_sha256": context["config_sha256"],
                       "workload": "reported_failed", "task": None,
                       "observations": {key: "unknown" for key in PROPERTIES}})
    def receipts():
        return {"receiver_uid": receiver, "nonces": json.loads(call(["exec", receiver, "python", "-I", "-c",
            "print(open('/tmp/receipts.json').read())"]))["nonces"]}
    result = evaluate(context, guest, receipts(), nonces, False, source="calibration")
    assert result["security_grade"] is None and result["incomplete"]
    assert result["positive_controls"] == "observed"
    # Deliberately unrestricted counterpart must reach the controlled receiver;
    # the classifier must identify delivery without emitting a live AWS grade.
    opened = create(network, ["-c", "import time;time.sleep(180)"])
    assert attempt(opened, address, nonces[1]) == "reported_delivery"
    result = evaluate(context, guest, receipts(), nonces, False, source="calibration")
    assert result["outcome"] == "observed_policy_violation" and result["security_grade"] is None
    assert result["properties"][-1]["outcome"] == "failed"
    print("PASS local refused/allowed receiver calibration; timeout stays incomplete; no provider grade")
finally:
    failures = []
    for identity in reversed(created):
        if subprocess.run(["docker", "rm", "-f", identity], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode:
            failures.append(identity)
    if network and subprocess.run(["docker", "network", "rm", network], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode:
        failures.append(network)
    if failures:
        raise RuntimeError("local calibration cleanup unconfirmed")
