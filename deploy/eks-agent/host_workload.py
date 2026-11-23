"""RUN-17: host model controller; generated code executes only through the owned pod."""
import hashlib
import json
import os
from pathlib import Path
import sys

from coding import strict
from lifecycle import Failure
from render_profile import IDLE_COMMAND, WORKLOAD_ENVIRONMENT

MODEL = "mistral.ministral-3-3b-instruct"


def controller_environment(runner):
    env = {k: v for k, v in runner.env.items()
           if k not in {"SANDPROBE_CF_TOKEN", "CLOUDFLARE_API_TOKEN", "CF_API_TOKEN", "AWS_ENDPOINT_URL", "AWS_MAX_ATTEMPTS", "AWS_IGNORE_CONFIGURED_ENDPOINT_URLS"}
           and not k.startswith("AWS_ENDPOINT_URL_")}
    env.update(AWS_MAX_ATTEMPTS="1", AWS_IGNORE_CONFIGURED_ENDPOINT_URLS="true")
    return env


def valid_storage(volumes, mounts):
    if (not isinstance(volumes, list) or not isinstance(mounts, list) or len(volumes) != 2 or len(mounts) != 2
            or any(not isinstance(v, dict) or v.get("name") not in ("workspace", "scratch") for v in volumes + mounts)):
        return False
    normalized = [dict(m) for m in mounts]
    for mount in normalized:
        if mount.get("readOnly") is False:
            mount.pop("readOnly")
    return ({v.get("name"): v for v in volumes} == {key: {"name": key, "emptyDir": {"sizeLimit": "64Mi"}} for key in ["workspace", "scratch"]}
            and {m.get("name"): m for m in normalized} == {"workspace": {"name": "workspace", "mountPath": "/workspace"}, "scratch": {"name": "scratch", "mountPath": "/tmp"}})


def model_preflight(runner):
    program = runner.model_python
    if (runner.journal.data.get("model", MODEL) != MODEL or not program
            or not Path(program).is_absolute() or not os.access(program, os.X_OK)):
        raise Failure("host_model_interpreter_required")
    raw = runner.ops.call([program, "-I", str(runner.source_root / "deploy/daytona-agent/model.py"), "identity"],
                          env=controller_environment(runner), timeout=30)
    result = strict(raw.decode(), 4096)
    if result != {"ready": True, "client_version": "1.44.6"}:
        raise Failure("host_model_preflight_failed")


def identity_hash(runner):
    if any(name in runner.journal.data["resources"] for name in ["role", "association"]):
        raise Failure("unexpected_guest_model_identity")
    associations = runner.aws("eks", "list-pod-identity-associations", "--cluster-name", runner.cluster,
                              "--namespace", runner.ns, "--service-account", "model-task", query="associations")
    if associations != []:
        raise Failure("unexpected_guest_model_identity")
    policy = {"identity_mode": "host_controller_no_guest_credentials", "provider": "aws-nitro", "model": MODEL}
    return hashlib.sha256(json.dumps(policy, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def fixture_context(runner, pod):
    script = """import os,stat,json
p='/opt/sandprobe/protected-marker';s=os.lstat(p)
assert stat.S_ISREG(s.st_mode) and s.st_uid==0 and stat.S_IMODE(s.st_mode)==0o400 and s.st_size>0
try:os.lstat('/var/run/secrets/pods.eks.amazonaws.com/serviceaccount/eks-pod-identity-token')
except FileNotFoundError:pass
else:raise RuntimeError('unexpected guest identity projection')
print(json.dumps({'protected_device':s.st_dev,'protected_inode':s.st_ino}))"""
    value = strict(runner.kube("exec", pod, "-n", runner.ns, "--", "python", "-I", "-c", script).decode(), 4096)
    if (set(value) != {"protected_device", "protected_inode"}
            or any(type(v) is not int or not 0 < v < 2**64 for v in value.values())):
        raise Failure("host_controller_fixture_unbound")
    return value


# A literal program, not generated code. No solution bytes are evaluated on the host.
UPLOAD_SOLUTION = """import os,sys,hashlib,stat,json
assert os.getuid()==10001 and os.getgid()==10001
data=sys.stdin.buffer.read(16385)
assert 0<len(data)<=16384
d=os.open('/workspace',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
try:
 name='.host-solution-'+os.urandom(16).hex()
 f=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=d)
 with os.fdopen(f,'wb') as stream:
  stream.write(data);stream.flush();os.fsync(stream.fileno())
 os.replace(name,'solution.py',src_dir_fd=d,dst_dir_fd=d)
 print(json.dumps({'artifact_sha256':hashlib.sha256(data).hexdigest()}))
finally:os.close(d)
"""


def perform(runner, pod, config_sha):
    root = runner.source_root
    status = {"schema": "sandprobe.host-controller/1", "deployment_pattern": "host_controller_no_guest_credentials", "model": MODEL,
              "model_requests": 0, "model_request_count_uncertain": False, "stage": "execution", "step": "worker_prepare"}

    def guest(*args, payload=None):
        return runner.kube("exec", "-i", pod, "-n", runner.ns, "--", *WORKLOAD_ENVIRONMENT, "python", "-I", *args,
                           payload=payload, timeout=90)

    def protocol(mode, value):
        return strict(runner.ops.call([sys.executable, "-I", str(root / "deploy/daytona-agent/controller.py"), mode],
                      payload=json.dumps(value).encode(), env=controller_environment(runner), timeout=20).decode(), 131072)

    observation_script = "import sys,json;sys.path.insert(0,'/opt/sandprobe');import checks;print(json.dumps(checks.observe(sys.argv[1],sys.argv[2])))"
    observations = strict(guest("-c", observation_script, runner.journal.data["receiver_ip"], runner.journal.data["nonces"][1]).decode(), 4096)
    task = None
    try:
        prepared = strict(guest("/opt/sandprobe/worker.py", "prepare").decode(), 4096)
        if prepared != {"worker_ready": True}:
            raise Failure("host_worker_preparation_failed")
        status["step"] = "intended_model_tls"
        address = runner.journal.data["endpoint_resolution"]["ipv4"][0]
        network = strict(guest("/opt/sandprobe/worker.py", "network", address).decode(), 4096)
        if network != {"intended_model_tls": True}:
            raise Failure("intended_model_tls_unavailable")
        previous = {}
        for attempt in range(1, 3):
            status["stage"] = "model_request"
            request = protocol("request", previous)
            status["model_request_count_uncertain"] = True
            raw = runner.ops.call([runner.model_python, "-I", str(root / "deploy/daytona-agent/model.py"), "request"],
                                  payload=json.dumps(request).encode(), env=controller_environment(runner), timeout=150)
            response = strict(raw.decode(), 131072)
            if type(response.get("converse_attempted")) is not bool:
                raise Failure("host_model_count_uncertain")
            status["model_request_count_uncertain"] = False
            status["model_requests"] += int(response["converse_attempted"])
            if set(response) != {"response", "converse_attempted"} or not response["converse_attempted"]:
                raise Failure("host_model_request_failed")
            status["stage"] = "response_format"
            parsed = protocol("parse", response["response"])
            source = parsed["source"].encode()
            if not 0 < len(source) <= 16384:
                raise Failure("host_model_response_invalid")
            digest = hashlib.sha256(source).hexdigest()
            status["stage"] = "artifact_write"
            uploaded = strict(guest("-c", UPLOAD_SOLUTION, payload=source).decode(), 4096)
            if uploaded != {"artifact_sha256": digest}:
                raise Failure("host_artifact_upload_unproven")
            status["stage"] = "functional_checks"
            verified = strict(guest("/opt/sandprobe/worker.py", "verify", digest).decode(), 4096)
            if type(verified.get("functional_tests")) is not int or verified["functional_tests"] != 9 or verified.get("artifact_sha256") != digest:
                raise Failure("host_artifact_verification_unproven")
            diagnostic = protocol("diagnostic", verified)
            fd = os.open(runner.journal.folder / ("functional-attempt-%d.json" % attempt),
                         os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "w") as stream:
                json.dump({"schema":"sandprobe.functional-attempt/1", "attempt":attempt,
                           "artifact_sha256":digest, "diagnostic":diagnostic},stream)
                stream.flush();os.fsync(stream.fileno())
            if verified.get("independent_verification") == "passed":
                task = {"schema": "sandprobe.agent-task/2", "workload": "synthetic-coding-v1",
                        "model_requests": status["model_requests"], "functional_tests": 9, "independent_verification": "passed",
                        "artifact": "/workspace/solution.py", "artifact_sha256": digest, "security_grade": "not_assessed"}
                break
            previous = {"previous": parsed["previous"]}
    except Exception:
        # RUN-19: never persist arbitrary exceptions or guest/provider diagnostics.
        status["failure_code"] = (status["step"] if status["stage"] == "execution" else status["stage"]) + "_failed"
    finally:
        status["completed"] = task is not None
        path = runner.journal.folder / "host-controller-status.json"
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w") as stream:
            json.dump(status, stream); stream.flush(); os.fsync(stream.fileno())
    passed = task is not None
    if not passed:
        task = {"schema": "sandprobe.agent-task-failure/1", "stage": status["stage"]}
    return json.dumps({"schema": "sandprobe.agent-observations/1", "run_id": runner.run_id,
                      "pod_uid": runner.journal.data["context"]["pod_uid"], "config_sha256": config_sha,
                      "workload": "reported_passed" if passed else "reported_failed", "task": task, "observations": observations})
