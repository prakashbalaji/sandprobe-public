#!/usr/bin/env python3
"""RUN-10: one-create managed workload runner; no credentials in records/logs."""
import argparse
import json
import os
from pathlib import Path
import re
import runpy
import secrets
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
# The operator's own AWS profile and account, from the environment. Unset, every account check fails closed.
PROFILE, REGION, ACCOUNT = os.environ.get("SANDPROBE_AWS_PROFILE", ""), "us-west-2", os.environ.get("SANDPROBE_AWS_ACCOUNT", "")
completion_message = runpy.run_path(str(ROOT / "deploy/managed_status.py"))["completion_message"]
SNAPSHOT = "08b45e29-cc9a-40fd-bcf8-511a34c6cb2b"
HOSTNAME = "bedrock-runtime.us-west-2.amazonaws.com"

class Failure(Exception):
    pass

def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()

def persist(path, value):
    raw=encoded(value)+b"\n"
    fd,name=tempfile.mkstemp(prefix=".journal-",dir=path.parent)
    temporary=Path(name)
    try:
        with os.fdopen(fd,"wb") as output:
            output.write(raw)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary,path)
        fd=os.open(path.parent,os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        temporary.unlink(missing_ok=True)

def sanitized_environment():
    env = {k: v for k, v in os.environ.items() if k != "AWS_ENDPOINT_URL" and not k.startswith("AWS_ENDPOINT_URL_")}
    env.update(AWS_IGNORE_CONFIGURED_ENDPOINT_URLS="true", AWS_MAX_ATTEMPTS="1")
    return env

def call(args, env, timeout=90, data=None, allowed_returncodes=(0,)):
    # Private file output avoids inherited pipes defeating the deadline.
    with tempfile.TemporaryFile() as output:
        try:
            process=subprocess.Popen(args,stdin=subprocess.PIPE,stdout=output,
                    stderr=subprocess.DEVNULL,env=env,cwd=ROOT,start_new_session=True)
        except OSError:
            raise Failure("managed_subprocess_failed") from None
        try:
            process.communicate(data,timeout=timeout)
        except (subprocess.TimeoutExpired,KeyboardInterrupt) as problem:
            try:
                os.killpg(process.pid,signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=10)
            if isinstance(problem,KeyboardInterrupt):
                raise
            raise Failure("managed_subprocess_failed") from None
        if process.returncode not in allowed_returncodes:
            raise Failure("managed_subprocess_failed")
        output.seek(0)
        raw=output.read((2 << 20)+1)
        if len(raw)>2 << 20:
            raise Failure("managed_output_limit")
        return raw

def private_key(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        s = os.fstat(stream.fileno())
        if not stat.S_ISREG(s.st_mode) or s.st_uid != os.getuid() or stat.S_IMODE(s.st_mode) & 0o077:
            raise Failure("unsafe_key_file")
        raw = stream.read(8193)
    if len(raw) > 8192:
        raise Failure("unsafe_key_file")
    return raw.decode().strip()

def aws(env, *args):
    return call(["aws", "--profile", PROFILE, "--region", REGION, *args], env)

def sdk(args, env, request):
    # Fresh isolated SDK process: key only on stdin, never argv or environment.
    raw = call([args.sdk_python, "-I", str(ROOT / "internal/host/daytona_runtime.py")],
               {"PATH": env["PATH"], "LANG": "C.UTF-8"}, data=encoded(request))
    return json.loads(raw)

def auth_environment(args, env):
    reference = json.loads(Path(args.dns_reference).read_text())
    if set(reference) != {"secret_id", "zone_id"}:
        raise Failure("invalid_dns_reference")
    bootstrap = os.environ.get("SANDPROBE_AWS_BOOTSTRAP_PROFILE", "")  # the profile that may read the DNS token
    if not bootstrap:
        raise Failure("bootstrap_profile_required")
    token = call(["aws", "--profile", bootstrap, "--region", REGION,
                  "secretsmanager", "get-secret-value", "--secret-id", reference["secret_id"],
                  "--query", "SecretString", "--output", "text"], env).decode().strip()
    env = env.copy()
    env.update(SANDPROBE_CF_TOKEN=token, SANDPROBE_CF_ZONE_ID=reference["zone_id"])
    return env, reference["zone_id"]

def state_values(path):
    values = {}
    if path.is_file():
        for line in path.read_text().splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                values[k] = v
    return values

def verify_receiver(env, original):
    # Independent reads of the exact IDs after the managed teardown, no name deletion.
    checks = {}
    absent_codes = {
        "eip": "InvalidAllocationID.NotFound", "sg": "InvalidGroup.NotFound",
        "volume": "InvalidVolume.NotFound", "role": "NoSuchEntity",
        "iprofile": "NoSuchEntity", "bucket": "404",
    }
    commands = {
        "eip": ["ec2", "describe-addresses", "--allocation-ids"],
        "sg": ["ec2", "describe-security-groups", "--group-ids"],
        "volume": ["ec2", "describe-volumes", "--volume-ids"],
        "role": ["iam", "get-role", "--role-name"],
        "iprofile": ["iam", "get-instance-profile", "--instance-profile-name"],
        "bucket": ["s3api", "head-bucket", "--bucket"],
    }
    if original.get("profile") != PROFILE or original.get("region") != REGION:
        raise Failure("receiver_context_mismatch")
    for key, command in commands.items():
        value = original.get(key)
        if not value:
            continue
        result = subprocess.run(["aws", "--profile", PROFILE, "--region", REGION, *command, value],
                                env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=60)
        # Only a specific service absence is accepted; never generic failure/403.
        checks[key] = result.returncode != 0 and ("(" + absent_codes[key] + ")").encode() in result.stderr
    if original.get("instance"):
        raw = aws(env, "ec2", "describe-instances", "--instance-ids", original["instance"],
                  "--query", "Reservations[].Instances[].State.Name", "--output", "json")
        checks["instance"] = json.loads(raw) == ["terminated"]
    if original.get("zone"):
        rows = json.loads(call(["cf", "dns", "records", "list", "-z", original["zone"],
                                "--name-endswith", original["domain"]], env))
        checks["dns"] = rows == []
    return {"account": ACCOUNT, "region": REGION, "domain": original.get("domain"),
            "checks": checks, "confirmed": bool(checks) and all(checks.values())}

def recover_sandbox(folder, args, env):
    if os.path.lexists(folder / "workspace-volume.state"):
        return recover_persistent(folder, args, env)["boxes_confirmed"]
    cleanup = folder / "sandbox-cleanup.json"
    try:
        if cleanup.is_file() and json.loads(cleanup.read_text()).get("confirmed") is True:
            return True
    except ValueError:
        pass  # A damaged summary never replaces original-ID recovery.
    candidates = list(folder.glob("daytona-*.state"))
    if not candidates and (folder / "owned-sandbox.json").is_file():
        candidates = [folder / "owned-sandbox.json"]
    if not candidates:
        status=folder/"execution-status.json"
        if status.is_file() and json.loads(status.read_text()).get("create_attempted") is False:
            return True
        return not (folder / "sandbox-started.json").exists()
    if len(candidates) != 1:
        return False
    try:
        raw = call([str(folder / "runner"), "--cleanup-state", str(candidates[0]),
                    "--key-file", args.key_file, "--sdk-python", args.sdk_python], env, timeout=240)
        result = json.loads(raw)
        persist(folder / "sandbox-recovery.json", result)
        return result.get("confirmed") is True
    except (Failure, ValueError):
        return False

def recover_persistent(folder, args, env):
    failed = {"boxes_confirmed": False, "storage_confirmed": False, "confirmed": False}
    try:
        raw = call([str(folder / "runner"), "--cleanup-persistent-state", str(folder / "workspace-volume.state"),
                    "--key-file", args.key_file, "--sdk-python", args.sdk_python], env, timeout=480, allowed_returncodes=(0,5))
        result = json.loads(raw)
        ids = result.get("box_ids") if isinstance(result, dict) else None
        if (not isinstance(result, dict) or any(type(result.get(key)) is not bool for key in failed)
                or not isinstance(ids, list) or len(ids)>2
                or any(not isinstance(value,str) or (value and not re.fullmatch(r"[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}",value)) for value in ids)
                or (result["boxes_confirmed"] and any(not value for value in ids))
                or (result["storage_confirmed"] and not result["boxes_confirmed"])
                or result["confirmed"] != (result["boxes_confirmed"] and result["storage_confirmed"])):
            raise ValueError("invalid persistent cleanup result")
        persist(folder / "persistent-recovery.json", result)
        return result
    except (Failure, ValueError):
        return failed

def cleanup_owned(folder, args, env):
    receiver = ROOT / "deploy/canary.sh"
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    # Do not release DNS/IP while an unconfirmed guest can still send traffic.
    if os.path.lexists(folder / "workspace-volume.state"):
        workload = recover_persistent(folder, args, env)
        sandbox_gone, storage_gone = workload["boxes_confirmed"], workload["storage_confirmed"]
    else:
        sandbox_gone, storage_gone = recover_sandbox(folder, args, env), True
    current = state_values(Path(env["STATE"]))
    original = current
    if not original and (folder / "receiver-ownership.json").is_file():
        original = json.loads((folder / "receiver-ownership.json").read_text())
    receiver_gone = not original
    if sandbox_gone and original:
        persist(folder / "receiver-ownership.json", {k: original[k] for k in
                ("profile", "region", "did", "domain", "zone", "instance", "volume", "eip", "sg", "role", "iprofile", "bucket") if k in original})
        try:
            print("Removing the run-owned receiver after sandbox confirmation", flush=True)
            if current:
                call(["bash", str(receiver), "down"], env, timeout=600)
            verified = verify_receiver(env, original)
            persist(folder / "receiver-cleanup.json", verified)
            receiver_gone = verified["confirmed"]
        except (Failure, subprocess.TimeoutExpired, ValueError):
            receiver_gone = False
    cleanup = {"sandbox_confirmed": sandbox_gone, "storage_confirmed": storage_gone, "receiver_confirmed": receiver_gone,
               "confirmed": sandbox_gone and storage_gone and receiver_gone}
    persist(folder / "cleanup.json", cleanup)
    print("Cleanup confirmed: " + str(cleanup["confirmed"]), flush=True)
    return cleanup

def main(args):
    model = getattr(args, "model", "mistral.ministral-3-3b-instruct")
    if model not in {"mistral.ministral-3-3b-instruct", "mistral.ministral-3-8b-instruct"}:
        raise Failure("unsupported_model")
    storage_profile = getattr(args, "storage_profile", "ephemeral")
    if storage_profile not in ("ephemeral", "persistent-workspace", "persistent-artifacts"):
        raise Failure("unsupported_storage_profile")
    parse_hosts = runpy.run_path(str(ROOT / "deploy/workload_measurement.py"))["upload_hosts"]
    approved_hosts = parse_hosts(getattr(args, "upload_hosts", ""))
    env = sanitized_environment()
    env["PATH"] = str(Path(args.go).parent) + os.pathsep + env.get("PATH", "")
    if aws(env, "sts", "get-caller-identity", "--query", "Account", "--output", "text").decode().strip() != ACCOUNT:
        raise Failure("wrong_experiment_account")
    if args.cleanup_run:
        if not re.fullmatch(r"[a-f0-9]{16}", args.cleanup_run):
            raise Failure("invalid_recovery_run")
        folder = Path.home()/".config/sandprobe"/("daytona-workload-"+args.cleanup_run)
        st=folder.lstat()
        if not stat.S_ISDIR(st.st_mode) or stat.S_IMODE(st.st_mode)&0o077 or st.st_uid!=os.getuid():
            raise Failure("unsafe_recovery_folder")
        intent=json.loads((folder/"intent.json").read_text())
        if intent.get("run_id")!=args.cleanup_run or intent.get("account")!=ACCOUNT or intent.get("profile")!=PROFILE or intent.get("region")!=REGION:
            raise Failure("recovery_context_mismatch")
        env["PATH"]=str(folder/"tools")+os.pathsep+env["PATH"]
        env,zone=auth_environment(args,env)
        env.update(PROFILE=PROFILE,REGION=REGION,ZONE="ac0.dev",DOMAIN="daytona-"+args.cleanup_run+".probe.ac0.dev",STATE=str(folder/"canary.state"),DURABLE_STATE="1",SANDPROBE_CANARY_NAME="sandprobe-canary-"+args.cleanup_run)
        state=state_values(folder/"canary.state")
        if state and state.get("zone")!=zone:
            raise Failure("recovery_DNS_scope_mismatch")
        return 0 if cleanup_owned(folder,args,env)["confirmed"] else 5
    model_check=json.loads(call([args.model_python,"-I",str(ROOT/"experiments/daytona-agent/model.py"),"identity"],env,timeout=90))
    if model_check.get("ready") is not True or model_check.get("client_version")!="1.44.6":
        raise Failure("model_client_preflight_failed")
    key = private_key(args.key_file)
    if sdk(args, env, {"op": "available", "key": key}).get("available") is not True:
        raise Failure("provider_access_failed")
    snapshot = sdk(args, env, {"op": "snapshot", "key": key, "snapshot_id": SNAPSHOT})
    if snapshot.get("id") != SNAPSHOT:
        raise Failure("snapshot_binding_failed")
    source = call(["git", "rev-parse", "HEAD"], env).decode().strip()
    if call(["git", "status", "--porcelain"], env).strip():
        raise Failure("source_not_clean")
    run_id = secrets.token_hex(8)
    folder = Path.home() / ".config/sandprobe" / ("daytona-workload-" + run_id)
    folder.mkdir(mode=0o700)
    persist(folder / "intent.json", {"schema": "sandprobe.managed-daytona/1", "run_id": run_id,
            "source_commit": source, "model_client_version":model_check["client_version"], "profile": PROFILE, "region": REGION, "account": ACCOUNT,
            "snapshot_id": SNAPSHOT, "deployment_pattern": "host_controller_no_guest_credentials", "upload_hosts": approved_hosts,
            "storage_profile": storage_profile, "model": model,
            "canary_tcp80_protocol": getattr(args, "canary_tcp80_protocol", "legacy")})
    print("Managed run: " + run_id, flush=True)
    print("Private records: " + str(folder), flush=True)
    tools = folder / "tools"
    tools.mkdir(mode=0o700)
    shutil.copyfile(args.cf_helper, tools / "cf")
    os.chmod(tools / "cf", 0o700)
    env["PATH"] = str(tools) + os.pathsep + env["PATH"]
    call(["make", "probes"], env, timeout=300)
    call([args.go, "build", "-trimpath", "-ldflags", "-X main.sourceCommit=" + source,
          "-o", str(folder / "runner"), "./cmd/sandprobe-daytona-workload"], env, timeout=180)
    env, zone = auth_environment(args, env)
    zones = json.loads(call(["cf", "zones", "list"], env))
    if len(zones) != 1 or zones[0].get("name") != "ac0.dev" or zones[0].get("id") != zone:
        raise Failure("DNS_scope_mismatch")
    network = sorted({v[4][0] for v in socket.getaddrinfo(HOSTNAME, 443, family=socket.AF_INET)})
    if not network or len(network) > 16:
        raise Failure("model_network_resolution_failed")
    persist(folder / "network-policy.json", {"hostname": HOSTNAME, "ipv4": network})
    env.update(PROFILE=PROFILE, REGION=REGION, ZONE="ac0.dev", DOMAIN="daytona-" + run_id + ".probe.ac0.dev",
               STATE=str(folder / "canary.state"), DURABLE_STATE="1", SANDPROBE_CANARY_NAME="sandprobe-canary-" + run_id)
    receiver = ROOT / "deploy/canary.sh"
    failed = False
    try:
        print("Preparing the run-owned receiver", flush=True)
        call(["bash", str(receiver), "up"], env, timeout=900)
        persist(folder / "sandbox-started.json", {"attempted": True})
        print("Starting the single Daytona workload attempt", flush=True)
        call([str(folder / "runner"), "--key-file", args.key_file, "--sdk-python", args.sdk_python,
              "--model-python",args.model_python,"--out", str(folder), "--run-id", run_id, "--snapshot", SNAPSHOT,
              "--network", ",".join(ip + "/32" for ip in network), "--source-root", str(ROOT),
              "--canary-state", env["STATE"], "--upload-hosts", ",".join(approved_hosts),
              "--storage-profile", storage_profile, "--model", model]+(["--canary-tcp80-protocol","tcp80-http-marker-v1"] if getattr(args,"canary_tcp80_protocol","legacy")=="http-v1" else []), env, timeout=1500 if storage_profile != "ephemeral" else 1000)
    except (Failure, KeyboardInterrupt):
        failed = True
        persist(folder / "execution-failure.json", {"category": "managed_execution_incomplete"})
    finally:
        cleanup = cleanup_owned(folder, args, env)
    if failed or not cleanup["confirmed"]:
        # SCR-4: preserve failure/cleanup gates; never infer success from exit5.
        print(completion_message(None, False, cleanup["confirmed"], exit_code=5, execution_ok=False), file=sys.stderr)
        return 5
    evaluation=json.loads((folder/"evaluation.json").read_text())
    assessment=evaluation["configuration_assessment"]
    workload=evaluation["functional_workload"]
    if workload.get("model") != model:
        raise Failure("workload_model_mismatch")
    exposure=evaluation.get("exposure_scorecard",{})
    if (evaluation.get("primary_assessment")!="rc_exposure_scorecard"
            or evaluation.get("managed_run_id")!=run_id or evaluation.get("source_commit")!=source
            or exposure.get("schema")!="sandprobe.workload-exposure/1"
            or exposure.get("run_id")!=assessment.get("run_id") or exposure.get("box_id")!=assessment.get("box_id")
            or type(exposure.get("valid")) is not bool or type(exposure.get("score")) is not int
            or exposure.get("of")!=6 or not 0<=exposure["score"]<=6):
        raise Failure("invalid_exposure_scorecard")
    grade=assessment.get("configuration_grade", "")
    if grade not in ("A","B","C","D","F", ""):
        raise Failure("invalid_assessment_grade")
    print(json.dumps({"primary_assessment":"rc_exposure_scorecard","exposure_scorecard":exposure,
                      "configuration_grade":grade,"complete":assessment.get("complete") is True,
                      "workload_passed":workload.get("independent_verification")=="passed",
                      "functional_tests":workload.get("functional_tests"),"model_requests":workload.get("model_requests"),
                      "model_request_count_uncertain":workload.get("model_request_count_uncertain",False)}))
    if grade in ("D","F"):
        exit_code = 6
    else:
        exit_code = 0 if assessment.get("benchmark_requirements_met") is True and workload.get("independent_verification")=="passed" else 5
    print(completion_message(exposure, workload.get("independent_verification")=="passed", cleanup["confirmed"],
                             assessment, exit_code), file=sys.stderr)
    return exit_code

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--cleanup-run", default="")
    parser.add_argument("--key-file", required=True)
    parser.add_argument("--sdk-python", required=True)
    parser.add_argument("--model-python", required=True)
    parser.add_argument("--go", required=True)
    parser.add_argument("--cf-helper", required=True)
    parser.add_argument("--dns-reference", required=True)
    parser.add_argument("--model", choices=("mistral.ministral-3-3b-instruct", "mistral.ministral-3-8b-instruct"), default="mistral.ministral-3-3b-instruct")
    parser.add_argument("--upload-hosts", default="", help="explicit shipped workload names for TLS-only EGR-6")
    parser.add_argument("--canary-tcp80-protocol", choices=("legacy","http-v1"), default="legacy")
    parser.add_argument("--storage-profile", choices=("ephemeral", "persistent-workspace", "persistent-artifacts"), default="ephemeral")
    args = parser.parse_args()
    if not re.fullmatch(r"[0-9]{12}", ACCOUNT) or not PROFILE:
        raise Failure("aws_account_and_profile_required")
    def interrupted(signum, frame):
        raise KeyboardInterrupt()
    signal.signal(signal.SIGTERM, interrupted)
    try:
        raise SystemExit(main(args))
    except (Failure, OSError, ValueError):
        print("Managed preflight/setup failed; inspect the private run folder if one was created.", file=sys.stderr)
        raise SystemExit(5)
