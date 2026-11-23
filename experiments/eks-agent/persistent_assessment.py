"""RUN-23: managed native artifacts and exact-identity child reset recovery."""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import stat

from coding import strict
from lifecycle import Failure
from persistent_storage import EBSWorkspace
from render_profile import WORKLOAD_ENVIRONMENT, render


def enabled(runner):
    return getattr(runner, "storage_profile", "ephemeral") == "persistent-artifacts"


def install(runner, receiver_ns, receiver_uid):
    if not enabled(runner):
        raise Failure("persistent_profile_required")
    if runner.scalar("pod", "receiver", "{.metadata.uid}", receiver_ns) != receiver_uid:
        raise Failure("persistent_receiver_identity_changed")
    node = runner.scalar("pod", "receiver", "{.spec.nodeName}", receiver_ns)
    if not re.fullmatch(r"[a-z0-9.-]+", node):
        raise Failure("persistent_receiver_node_invalid")
    zone = runner.scalar("node", node, "{.metadata.labels.topology\\.kubernetes\\.io/zone}")
    volume = EBSWorkspace(runner).create(zone)
    plan = render(runner.run_id, runner.image, runner.account_id, runner.journal.data["model"],
                  runner.journal.data["endpoint_resolution"]["ipv4"], runner.journal.data["dns_address"],
                  controller="host", storage_profile="persistent-artifacts", workspace_volume=volume)
    for resource in plan["kubernetes"]["items"]:
        if resource["kind"] in {"StorageClass", "PersistentVolume", "PersistentVolumeClaim"}:
            runner.create(resource)
    binding(runner, require_bound=False)
    return plan


def binding(runner, require_bound=True):
    resources = runner.journal.data["resources"]
    def uid(kind, name, namespace=""):
        record = resources.get(f"kube:{kind}:{namespace}:{name}", {})
        value = record.get("uid", "")
        if record.get("status") != "created" or not re.fullmatch(r"[a-f0-9-]{16,64}", value):
            raise Failure("persistent_storage_creator_identity_missing")
        if runner.scalar(kind, name, "{.metadata.uid}", namespace or None) != value:
            raise Failure("persistent_storage_creator_identity_changed")
        return value
    volume = EBSWorkspace(runner).read()
    name = "sandprobe-artifacts-" + runner.run_id
    result = {"storage_profile": "persistent-artifacts", "namespace_uid": uid("Namespace", runner.ns),
              "claim_uid": uid("PersistentVolumeClaim", "artifacts", runner.ns),
              "pv_uid": uid("PersistentVolume", name), "class_uid": uid("StorageClass", name),
              "volume_id": volume["id"], "zone": volume["zone"]}
    # Check the actual sources before scheduling, then require binding before
    # artifact/model release. Creator UIDs alone do not establish configuration.
    checks = [("PersistentVolume", name, "{.spec.csi}", None,
               {"driver": "ebs.csi.eks.amazonaws.com", "volumeHandle": volume["id"], "fsType": "ext4"}),
              ("PersistentVolume", name, "{.spec.nodeAffinity}", None,
               {"required": {"nodeSelectorTerms": [{"matchExpressions": [{"key": "topology.kubernetes.io/zone", "operator": "In", "values": [volume["zone"]]}]}]}}),
              ("PersistentVolume", name, "{.spec.accessModes}", None, ["ReadWriteOncePod"]),
              ("PersistentVolumeClaim", "artifacts", "{.spec.volumeName}", runner.ns, name),
              ("PersistentVolumeClaim", "artifacts", "{.spec.storageClassName}", runner.ns, name),
              ("PersistentVolumeClaim", "artifacts", "{.spec.accessModes}", runner.ns, ["ReadWriteOncePod"])]
    if require_bound:
        checks += [("PersistentVolume", name, "{.status.phase}", None, "Bound"),
                   ("PersistentVolume", name, "{.spec.claimRef.uid}", None, result["claim_uid"]),
                   ("PersistentVolumeClaim", "artifacts", "{.status.phase}", runner.ns, "Bound")]
    for kind, resource, field, namespace, wanted in checks:
        if runner.projection(kind, resource, field, namespace) != wanted:
            raise Failure("persistent_storage_source_changed")
    return result


def persist(runner, name, value):
    fd = os.open(runner.journal.folder / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as output:
        output.write(json.dumps(value, sort_keys=True, separators=(",", ":")).encode())
        output.flush()
        os.fsync(output.fileno())
    fd = os.open(runner.journal.folder, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def artifact(runner, pod, label, payload):
    if label not in {"preflight", "workload-result"} or not 0 < len(payload) <= 4096:
        raise Failure("persistent_artifact_declaration_invalid")
    script = (runner.source_root / "internal/host/workload_artifact.py").read_text()
    raw = runner.kube("exec", pod, "-n", runner.ns, "--", *WORKLOAD_ENVIRONMENT,
                      "python", "-I", "-c", script, label + "-" + runner.run_id + ".json",
                      base64.b64encode(payload).decode(), timeout=90)
    proof = strict(raw.decode(), 4096)
    keys = {"agent_uid", "agent_gid", "root_uid", "root_gid", "root_mode", "directory", "verified", "bytes", "sha256", "failure_kind"}
    if (not isinstance(proof, dict) or set(proof) != keys or proof["agent_uid"] != 10001 or proof["agent_gid"] != 10001
            or any(type(proof[key]) is not int or proof[key] < 0 for key in ["agent_uid", "agent_gid", "root_uid", "root_gid", "root_mode", "bytes"])
            or proof["root_mode"] > 0o7777 or type(proof["directory"]) is not bool or type(proof["verified"]) is not bool
            or proof["failure_kind"] not in {"root_unavailable", "write_unavailable", "readback_unavailable", "passed"}
            or not isinstance(proof["sha256"], str) or not re.fullmatch(r"(?:[a-f0-9]{64})?", proof["sha256"])):
        raise Failure("persistent_artifact_proof_invalid")
    persist(runner, "storage-" + label + ".json", proof)
    if (proof["verified"] is not True or proof["directory"] is not True or proof["bytes"] != len(payload)
            or proof["sha256"] != hashlib.sha256(payload).hexdigest() or proof["failure_kind"] != "passed"):
        raise Failure("persistent_artifact_unverified")
    return proof


def reset_request(runner, pod):
    frozen = runner.journal.data.get("persistent_reset")
    if not isinstance(frozen, dict) or set(frozen) != {"authority", "original_job"}:
        raise Failure("persistent_reset_original_missing")
    return {"journal": str(runner.journal.folder / "nitro-reset.state"), **frozen}


def import_reset(runner):
    """Always called in finally, including ambiguous child launch/create responses."""
    path = runner.journal.folder / "nitro-reset.state"
    if not path.exists():
        return
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) & 0o077:
            raise Failure("persistent_reset_journal_unsafe")
        state = strict(stream.read(8193).decode(), 8192)
    original = runner.journal.data["context"]
    resources = runner.journal.data["resources"]
    frozen = runner.journal.data["persistent_reset"]
    expected = {"schema": "sandprobe.nitro-reset/1", "run_id": runner.run_id, "authority": frozen["authority"],
                "namespace_uid": resources[f"kube:Namespace::{runner.ns}"]["uid"],
                "volume_id": resources["workspace_volume"]["id"],
                "original_job_uid": resources[f"kube:Job:{runner.ns}:model-task"]["uid"],
                "original_pod_uid": original["pod_uid"], "original_config_sha256": original["config_sha256"]}
    fields = set(expected) | {"phase", "job_uid", "pod_uid", "pod_name", "config_sha256", "container_id"}
    if (not isinstance(state, dict) or set(state) != fields or any(state.get(k) != v for k, v in expected.items())
            or state["phase"] not in {"prepared", "delete_intent", "create_intent", "created", "ready"}
            or not re.fullmatch(r"[a-f0-9]{64}", state["config_sha256"])):
        raise Failure("persistent_reset_journal_context_changed")
    for key, pattern in [("pod_uid", r"[a-f0-9-]{16,64}"), ("pod_name", r"model-task-reset-[a-z0-9-]{1,50}"),
                         ("container_id", r"[a-z][a-z0-9+.-]*://[a-f0-9]{32,128}")]:
        value = state[key]
        if not isinstance(value, str) or (value and not re.fullmatch(pattern, value)):
            raise Failure("persistent_reset_replacement_identity_invalid")
    if (state["pod_uid"] == original["pod_uid"] or (state["phase"] == "ready" and
            not all(state[key] for key in ["job_uid", "pod_uid", "pod_name", "container_id"]))):
        raise Failure("persistent_reset_replacement_identity_invalid")
    # Independently derive the child's permitted reset hash from the host original.
    job = json.loads(json.dumps(frozen["original_job"]))
    env = job["spec"]["template"]["spec"]["containers"][0]["env"]
    hashes = [entry for entry in env if entry.get("name") == "SANDPROBE_CONFIG_SHA256"]
    if hashes != [{"name": "SANDPROBE_CONFIG_SHA256", "value": original["config_sha256"]}]:
        raise Failure("persistent_reset_original_hash_invalid")
    env[:] = [entry for entry in env if entry.get("name") != "SANDPROBE_CONFIG_SHA256"]
    if hashlib.sha256(json.dumps(job, sort_keys=True, separators=(",", ":")).encode()).hexdigest() != original["config_sha256"]:
        raise Failure("persistent_reset_original_hash_invalid")
    job["metadata"]["name"] = "model-task-reset"
    digest = hashlib.sha256(json.dumps(job, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    if state["config_sha256"] != digest:
        raise Failure("persistent_reset_hash_changed")
    uid = state["job_uid"]
    if ((uid and (not isinstance(uid, str) or not re.fullmatch(r"[a-f0-9-]{16,64}", uid)))
            or uid == expected["original_job_uid"] or (not uid and state["phase"] in {"created", "ready"})
            or (state["phase"] in {"prepared", "delete_intent", "create_intent"} and any(state[key] for key in ["job_uid", "pod_uid", "pod_name", "container_id"]))):
        raise Failure("persistent_reset_job_identity_invalid")
    key = f"kube:Job:{runner.ns}:model-task-reset"
    existing = resources.get(key)
    if existing and existing.get("uid", "") != uid:
        raise Failure("persistent_reset_job_identity_changed")
    if state["phase"] in {"create_intent", "created", "ready"}:
        resources[key] = {"kind": "Job", "name": "model-task-reset", "namespace": runner.ns,
                          "status": "created" if uid else "intent", "uid": uid}
    runner.journal.data["persistent_reset_state"] = state
    runner.journal.save()
