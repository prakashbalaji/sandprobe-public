"""RUN-1..5: explicit, journaled disposable EKS evaluation; no unattended runs."""
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import runpy
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import time

from assessment import evaluate, guest_document
import host_workload
from coding import strict
from lifecycle import Commands, Failure, Journal, directory
from render_profile import HOSTNAME, REGION, FixedErrorParser, render
from image_artifact import artifact_name, validate_run, select_artifact, download as download_image, open_verified
from image_artifact import archive_transport, validate_destination
from configuration_evidence import runtime_image_matches, verified_configuration_evidence

# The operator's own AWS account and CLI profile, from the environment. Unset, every account check fails closed.
ACCOUNT = os.environ.get("SANDPROBE_AWS_ACCOUNT", "")
ROOT = Path(__file__).resolve().parents[2]
completion_message = runpy.run_path(str(ROOT / "deploy/managed_status.py"))["completion_message"]
STATE_ROOT = Path.home() / ".config/sandprobe/agent-evaluation"
PROFILE = os.environ.get("SANDPROBE_AWS_PROFILE", "")
KUBERNETES_VERSION = "1.37"


def kubectl_version(data):
    try:
        version = data["clientVersion"]
        major, minor = version["major"], version["minor"]
        if major != "1" or not isinstance(minor, str) or not re.fullmatch(r"[0-9]{1,2}\+?", minor):
            raise ValueError()
        minor = int(minor.rstrip("+"))
        if abs(minor - int(KUBERNETES_VERSION.split(".")[1])) > 1:
            raise ValueError()
        return "1." + str(minor)
    except (KeyError, TypeError, ValueError):
        raise Failure("unsupported_kubectl_server_version_skew") from None

GUARD_FAILURES = frozenset({
    "unexpected_container_security_override", "missing_pod_security_context", "unexpected_pod_security_override",
    "unexpected_volume_set", "unexpected_volume_source", "unexpected_identity_volume", "unexpected_identity_projection",
    "unexpected_identity_token_context", "unexpected_mount_set", "unexpected_mount_options", "unexpected_node_selector",
    "unexpected_tolerations", "missing_dedicated_node_toleration", "unexpected_toleration", "unexpected_volume_device",
    "unexpected_environment_entry", "missing_changed_or_duplicate_expected_environment", "unexpected_pod_identity_binding",
    "unexpected_container_hook_or_arguments", "unexpected_task_command", "unexpected_pod_routing_or_process_override",
    "intended_identity_token_not_present", "returned_task_configuration_mismatch", "task_not_on_dedicated_enforcement_nodepool",
    "startup_network_policy_not_declared", "task_image_identity_mismatch", "task_pod_identity_missing", "invalid_config_projection",
    "workload_home_configuration_mismatch", "pre_workload_contract_changed",
})


def association_token(run_id):
    # IDN-1: EKS requires 33..126 characters; the run ID alone has only16.
    if not isinstance(run_id, str) or not re.fullmatch(r"[a-f0-9]{16}", run_id):
        raise Failure("invalid_association_run_identity")
    return hashlib.sha256(("sandprobe:pod-identity:" + run_id).encode()).hexdigest()


def auto_mode_dns(cluster):
    """DNS-1: AWS documents node-local DNS at service CIDR +10 in Auto Mode."""
    try:
        if cluster["computeConfig"]["enabled"] is not True:
            raise ValueError()
        cidr = cluster["kubernetesNetworkConfig"]["serviceIpv4Cidr"]
        if not isinstance(cidr, str):
            raise ValueError()
        network = ipaddress.ip_network(cidr, strict=True)
        private = [ipaddress.ip_network(c) for c in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]
        if (network.version != 4 or str(network) != cidr or not 12 <= network.prefixlen <= 24
                or not any(network.subnet_of(parent) for parent in private)):
            raise ValueError()
        return str(network[10])
    except (KeyError, TypeError, ValueError):
        raise Failure("auto_mode_dns_metadata_invalid") from None


def failure_category(error):
    if isinstance(error, KeyboardInterrupt):
        return "interrupted"
    if isinstance(error, Failure):
        code = str(error)
        allowed = {"command_failed", "command_unavailable_or_timed_out", "run_deadline",
                   "kubernetes_authentication_failed", "kubernetes_api_unavailable", "kubernetes_request_timeout",
                   "destination_image_config_mismatch", "auto_mode_dns_metadata_invalid",
                   "image_transport_identity_changed", "image_transport_content_changed",
                   "image_transport_timestamps_changed", "verified_archive_transport_not_supported"}
        return code if code in allowed or code in GUARD_FAILURES else "controlled_failure"
    return "unexpected_failure"


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def trust_policy(cluster_arn, namespace):
    return {"Version": "2012-10-17", "Statement": [{"Effect": "Allow",
        "Principal": {"Service": "pods.eks.amazonaws.com"},
        "Action": ["sts:AssumeRole", "sts:TagSession"],
        "Condition": {"StringEquals": {"aws:RequestTag/eks-cluster-arn": cluster_arn,
            "aws:RequestTag/kubernetes-namespace": namespace,
            "aws:RequestTag/kubernetes-service-account": "model-task"}}}]}


class Runner:
    def __init__(self, journal, profile=PROFILE, commands=None, upload_hosts=None, controller="guest", model_python=""):
        if not re.fullmatch(r"[a-zA-Z0-9_-]{1,64}", profile):
            raise Failure("invalid_profile")
        if controller not in {"guest", "host"}:
            raise Failure("invalid_controller_pattern")
        self.controller, self.model_python, self.source_root = controller, model_python, ROOT
        self.journal, self.profile = journal, profile
        parse_hosts = runpy.run_path(str(ROOT / "deploy/workload_measurement.py"))["upload_hosts"]
        self.upload_hosts = parse_hosts(",".join(upload_hosts or []))
        self.ops = commands or Commands()
        self.run_id = journal.data["run_id"]
        self.name = "sandprobe-agent-" + self.run_id
        self.ns = self.name
        self.kubeconfig = None
        self.cluster = None
        self.archive_handle = None
        self.env = os.environ.copy()
        for key in list(self.env):
            if key == "AWS_ENDPOINT_URL" or key.startswith("AWS_ENDPOINT_URL_"):
                self.env.pop(key)
        self.env["AWS_IGNORE_CONFIGURED_ENDPOINT_URLS"] = "true"
        # Every child, the standard grade included, checks the account and the profile this run selected.
        self.env["SANDPROBE_AWS_ACCOUNT"], self.env["SANDPROBE_AWS_PROFILE"] = ACCOUNT, self.profile

    def stage(self, label):
        # RUN-7: callers supply fixed source labels, never external error text.
        self.journal.data["execution_stage"] = label
        self.journal.save()

    def task_node_selector(self):
        # GAT-2: explicitly request the RuntimeClass's exact Nitro capability.
        return {"karpenter.sh/nodepool": self.name, "eks.amazonaws.com/nitro-sandbox": "true"}

    def guard_read(self, operation, *args, **kwargs):
        # GAT-1: used only for idempotent config reads, never release/model calls.
        for attempt in range(3):
            try:
                return operation(*args, **kwargs)
            except Failure as error:
                if str(error) != "command_failed" or attempt == 2:
                    raise
                time.sleep(1)

    def aws(self, service, operation, *args, query=None):
        command = ["aws", "--profile", self.profile, "--region", REGION, service, operation, *args, "--output", "json"]
        if query:
            command += ["--query", query]
        raw = self.ops.call(command, env=self.env)
        return strict(raw.decode(), 1 << 20) if raw.strip() else None

    def account(self):
        if self.aws("sts", "get-caller-identity", query="Account") != ACCOUNT:
            raise Failure("wrong_account_no_mutations_allowed")

    def preflight(self, model, approval, image_run_id=None):
        if not isinstance(approval, str) or not 3 <= len(approval) <= 512 or not approval.isprintable():
            raise Failure("aws_eks_testing_approval_reference_required")
        if self.controller == "host":
            if model != host_workload.MODEL:
                raise Failure("host_controller_requires_fixed_model")
            host_workload.model_preflight(self)
        # Validate the supported model syntax using the same renderer as live.
        render(self.run_id, f"{ACCOUNT}.dkr.ecr.{REGION}.amazonaws.com/{self.name}@sha256:" + "a" * 64,
               ACCOUNT, model, ["52.94.0.1"], "172.20.0.10", controller=self.controller)
        tools = ["aws", "kubectl", "bash", "git", "go", "make", "cf", "jq", "openssl", "ps"] + (["docker"] if image_run_id is None else ["gh", "skopeo"])
        for tool in tools:
            if not shutil.which(tool):
                raise Failure("required_tool_unavailable")
        # CLI-1: reject unsupported host tooling before provisioning anything.
        client = kubectl_version(strict(self.ops.call(["kubectl", "version", "--client", "-o", "json"]).decode(), 65536))
        self.journal.data.update(kubectl_version=client, kubernetes_version=KUBERNETES_VERSION)
        if image_run_id is None:
            if self.ops.call(["docker", "info", "--format", "{{.OSType}}"], timeout=15).strip() != b"linux":
                raise Failure("linux_docker_daemon_required")
        elif not re.fullmatch(r"[0-9]{1,20}", str(image_run_id)):
            raise Failure("invalid_image_workflow_run_id")
        if self.ops.call(["git", "-C", str(ROOT), "status", "--porcelain"]).strip():
            raise Failure("live_run_requires_clean_reviewed_source")
        # RUN-8: build the shipped probe + host bridge before any paid resources.
        self.ops.call(["make", "-C", str(ROOT), "probes"], env=self.env, timeout=180)
        self.ops.call(["go", "-C", str(ROOT), "build", "-trimpath", "-o",
                       str(self.journal.folder / "standard-grade"), "./cmd/sandprobe-agent-grade"], env=self.env, timeout=180)
        zones = strict(self.ops.call(["cf", "zones", "list"], env=self.env).decode(), 1 << 20)
        if (not isinstance(zones, list) or len([z for z in zones if isinstance(z, dict)
                and z.get("name") == "ac0.dev" and isinstance(z.get("id"), str)
                and re.fullmatch(r"[a-f0-9]{32}", z["id"])]) != 1):
            raise Failure("owned_canary_dns_zone_unavailable")
        self.account()
        availability = self.aws("bedrock", "get-foundation-model-availability", "--model-id", model)
        if (availability.get("authorizationStatus") != "AUTHORIZED"
                or availability.get("entitlementAvailability") != "AVAILABLE"
                or availability.get("regionAvailability") != "AVAILABLE"
                or availability.get("agreementAvailability", {}).get("status") != "AVAILABLE"):
            raise Failure("model_access_or_agreement_not_pre_enabled")
        detail = self.aws("bedrock", "get-foundation-model", "--model-identifier", model,
                          query="modelDetails.inferenceTypesSupported")
        if "ON_DEMAND" not in detail:
            raise Failure("regional_on_demand_model_required")
        ips = sorted({r[4][0] for r in socket.getaddrinfo(HOSTNAME, 443, socket.AF_INET, socket.SOCK_STREAM)})
        if not ips or any(not ipaddress.ip_address(ip).is_global for ip in ips):
            raise Failure("invalid_model_endpoint_resolution")
        source_commit = self.ops.call(["git", "-C", str(ROOT), "rev-parse", "HEAD"]).decode().strip()
        if image_run_id is not None:
            attempt = validate_run(self.image_run_metadata(image_run_id), source_commit, image_run_id)
            raw = self.ops.call(["gh", "api", "--hostname", "github.com", f"repos/summationai/sandprobe/actions/runs/{image_run_id}/artifacts?per_page=100"])
            artifact = select_artifact(strict(raw.decode(), 1 << 20), source_commit, image_run_id, attempt)
            self.journal.data.update(image_run_id=str(image_run_id), image_run_attempt=attempt, image_artifact=artifact)
        self.journal.data.update(model=model, profile=self.profile, account=ACCOUNT,
            approval_reference_sha256=hashlib.sha256(approval.encode()).hexdigest(),
            endpoint_resolution={"hostname": HOSTNAME, "ipv4": ips, "resolved_at": int(time.time())},
            source_commit=source_commit, controller=self.controller,
            deployment_pattern="host_controller_no_guest_credentials" if self.controller == "host" else "guest_assigned_identity", phase="preflight_passed")
        self.journal.save()

    def kube(self, *args, payload=None, timeout=60):
        if not self.kubeconfig or not self.cluster:
            raise Failure("cluster_context_unavailable")
        return self.ops.call(["kubectl", "--kubeconfig", str(self.kubeconfig), "--context", self.cluster,
                              "--request-timeout=30s", *args], payload=payload, timeout=timeout, env=self.env)

    def scalar(self, kind, name, expression, namespace=None):
        args = ["get", kind, name, "--ignore-not-found", "-o", "jsonpath=" + expression]
        if namespace:
            args += ["-n", namespace]
        return self.kube(*args).decode().strip()

    def create(self, resource):
        meta = resource["metadata"]
        key = "kube:" + resource["kind"] + ":" + meta.get("namespace", "") + ":" + meta["name"]
        self.journal.intent(key, kind=resource["kind"], name=meta["name"], namespace=meta.get("namespace", ""))
        uid = self.kube("create", "-f", "-", "-o", "jsonpath={.metadata.uid}", payload=encoded(resource)).decode().strip()
        if not re.fullmatch(r"[a-f0-9-]{16,64}", uid):
            raise Failure("created_resource_identity_missing")
        self.journal.recorded(key, uid=uid)
        return uid

    def delegated_state(self):
        import stat
        fd = os.open(self.journal.folder / "eks.state", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "r") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1:
                raise Failure("unsafe_delegated_state")
            raw = stream.read(65537)
        if len(raw) > 65536:
            raise Failure("oversize_delegated_state")
        return dict(line.strip().split("=", 1) for line in raw.splitlines() if "=" in line)

    def cluster_up(self):
        self.journal.intent("cluster", delegated_state="eks.state")
        env = dict(self.env, PROFILE=self.profile, REGION=REGION, DURABLE_STATE="1", VERSION=KUBERNETES_VERSION,
                   STATE=str(self.journal.folder / "eks.state"))
        self.ops.call(["bash", str(ROOT / "deploy/eks.sh"), "up"], env=env, timeout=1800)
        values = self.delegated_state()
        cluster = values.get("cluster", "")
        if not re.fullmatch(r"sandprobe-[a-f0-9]{8}", cluster):
            raise Failure("unexpected_cluster_identity")
        data = self.aws("eks", "describe-cluster", "--name", cluster, query="cluster")
        if data.get("version") != KUBERNETES_VERSION:
            raise Failure("unexpected_cluster_kubernetes_version")
        if data.get("tags", {}).get("sandprobe:deployment") != values.get("did"):
            raise Failure("cluster_ownership_mismatch")
        kc = Path(values.get("kubeconfig", ""))
        if kc.parent != self.journal.folder or not re.fullmatch(r"eks-[a-f0-9]{8}\.kubeconfig", kc.name):
            raise Failure("unexpected_kubeconfig_path")
        self.cluster, self.kubeconfig = cluster, kc
        endpoint = self.kube("config", "view", "--minify", "-o", "jsonpath={.clusters[0].cluster.server}").decode()
        if endpoint != data["endpoint"]:
            raise Failure("kubeconfig_cluster_mismatch")
        self.journal.recorded("cluster", name=cluster, arn=data["arn"], created_at=data["createdAt"], did=values["did"])
        return data, values["nrole"]

    def configure_nodes(self, data, node_role):
        if not re.fullmatch(r"sandprobe-eksnode-[a-f0-9]{8}", node_role):
            raise Failure("unexpected_node_role")
        cm = {"enable-network-policy-controller": "true", "enable-network-policy": "true"}
        uid = self.scalar("configmap", "amazon-vpc-cni", "{.metadata.uid}", "kube-system")
        if uid:
            self.kube("patch", "configmap", "amazon-vpc-cni", "-n", "kube-system", "--type=merge", "-p", json.dumps({"data": cm}))
        else:
            self.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "amazon-vpc-cni", "namespace": "kube-system"}, "data": cm})
        self.create({"apiVersion": "eks.amazonaws.com/v1", "kind": "NodeClass", "metadata": {"name": self.name},
            "spec": {"role": node_role, "subnetSelectorTerms": [{"id": i} for i in data["resourcesVpcConfig"]["subnetIds"]],
                     "securityGroupSelectorTerms": [{"id": data["resourcesVpcConfig"]["clusterSecurityGroupId"]}],
                     "networkPolicy": "DefaultDeny", "networkPolicyEventLogs": "Enabled"}})
        self.create({"apiVersion": "karpenter.sh/v1", "kind": "NodePool", "metadata": {"name": self.name},
            "spec": {"limits": {"cpu": "4"}, "template": {"metadata": {"labels": {"sandprobe.run": self.run_id}},
                "spec": {"nodeClassRef": {"group": "eks.amazonaws.com", "kind": "NodeClass", "name": self.name},
                         "requirements": [{"key": "kubernetes.io/arch", "operator": "In", "values": ["amd64"]},
                                          {"key": "karpenter.sh/capacity-type", "operator": "In", "values": ["on-demand"]},
                                          {"key": "node.kubernetes.io/instance-type", "operator": "In", "values": ["c8a.large"]}],
                         "taints": [{"key": "sandprobe.run", "value": self.run_id, "effect": "NoSchedule"}]}}}})

    def image_run_metadata(self, run_id):
        fields = '{status,conclusion,event,head_branch,head_sha,path,run_attempt,id,repository:.repository.full_name,head_repository:.head_repository.full_name}'
        raw = self.ops.call(["gh", "api", "--hostname", "github.com", f"repos/summationai/sandprobe/actions/runs/{run_id}", "--jq", fields])
        return strict(raw.decode(), 65536)

    def prepare_ci_image(self):
        source, attempt = self.journal.data["source_commit"], self.journal.data["image_run_attempt"]
        folder = directory(self.journal.folder / "image-artifact")
        download_image(self.journal.data["image_artifact"], folder, min(self.ops.deadline, time.monotonic()+300), self.env)
        metadata, self.archive_handle = open_verified(folder, source, attempt)
        os.fchmod(self.archive_handle.fileno(), 0o400)
        with archive_transport(self.archive_handle, folder, metadata) as (source_image, descriptors):
            platform = self.ops.call(["skopeo", "inspect", "--format", "{{.Os}}/{{.Architecture}}",
                source_image], timeout=60, limit=1024, pass_fds=descriptors)
        if platform.strip() != b"linux/amd64":
            raise Failure("verified_archive_transport_not_supported")
        self.archive_handle.seek(0)
        current_attempt = validate_run(self.image_run_metadata(self.journal.data["image_run_id"]), source, self.journal.data["image_run_id"])
        if current_attempt != attempt:
            raise Failure("image_workflow_attempt_changed")
        self.journal.data["verified_image_artifact"] = metadata
        self.journal.save()

    def publish_ci_image(self, repo):
        if self.archive_handle is None:
            raise Failure("verified_image_descriptor_missing")
        auth = self.journal.folder / "registry-auth.json"
        fd = os.open(auth, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w") as stream:
            json.dump({"auths": {}}, stream)
        password = login = None
        try:
            password = subprocess.Popen(["aws", "--profile", self.profile, "--region", REGION,
                "ecr", "get-login-password"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=self.env, start_new_session=True)
            login = subprocess.Popen(["skopeo", "login", "--authfile", str(auth), "--username", "AWS", "--password-stdin",
                f"{ACCOUNT}.dkr.ecr.{REGION}.amazonaws.com"], stdin=password.stdout,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=self.env, start_new_session=True)
            password.stdout.close()
            if login.wait(timeout=45) or password.wait(timeout=10):
                raise Failure("registry_login_failed")
            with archive_transport(self.archive_handle, self.journal.folder / "image-artifact",
                                   self.journal.data["verified_image_artifact"]) as (source_image, descriptors):
                self.ops.call(["skopeo", "copy", "--dest-authfile", str(auth),
                    source_image, "docker://" + repo["repositoryUri"] + ":task"],
                    env=self.env, timeout=600, pass_fds=descriptors)
            self.stage("registry_validation")
            digest = self.aws("ecr", "describe-images", "--repository-name", self.name,
                              "--image-ids", "imageTag=task", query="imageDetails[0].imageDigest")
            if not isinstance(digest, str) or not re.fullmatch(r"sha256:[a-f0-9]{64}", digest):
                raise Failure("pushed_image_digest_missing")
            manifest = self.ops.call(["skopeo", "inspect", "--raw", "--authfile", str(auth),
                "docker://" + repo["repositoryUri"] + "@" + digest], env=self.env, timeout=60, limit=1 << 20)
            validate_destination(manifest, self.journal.data["verified_image_artifact"]["image_id"])
        finally:
            for process in [login, password]:
                if process is not None and process.poll() is None:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()
            auth.unlink(missing_ok=True)
            self.archive_handle.close()
            self.archive_handle = None
        return repo["repositoryUri"] + "@" + digest

    def publish_image(self):
        self.journal.intent("repository", name=self.name)
        repo = self.aws("ecr", "create-repository", "--repository-name", self.name, "--image-tag-mutability", "IMMUTABLE",
                        "--tags", f"Key=sandprobe:run,Value={self.run_id}", query="repository")
        self.journal.recorded("repository", arn=repo["repositoryArn"], created_at=repo["createdAt"], uri=repo["repositoryUri"])
        if self.journal.data.get("image_run_id"):
            return self.publish_ci_image(repo)
        docker_config = directory(self.journal.folder / "docker")
        env = dict(self.env, DOCKER_CONFIG=str(docker_config))
        # A nonempty explicit file-store config prevents Docker's automatic
        # platform keychain discovery; never overwrite the user's global store.
        fd = os.open(docker_config / "config.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w") as config:
            json.dump({"auths": {"sandprobe.invalid": {}}}, config)
            config.flush()
            os.fsync(config.fileno())
        tag = repo["repositoryUri"] + ":task"
        self.journal.intent("local_image", tag=tag)
        self.ops.call(["docker", "build", "--platform=linux/amd64", "--label", "sandprobe.run=" + self.run_id,
                       "-t", tag, str(Path(__file__).parent)], env=env, timeout=600)
        image_id = self.ops.call(["docker", "image", "inspect", tag, "--format", "{{.Id}}"], env=env).decode().strip()
        if not re.fullmatch(r"sha256:[a-f0-9]{64}", image_id):
            raise Failure("local_image_identity_missing")
        self.journal.recorded("local_image", image_id=image_id)
        registry = f"{ACCOUNT}.dkr.ecr.{REGION}.amazonaws.com"
        password = login = None
        try:
            # Protocol pipe: credential bytes never enter Python, logs or journal.
            password = subprocess.Popen(["aws", "--profile", self.profile, "--region", REGION,
                "ecr", "get-login-password"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=self.env, start_new_session=True)
            login = subprocess.Popen(["docker", "login", "--username", "AWS", "--password-stdin", registry],
                stdin=password.stdout, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env, start_new_session=True)
            password.stdout.close()
            if login.wait(timeout=45) or password.wait(timeout=10):
                raise Failure("registry_login_failed")
            self.ops.call(["docker", "push", tag], env=env, timeout=600)
        finally:
            for process in [login, password]:
                if process is not None and process.poll() is None:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()
            shutil.rmtree(docker_config)
        digest = self.aws("ecr", "describe-images", "--repository-name", self.name,
                          "--image-ids", "imageTag=task", query="imageDetails[0].imageDigest")
        if not isinstance(digest, str) or not re.fullmatch(r"sha256:[a-f0-9]{64}", digest):
            raise Failure("pushed_image_digest_missing")
        return repo["repositoryUri"] + "@" + digest

    def role(self, policy):
        self.journal.intent("role", name=self.name)
        arn = self.journal.data["resources"]["cluster"]["arn"]
        role = self.aws("iam", "create-role", "--role-name", self.name,
                        "--assume-role-policy-document", json.dumps(trust_policy(arn, self.ns)),
                        "--tags", f"Key=sandprobe:run,Value={self.run_id}", query="Role")
        self.journal.recorded("role", role_id=role["RoleId"], arn=role["Arn"])
        self.aws("iam", "put-role-policy", "--role-name", self.name, "--policy-name", self.name,
                 "--policy-document", json.dumps(policy))
        self.journal.intent("association", cluster=self.cluster)
        self.stage("identity_association")
        association = self.aws("eks", "create-pod-identity-association", "--cluster-name", self.cluster,
            "--namespace", self.ns, "--service-account", "model-task", "--role-arn", role["Arn"],
            "--client-request-token", association_token(self.run_id), "--tags", json.dumps({"sandprobe:run": self.run_id}), query="association")
        self.journal.recorded("association", association_id=association["associationId"], arn=association["associationArn"])

    def simple_pod(self, name, command, env=None, namespace=None):
        return {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": name, "namespace": namespace or self.ns,
                "labels": {"sandprobe.run": self.run_id, "sandprobe.component": name}},
            "spec": {"automountServiceAccountToken": False, "enableServiceLinks": False,
                     "nodeSelector": {"kubernetes.io/arch": "amd64"},
                     "restartPolicy": "Never", "activeDeadlineSeconds": 3600,
                     "securityContext": {"runAsUser": 10001, "runAsGroup": 10001, "runAsNonRoot": True,
                         "fsGroup": 10001, "seccompProfile": {"type": "RuntimeDefault"}},
                     "containers": [{"name": name, "image": self.image, "command": command, "env": env or [],
                         "securityContext": {"readOnlyRootFilesystem": True, "allowPrivilegeEscalation": False,
                                              "capabilities": {"drop": ["ALL"]}},
                         "resources": {"limits": {"cpu": "100m", "memory": "128Mi"}},
                         "volumeMounts": [{"name": "scratch", "mountPath": "/tmp"}]}],
                     "volumes": [{"name": "scratch", "emptyDir": {"sizeLimit": "16Mi"}}]}}

    def wait_pod(self, name, namespace):
        self.kube("wait", "pod/" + name, "-n", namespace, "--for=condition=Ready", "--timeout=15m", timeout=930)
        uid = self.scalar("pod", name, "{.metadata.uid}", namespace)
        key = f"kube:Pod:{namespace}:{name}"
        if uid != self.journal.data["resources"][key]["uid"]:
            raise Failure("pod_identity_changed")
        return self.scalar("pod", name, "{.status.podIP}", namespace)

    def control(self, receiver_ip, nonce):
        uid = self.scalar("pod", "control", "{.metadata.uid}", self.ns)
        if uid != self.journal.data["resources"][f"kube:Pod:{self.ns}:control"]["uid"]:
            raise Failure("control_identity_changed")
        for _ in range(5):
            raw = self.kube("exec", "control", "-n", self.ns, "--", "python", "-I", "/opt/sandprobe/checks.py", "--control", receiver_ip, nonce)
            if strict(raw.decode()).get("control") == "reported_delivery":
                return
            time.sleep(1)
        raise Failure("positive_control_failed")

    def delete_job(self):
        key = f"kube:Job:{self.ns}:model-task"
        record = self.journal.data["resources"][key]
        uid = self.scalar("job", "model-task", "{.metadata.uid}", self.ns)
        if not uid:
            return
        if uid != record["uid"]:
            raise Failure("job_identity_changed")
        self.kube("delete", "--raw", f"/apis/batch/v1/namespaces/{self.ns}/jobs/model-task", "-f", "-",
            payload=encoded({"apiVersion": "v1", "kind": "DeleteOptions", "preconditions": {"uid": uid}, "propagationPolicy": "Foreground"}))
        self.kube("wait", "--for=delete", "job/model-task", "-n", self.ns, "--timeout=5m", timeout=330)
        if self.kube("get", "pods", "-n", self.ns, "-l", "job-name=model-task", "-o", "jsonpath={.items[*].metadata.uid}").strip():
            raise Failure("task_pods_not_confirmed_gone")
        record["status"] = "deleted"
        self.journal.save()

    def execute(self):
        if self.journal.data.get("image_run_id"):
            self.stage("image_preparation")
            self.prepare_ci_image() # Validate download before ANY cloud create.
        self.stage("canary_creation")
        self.journal.intent("canary", delegated_state="canary.state",
            namespace="sandprobe-canary-" + self.run_id, outcome_file="canary-outcome.json",
            outcome_nonce=secrets.token_hex(24),
            delegate_sha256=hashlib.sha256((ROOT / "deploy/canary.sh").read_bytes()).hexdigest())
        self.canary("up", timeout=1200)
        self.journal.recorded("canary", delegated_state="canary.state")
        self.stage("cluster_creation")
        cluster, role = self.cluster_up()
        self.stage("node_configuration")
        self.configure_nodes(cluster, role)
        self.stage("registry_publication")
        self.image = self.publish_image()
        self.stage("dns_selection")
        dns_ip = auto_mode_dns(cluster)
        self.journal.data["dns_address"] = dns_ip
        self.stage("task_setup")
        model = self.journal.data["model"]
        plan = render(self.run_id, self.image, ACCOUNT, model,
                      self.journal.data["endpoint_resolution"]["ipv4"], dns_ip, controller=self.controller)
        items = plan["kubernetes"]["items"]
        for resource in items[:-1]:
            self.create(resource)
        if self.controller == "guest":
            self.role(plan["iam_policy"])
        nonces = [secrets.token_hex(24) for _ in range(3)]
        self.journal.data["nonces"] = nonces
        self.journal.save()
        receiver_ns = self.name + "-receiver"
        self.create({"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": receiver_ns, "labels": {"sandprobe.run": self.run_id}}})
        self.create({"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
            "metadata": {"name": "receiver-only", "namespace": receiver_ns},
            "spec": {"podSelector": {}, "policyTypes": ["Ingress", "Egress"], "egress": [], "ingress": [{
                "from": [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": self.ns}},
                          "podSelector": {"matchExpressions": [{"key": "sandprobe.component", "operator": "In", "values": ["agent", "control"]}]}}],
                "ports": [{"protocol": "TCP", "port": 8080}]}]}})
        receiver = self.simple_pod("receiver", ["python", "-I", "/opt/sandprobe/receiver.py"],
            [{"name": "SANDPROBE_RECEIVER_NONCES", "value": json.dumps(nonces)}], namespace=receiver_ns)
        receiver_uid = self.create(receiver)
        receiver_ip = self.wait_pod("receiver", receiver_ns)
        self.journal.data["receiver_ip"] = receiver_ip
        self.journal.save()
        if not ipaddress.ip_address(receiver_ip).is_private:
            raise Failure("receiver_address_not_private")
        # Control has a distinct label and only receiver access; the agent policy
        # cannot select it. No model identity is associated with the default SA.
        self.create({"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
            "metadata": {"name": "control-only", "namespace": self.ns},
            "spec": {"podSelector": {"matchLabels": {"sandprobe.component": "control"}},
                "policyTypes": ["Ingress", "Egress"], "ingress": [],
                "egress": [{"to": [{"ipBlock": {"cidr": receiver_ip + "/32"}}], "ports": [{"protocol": "TCP", "port": 8080}]}]}})
        control = self.simple_pod("control", ["python", "-I", "-c", "import time;time.sleep(3500)"])
        control["metadata"]["labels"].pop("sandprobe.run")
        self.create(control)
        self.wait_pod("control", self.ns)
        self.control(receiver_ip, nonces[0])
        job = items[-1]
        job["spec"]["template"]["metadata"]["labels"]["sandprobe.component"] = "agent"
        spec = job["spec"]["template"]["spec"]
        spec["nodeSelector"] = self.task_node_selector()
        spec["tolerations"] = [{"key": "sandprobe.run", "operator": "Equal", "value": self.run_id, "effect": "NoSchedule"}]
        container = spec["containers"][0]
        container["command"] = list(host_workload.IDLE_COMMAND) if self.controller == "host" else ["python", "-I", "/opt/sandprobe/execute.py"]
        container["env"] += [{"name": "SANDPROBE_RUN_ID", "value": self.run_id},
                             {"name": "SANDPROBE_POD_UID", "valueFrom": {"fieldRef": {"fieldPath": "metadata.uid"}}},
                             {"name": "SANDPROBE_RECEIVER_IP", "value": receiver_ip},
                             {"name": "SANDPROBE_AGENT_NONCE", "value": nonces[1]}]
        job["spec"]["activeDeadlineSeconds"] = 2700
        config_sha = hashlib.sha256(encoded(job)).hexdigest()
        container["env"].append({"name": "SANDPROBE_CONFIG_SHA256", "value": config_sha})
        self.journal.data["context"] = {"run_id": self.run_id, "receiver_uid": receiver_uid,
            "image": self.image, "config_sha256": config_sha, "pod_uid": "pending"}
        self.journal.save()
        job_uid = self.create(job)
        # Wait for exactly one created pod without logging whole Pod objects.
        end = time.monotonic() + 900
        pod_name = None
        while time.monotonic() < end:
            names = self.kube("get", "pods", "-n", self.ns, "-l", "job-name=model-task", "-o", "jsonpath={.items[*].metadata.name}").decode().split()
            if len(names) > 1:
                raise Failure("multiple_task_pods_budget_uncertain")
            if names:
                pod_name = names[0]
                break
            time.sleep(2)
        if not pod_name or not re.fullmatch(r"model-task-[a-z0-9-]+", pod_name):
            raise Failure("task_pod_not_created")
        self.verify_task_pod(pod_name, job_uid)
        self.stage("workload_contract_freeze")
        self.freeze_workload_contract(pod_name)
        self.stage("task_execution")
        if self.controller == "guest":
            self.kube("exec", pod_name, "-n", self.ns, "--", "python", "-I", "-c",
                "import os;f=os.open('/workspace/.host-release',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600);os.write(f,b'" + self.run_id + "');os.close(f)")
        raw = self.collect_task_and_grade(pod_name, job_uid, config_sha)
        self.delete_job()
        self.control(receiver_ip, nonces[2])
        if self.scalar("pod", "receiver", "{.metadata.uid}", receiver_ns) != receiver_uid:
            raise Failure("receiver_identity_changed")
        receipts = strict(self.kube("exec", "receiver", "-n", receiver_ns, "--", "python", "-I", "-c",
            "import sys;sys.stdout.buffer.write(open('/tmp/receipts.json','rb').read(4097))").decode(), 4096)
        doc = guest_document(raw, self.run_id, self.journal.data["context"]["pod_uid"], config_sha)
        if (set(receipts) != {"nonces"} or not isinstance(receipts["nonces"], list)
                or any(n not in nonces for n in receipts["nonces"]) or len(set(receipts["nonces"])) != len(receipts["nonces"])):
            raise Failure("invalid_receiver_receipts")
        self.journal.data["guest"] = json.dumps(doc, sort_keys=True) if doc is not None else ""
        self.journal.data["receipts"] = {"receiver_uid": receiver_uid, "nonces": receipts["nonces"]}
        self.journal.data["phase"] = "collected"
        self.journal.save()

    def collect_task_and_grade(self, pod_name, job_uid, config_sha):
        raw = (host_workload.perform(self, pod_name, config_sha) if self.controller == "host"
               else self.wait_workload(pod_name, config_sha))
        # RUN-8: preserve workload outcome even if standard grading fails.
        self.journal.data["guest"] = raw
        self.journal.save()
        self.verify_task_pod(pod_name, job_uid)
        self.verify_frozen_workload_contract(pod_name)
        self.stage("standard_grading")
        self.standard_grade(pod_name, job_uid, config_sha)
        return raw

    def identity_configuration_hash(self):
        if self.controller == "host":
            return host_workload.identity_hash(self)
        # WGR-4: exact requested IAM configuration, not all effective permissions.
        role = self.journal.data["resources"]["role"]
        if self.aws("iam", "get-role", "--role-name", self.name, query="Role.RoleId") != role["role_id"]:
            raise Failure("model_role_identity_changed")
        if self.aws("iam", "list-role-policies", "--role-name", self.name, query="PolicyNames") != [self.name]:
            raise Failure("unexpected_model_inline_policies")
        if self.aws("iam", "list-attached-role-policies", "--role-name", self.name, query="AttachedPolicies") != []:
            raise Failure("unexpected_model_attached_policies")
        policy = self.aws("iam", "get-role-policy", "--role-name", self.name, "--policy-name", self.name, query="PolicyDocument")
        expected = render(self.run_id, self.image, ACCOUNT, self.journal.data["model"],
                          self.journal.data["endpoint_resolution"]["ipv4"], self.journal.data["dns_address"])["iam_policy"]
        if policy != expected:
            raise Failure("model_policy_scope_mismatch")
        return hashlib.sha256(encoded(policy)).hexdigest()

    def workload_fixture_context(self, pod_name):
        if self.controller == "host":
            return host_workload.fixture_context(self, pod_name)
        # WGR-1/2: stat metadata only; no token/marker contents read. The image,
        # private PID/mount/identity context were checked by verify_task_pod.
        script = """import os,stat,json
p='/opt/sandprobe/protected-marker';s=os.lstat(p)
if not (stat.S_ISREG(s.st_mode) and s.st_uid==0 and stat.S_IMODE(s.st_mode)==0o400 and s.st_size>0):raise RuntimeError('protected fixture metadata mismatch')
t='/var/run/secrets/pods.eks.amazonaws.com/serviceaccount/eks-pod-identity-token'
c=os.path.realpath(t);a=os.stat(t);b=os.stat(c)
if not (stat.S_ISREG(a.st_mode) and a.st_size>0 and (a.st_dev,a.st_ino)==(b.st_dev,b.st_ino)):raise RuntimeError('identity projection metadata mismatch')
print(json.dumps({'canonical':c,'device':a.st_dev,'inode':a.st_ino,'protected_device':s.st_dev,'protected_inode':s.st_ino}))"""
        context = strict(self.kube("exec", pod_name, "-n", self.ns, "--", "python", "-I", "-c", script).decode(), 4096)
        if (set(context) != {"canonical", "device", "inode", "protected_device", "protected_inode"}
                or not isinstance(context["canonical"], str)
                or not re.fullmatch(r"/run/secrets/pods\.eks\.amazonaws\.com/serviceaccount/\.\.[0-9_.]+/eks-pod-identity-token", context["canonical"])
                or any(type(context[k]) is not int or not 0 < context[k] < 2**64 for k in ["device", "inode", "protected_device", "protected_inode"])):
            raise Failure("unbound_identity_projection_alias")
        return context

    def workload_contract(self, pod_name):
        token = self.workload_fixture_context(pod_name)
        # RUN-15: common metadata-only guard; frozen before model release and
        # recomputed afterwards. Source is the same helper embedded in Go.
        self.stage('task_guard_home_metadata')
        guard_path=ROOT/'internal/host/workload_home_guard.py'
        guard=runpy.run_path(str(guard_path),run_name='sandprobe_owned_home_guard')
        raw=self.guard_read(self.kube,'exec',pod_name,'-n',self.ns,'--','python','-I','-c',guard_path.read_text())
        try:
            home_context=guard['validate'](strict(raw.decode(),8192))
        except (ValueError,TypeError,KeyError):
            raise Failure('workload_home_configuration_mismatch') from None
        # RUN-19: validated synthetic fixture metadata only, never directory contents.
        phase = "after" if "workload_contract" in self.journal.data else "before"
        self.journal.data["workload_home_" + phase] = home_context
        self.journal.save()
        contract = {"schema": "sandprobe.workload-contract/1", "profile": "networked-coding-v1",
                "managed_run_id": self.run_id, "box_id": self.journal.data["context"]["pod_uid"],
                "image": self.image, "config_sha256": self.journal.data["context"]["config_sha256"],
                "agent_home_sha256": hashlib.sha256(encoded(home_context)).hexdigest(),
                "identity_policy_sha256": self.identity_configuration_hash(),
                "token_canonical": token.get("canonical", ""), "token_device": token.get("device", 0), "token_inode": token.get("inode", 0), "protected_device": token["protected_device"], "protected_inode": token["protected_inode"],
                "private_container_verified": True, "identity_configuration_verified": True, "protected_fixture_verified": True}
        if self.controller == "host":
            if not runtime_image_matches(self.image, self.journal.data.get("runtime_image_id")):
                raise Failure("host_controller_image_unverified")
            for key in ["token_canonical", "token_device", "token_inode"]:
                del contract[key]
            contract.update(schema="sandprobe.workload-contract/3", provider="aws-nitro",
                            identity_mode="host_controller_no_guest_credentials", agent_uid=10001, agent_gid=10001,
                            image_content_verified=True)
        return contract

    def freeze_workload_contract(self, pod_name):
        if "workload_contract" in self.journal.data:
            raise Failure("workload_contract_already_frozen")
        self.journal.data["workload_contract"] = strict(encoded(self.workload_contract(pod_name)).decode(), 65536)
        self.journal.save() # Durable BEFORE host-release and the first model call.
        # EVD-5: existing verified control-plane guards, retained for provider parity.
        contract = self.journal.data["workload_contract"]
        evidence = verified_configuration_evidence(self.run_id, contract["box_id"], contract["config_sha256"],
                                                   self.image, self.journal.data["runtime_image_id"], contract["private_container_verified"])
        fd = os.open(self.journal.folder / "configuration-evidence.json", os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as output:
            output.write(encoded(evidence)); output.flush(); os.fsync(output.fileno())

    def verify_frozen_workload_contract(self, pod_name):
        observed = self.workload_contract(pod_name)
        frozen = self.journal.data.get("workload_contract", {})
        if observed != frozen:
            # RUN-19: persist source-defined field names, never untrusted values.
            self.journal.data["workload_contract_changed_fields"] = sorted(
                key for key in observed if observed[key] != frozen.get(key))
            self.journal.save()
            raise Failure("pre_workload_contract_changed")

    def finalize_workload_grade(self, workload):
        # WGR-3/4: core Go grader recomputes from the host's bound raw collection,
        # after post-stop receipts are available. Never use the saved legacy letter.
        bundle = strict((self.journal.folder / "standard-evidence.json").read_text(), 4 << 20)
        request = {"manifest": bundle["report"]["manifest"], "observations": bundle["observations"],
                   "evidence": bundle["evidence"], "workload": workload,
                   "private_receiver": {"expected_uid": self.journal.data["context"]["receiver_uid"],
                     "observed_uid": self.journal.data.get("receipts", {}).get("receiver_uid", ""),
                     "issued_nonces": self.journal.data.get("nonces", []),
                     "received_nonces": self.journal.data.get("receipts", {}).get("nonces", [])}}
        raw = self.ops.call([str(self.journal.folder / "standard-grade"), "--workload-summary", "--include-coverage"],
                            payload=encoded(request), env=self.env, timeout=30)
        rendered = strict(raw.decode(), 1 << 20)
        assessment = rendered["assessment"]
        if (assessment["schema"] != "sandprobe.workload-assessment/1"
                or assessment["box_id"] != self.journal.data["context"]["pod_uid"]
                or assessment["security_assurance"] != "not_established_against_active_guest_tampering"
                or assessment["input_verification"] != "retrospective_recomputation_unauthenticated_input"
                or assessment["profile"] != "networked-coding-v1"
                or assessment["run_id"] != request["manifest"]["RunID"]
                or assessment["workload"] != workload
                or (assessment["benchmark_requirements_met"] and not (assessment["valid"] and assessment["complete"]
                    and assessment["contract_bound"] and assessment["configuration_grade"] == "B" and workload == "reported_passed"))):
            raise Failure("workload_assessment_binding_mismatch")
        coverage=rendered.get("evidence_coverage",{})
        if (coverage.get("schema")!="sandprobe.evidence-coverage/1"
                or coverage.get("run_id")!=assessment["run_id"]
                or coverage.get("valid") is not assessment["valid"]
                or coverage.get("unknown_controls")!=len(assessment.get("unknown",[]))):
            raise Failure("workload_coverage_binding_mismatch")
        exposure=rendered.get("exposure_scorecard",{})
        if (exposure.get("schema")!="sandprobe.workload-exposure/1"
                or exposure.get("run_id")!=assessment["run_id"] or exposure.get("box_id")!=assessment["box_id"]
                or exposure.get("input_verification")!="proof_recomputation_unauthenticated_input"
                or type(exposure.get("valid")) is not bool or type(exposure.get("score")) is not int
                or exposure.get("of")!=6 or not 0<=exposure["score"]<=6
                or not exposure["valid"] and (exposure["score"]!=0 or exposure.get("rows") not in [None,[]])
                or exposure["valid"] and (not isinstance(exposure.get("rows"),list) or len(exposure["rows"])!=6
                    or any(not isinstance(row,dict) or row.get("name")!=name or type(row.get("green")) is not bool
                           or row["green"] and (row.get("found") or row.get("unknown"))
                           for row,name in zip(exposure["rows"],["Secrets","Exfiltration","Containment","Privilege","Cloud access","Persistence"]))
                    or sum(row["green"] for row in exposure["rows"])!=exposure["score"])):
            raise Failure("workload_exposure_binding_mismatch")
        for name, content in [("workload-report.json", encoded(assessment)), ("workload-report.html", rendered["html"].encode()),
                              ("evidence-coverage.json",encoded(coverage)), ("exposure-scorecard.json",encoded(exposure))]:
            fd = os.open(self.journal.folder / name, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "wb") as output:
                output.write(content); output.flush(); os.fsync(output.fileno())
        self.journal.data["workload_assessment"] = assessment
        self.journal.data["exposure_scorecard"] = exposure
        self.journal.save()
        return assessment

    def canary(self, action, timeout):
        # RUN-16: never collide with or adopt the shared default receiver.
        env = dict(self.env, PROFILE=self.profile, REGION=REGION, DURABLE_STATE="1",
                   SANDPROBE_CANARY_NAME=("sandprobe-canary-" + self.run_id if action == "up" else
                       self.journal.data["resources"].get("canary", {}).get("namespace", "sandprobe-canary")),
                   DOMAIN="agent-" + self.run_id + ".probe.ac0.dev",
                   STATE=str(self.journal.folder / "canary.state"))
        args = ["bash", str(ROOT / "deploy/canary.sh"), action]
        if action != "up":
            return self.ops.call(args, env=env, timeout=timeout)
        record = self.journal.data["resources"]["canary"]
        outcome = runpy.run_path(str(ROOT / "deploy/canary_outcome.py"))
        path = self.journal.folder / record["outcome_file"]
        if record["delegate_sha256"] != hashlib.sha256((ROOT / "deploy/canary.sh").read_bytes()).hexdigest():
            raise Failure("canary_delegate_changed")
        outcome["begin"](path, self.run_id, record["outcome_nonce"], env["STATE"], ROOT / "deploy/canary.sh")
        env.update(SANDPROBE_CANARY_OUTCOME_FILE=str(path), SANDPROBE_CANARY_OUTCOME_NONCE=record["outcome_nonce"])
        try:
            result = self.ops.call(args, env=env, timeout=timeout, quiesce_group=True)
        except BaseException as error:
            if getattr(self.ops, "last_group_quiescent", False):
                outcome["finish"](path, record["outcome_nonce"],
                    "interrupted" if isinstance(error, (KeyboardInterrupt, SystemExit)) else "failed", True)
            raise
        if not getattr(self.ops, "last_group_quiescent", False):
            raise Failure("canary_quiescence_unconfirmed")
        receipt = outcome["finish"](path, record["outcome_nonce"], "completed", True)
        if receipt["phase"] != "mutation_possible":
            raise Failure("canary_creation_not_proven")
        return result

    def canary_no_create(self, record):
        return self.canary_outcome_proves(record, "no_create")

    def canary_outcome_proves(self, record, predicate):
        if record.get("outcome_file") != "canary-outcome.json":
            return False
        outcome = runpy.run_path(str(ROOT / "deploy/canary_outcome.py"))
        return outcome[predicate](self.journal.folder / record["outcome_file"], self.run_id,
            record.get("outcome_nonce"), str(self.journal.folder / "canary.state"), record.get("delegate_sha256"))

    def wait_workload(self, pod_name, config_sha):
        end = time.monotonic() + 600
        while time.monotonic() < end:
            if self.scalar("pod", pod_name, "{.metadata.uid}", self.ns) != self.journal.data["context"]["pod_uid"]:
                raise Failure("workload_pod_identity_changed")
            raw = self.kube("logs", pod_name, "-n", self.ns, "--limit-bytes=65537").decode()
            if guest_document(raw, self.run_id, self.journal.data["context"]["pod_uid"], config_sha) is not None:
                return raw  # Includes a reported task failure; it must still be graded.
            time.sleep(2)
        raise Failure("workload_result_deadline")

    def standard_grade(self, pod_name, job_uid, config_sha):
        request = {"pod": {"kubeconfig": str(self.kubeconfig), "context": self.cluster,
                   "endpoint": self.delegated_state()["endpoint"], "run_id": self.run_id,
                   "namespace": self.ns, "name": pod_name, "uid": self.journal.data["context"]["pod_uid"],
                   "job_uid": job_uid, "image": self.image, "container_id": self.journal.data["task_container_id"], "config_sha256": config_sha},
                   "canary_state": str(self.journal.folder / "canary.state"),
                   "contract": self.journal.data["workload_contract"], "upload_hosts": self.upload_hosts}
        # MEAS-7: the same literal address the workload used, from its frozen policy.
        if HOSTNAME in self.upload_hosts:
            request["upload_addresses"] = {HOSTNAME: self.journal.data["endpoint_resolution"]["ipv4"][0]}
        if self.controller == "host":
            request["pod"]["clean_environment"] = True
        # No retries: an ambiguous launch cannot become a second assessment.
        bundle = strict(self.ops.call([str(self.journal.folder / "standard-grade")],
            payload=encoded(request), env=self.env, timeout=500, limit=4 << 20).decode(), 4 << 20)
        report = bundle["report"]
        expected_schema = "sandprobe/3" if self.controller == "host" else "sandprobe/1"
        if (report["schema"] != expected_schema or report["run"]["box"]["provider_id"] != request["pod"]["uid"]
                or report["run"]["provider"] != "aws-nitro"):
            raise Failure("standard_report_binding_mismatch")
        for name, data in [("legacy-standard-report.json", encoded(report)),
                           ("legacy-standard-report.html", bundle["html"].encode()),
                           ("standard-evidence.json", encoded({k:v for k,v in bundle.items() if k != "html"}))]:
            fd = os.open(self.journal.folder / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "wb") as output:
                output.write(data); output.flush(); os.fsync(output.fileno())
        self.journal.data["standard_assessment"] = {"grade": report["grade"],
            "run_id": report["run"]["id"], "pod_uid": request["pod"]["uid"],
            "config_sha256": config_sha, "image": self.image, "report": "legacy-standard-report.json"}
        self.journal.save()

    def projection(self, kind, name, expression, namespace=None):
        args = ["get", kind, name, "-o", "jsonpath-as-json=" + expression]
        if namespace:
            args += ["-n", namespace]
        values = strict(self.guard_read(self.kube, *args).decode(), 1 << 20)
        if not isinstance(values, list) or len(values) > 1:
            raise Failure("invalid_config_projection")
        return values[0] if values else None

    def template_result(self, name, source):
        return self.guard_read(self.kube, "get", "pod", name, "-n", self.ns, "-o", "go-template=" + source).decode()

    def validate_task_structure(self, name):
        self.stage("task_guard_structure")
        expected_sc = {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                       "privileged": False, "capabilities": {"drop": ["ALL"]}}
        if self.projection("pod", name, "{.spec.containers[0].securityContext}", self.ns) != expected_sc:
            raise Failure("unexpected_container_security_override")
        expected_pod = {"runAsUser": 10001, "runAsGroup": 10001, "runAsNonRoot": True,
                        "fsGroup": 10001, "seccompProfile": {"type": "RuntimeDefault"}}
        actual_pod = self.projection("pod", name, "{.spec.securityContext}", self.ns)
        if not isinstance(actual_pod, dict):
            raise Failure("missing_pod_security_context")
        for key, default in [("fsGroupChangePolicy", "Always"), ("supplementalGroupsPolicy", "Merge")]:
            if actual_pod.get(key) == default:
                actual_pod.pop(key)
        if actual_pod != expected_pod:
            raise Failure("unexpected_pod_security_override")
        if self.controller == "host":
            volumes = self.projection("pod", name, "{.spec.volumes}", self.ns)
            mounts = self.projection("pod", name, "{.spec.containers[0].volumeMounts}", self.ns)
            if not host_workload.valid_storage(volumes, mounts):
                raise Failure("unexpected_host_controller_storage")
        else:
            volumes = self.projection("pod", name, "{.spec.volumes}", self.ns)
            if not isinstance(volumes, list) or len(volumes) != 3:
                raise Failure("unexpected_volume_set")
            by_name = {v.get("name"): v for v in volumes}
            if len(by_name) != 3 or set(by_name) != {"workspace", "scratch", "eks-pod-identity-token"}:
                raise Failure("unexpected_volume_set")
            for key in ["workspace", "scratch"]:
                if by_name[key] != {"name": key, "emptyDir": {"sizeLimit": "64Mi"}}:
                    raise Failure("unexpected_volume_source")
            token = by_name["eks-pod-identity-token"]
            projected = token.get("projected", {})
            if set(token) != {"name", "projected"} or set(projected) - {"defaultMode", "sources"}:
                raise Failure("unexpected_identity_volume")
            sources = projected.get("sources")
            if (projected.get("defaultMode", 420) != 420 or not isinstance(sources, list) or len(sources) != 1
                    or set(sources[0]) != {"serviceAccountToken"}):
                raise Failure("unexpected_identity_projection")
            value = sources[0]["serviceAccountToken"]
            lifetime = value.get("expirationSeconds")
            if (set(value) != {"audience", "path", "expirationSeconds"} or value.get("audience") != "pods.eks.amazonaws.com"
                    or value.get("path") != "eks-pod-identity-token" or type(lifetime) is not int
                    or not 3600 <= lifetime <= 86400):
                raise Failure("unexpected_identity_token_context")
            mounts = self.projection("pod", name, "{.spec.containers[0].volumeMounts}", self.ns)
            if not isinstance(mounts, list) or len(mounts) != 3:
                raise Failure("unexpected_mount_set")
            mount_map = {m.get("name"): m for m in mounts}
            expected_mounts = {"workspace": {"name": "workspace", "mountPath": "/workspace"},
                               "scratch": {"name": "scratch", "mountPath": "/tmp"},
                               "eks-pod-identity-token": {"name": "eks-pod-identity-token", "mountPath": "/var/run/secrets/pods.eks.amazonaws.com/serviceaccount", "readOnly": True}}
            for mount in mount_map.values():
                if mount.get("readOnly") is False:
                    mount.pop("readOnly")
            if mount_map != expected_mounts or len(mount_map) != 3:
                raise Failure("unexpected_mount_options")
        if self.projection("pod", name, "{.spec.nodeSelector}", self.ns) != self.task_node_selector():
            raise Failure("unexpected_node_selector")
        tolerations = self.projection("pod", name, "{.spec.tolerations}", self.ns)
        if not isinstance(tolerations, list) or not 1 <= len(tolerations) <= 3:
            raise Failure("unexpected_tolerations")
        own = {"key": "sandprobe.run", "operator": "Equal", "value": self.run_id, "effect": "NoSchedule"}
        if tolerations.count(own) != 1:
            raise Failure("missing_dedicated_node_toleration")
        for entry in tolerations:
            if entry == own:
                continue
            if entry not in [{"key": key, "operator": "Exists", "effect": "NoExecute", "tolerationSeconds": 300}
                             for key in ["node.kubernetes.io/not-ready", "node.kubernetes.io/unreachable"]]:
                raise Failure("unexpected_toleration")
        if self.projection("pod", name, "{.spec.containers[0].volumeDevices}", self.ns):
            raise Failure("unexpected_volume_device")
        # Unknown env values never reach the host; only fixed expected values are
        # compared inside the projection. Missing/duplicate entries reject.
        self.stage("task_guard_environment")
        expected = {"SANDPROBE_MODEL_ID": self.journal.data["model"], "AWS_REGION": REGION,
                    "AWS_EC2_METADATA_DISABLED": "true", "HOME": "/opt/sandprobe/home", "XDG_CACHE_HOME":"/workspace/.cache", "SANDPROBE_RUN_ID": self.run_id,
                    "SANDPROBE_RECEIVER_IP": self.journal.data["receiver_ip"],
                    "SANDPROBE_AGENT_NONCE": self.journal.data["nonces"][1],
                    "SANDPROBE_CONFIG_SHA256": self.journal.data["context"]["config_sha256"],
                    "AWS_CONTAINER_CREDENTIALS_FULL_URI": "http://169.254.170.23/v1/credentials",
                    "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE": "/var/run/secrets/pods.eks.amazonaws.com/serviceaccount/eks-pod-identity-token"}
        if self.controller == "host":
            for key in ["AWS_CONTAINER_CREDENTIALS_FULL_URI", "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE"]:
                del expected[key]
        optional = {} if self.controller == "host" else {"AWS_DEFAULT_REGION": REGION, "AWS_STS_REGIONAL_ENDPOINTS": "regional"}
        names = list(expected) + list(optional) + ["SANDPROBE_POD_UID"]
        allowed = " ".join("(eq .name " + json.dumps(key) + ")" for key in names)
        source = "{{with index .spec.containers 0}}{{range .env}}{{if not (or " + allowed + ")}}unexpected{{end}}{{end}}{{end}}"
        if self.template_result(name, source):
            raise Failure("unexpected_environment_entry")
        for key, value in dict(expected, **optional).items():
            source = ('{{with index .spec.containers 0}}{{range .env}}{{if eq .name ' + json.dumps(key)
                      + '}}{{if and (eq .value ' + json.dumps(value) + ') (not .valueFrom)}}match{{else}}mismatch{{end}}{{end}}{{end}}{{end}}')
            actual = self.template_result(name, source)
            if actual != "match" and not (key in optional and actual == ""):
                raise Failure("missing_changed_or_duplicate_expected_environment")
        source = '{{with index .spec.containers 0}}{{range .env}}{{if eq .name "SANDPROBE_POD_UID"}}{{if and (not .value) (eq .valueFrom.fieldRef.fieldPath "metadata.uid")}}match{{else}}mismatch{{end}}{{end}}{{end}}{{end}}'
        if self.template_result(name, source) != "match":
            raise Failure("unexpected_pod_identity_binding")
        source = '{{with index .spec.containers 0}}{{if or .lifecycle .startupProbe .livenessProbe .readinessProbe .args}}unexpected{{end}}{{end}}'
        if self.template_result(name, source):
            raise Failure("unexpected_container_hook_or_arguments")
        command = host_workload.IDLE_COMMAND if self.controller == "host" else ["python", "-I", "/opt/sandprobe/execute.py"]
        pieces = ["(eq (len .command) " + str(len(command)) + ")"] + ["(eq (index .command " + str(i) + ") " + json.dumps(value) + ")" for i, value in enumerate(command)]
        source = '{{with index .spec.containers 0}}{{if and ' + ' '.join(pieces) + '}}match{{else}}mismatch{{end}}{{end}}'
        if self.template_result(name, source) != "match":
            raise Failure("unexpected_task_command")
        source = '{{if or .spec.hostAliases .spec.dnsConfig .spec.shareProcessNamespace}}unexpected{{end}}'
        if self.template_result(name, source):
            raise Failure("unexpected_pod_routing_or_process_override")
        if self.controller == "host":
            host_workload.fixture_context(self, name)
            return
        # File metadata only; token value is consumed solely by the SDK later.
        self.stage("task_guard_token_metadata")
        result = self.guard_read(self.kube, "exec", name, "-n", self.ns, "--", "python", "-I", "-c",
            "import os,stat;s=os.stat('/var/run/secrets/pods.eks.amazonaws.com/serviceaccount/eks-pod-identity-token');assert stat.S_ISREG(s.st_mode) and 0<s.st_size<16384;print('present')")
        if result.strip() != b"present":
            raise Failure("intended_identity_token_not_present")

    def verify_task_pod(self, name, job_uid):
        # Gate model/code execution until a narrow returned-config projection matches.
        self.kube("wait", "pod/" + name, "-n", self.ns, "--for=condition=Ready", "--timeout=15m", timeout=930)
        self.stage("task_guard_configuration")
        pairs = {"{.metadata.ownerReferences[0].uid}": job_uid, "{.spec.runtimeClassName}": "isolated-sandbox",
                 "{.spec.serviceAccountName}": "model-task", "{.spec.automountServiceAccountToken}": "false",
                 "{.spec.hostNetwork}": "false", "{.spec.hostPID}": "false", "{.spec.hostIPC}": "false",
                 "{.spec.securityContext.runAsUser}": "10001", "{.spec.securityContext.runAsGroup}": "10001",
                 "{.spec.securityContext.runAsNonRoot}": "true", "{.spec.securityContext.seccompProfile.type}": "RuntimeDefault",
                 "{.spec.containers[0].image}": self.image,
                 "{.spec.containers[0].securityContext.readOnlyRootFilesystem}": "true",
                 "{.spec.containers[0].securityContext.allowPrivilegeEscalation}": "false",
                 "{.spec.containers[0].securityContext.privileged}": "false",
                 "{.spec.containers[0].securityContext.capabilities.drop[*]}": "ALL",
                 "{.spec.containers[0].securityContext.capabilities.add[*]}": "",
                 "{.spec.initContainers[*].name}": "", "{.spec.ephemeralContainers[*].name}": "",
                 "{.spec.containers[*].name}": "agent", "{.spec.containers[0].envFrom[*]}": ""}
        for field, expected in pairs.items():
            actual = self.guard_read(self.scalar, "pod", name, field, self.ns)
            if field in {"{.spec.hostNetwork}", "{.spec.hostPID}", "{.spec.hostIPC}"} and actual == "":
                actual = "false" # Kubernetes omits false non-pointer flags.
            if actual != expected:
                raise Failure("returned_task_configuration_mismatch")
        self.validate_task_structure(name)
        self.stage("task_guard_node_binding")
        node = self.guard_read(self.scalar, "pod", name, "{.spec.nodeName}", self.ns)
        if self.guard_read(self.scalar, "node", node, "{.metadata.labels.karpenter\\.sh/nodepool}") != self.name:
            raise Failure("task_not_on_dedicated_enforcement_nodepool")
        if self.guard_read(self.scalar, "nodeclass", self.name, "{.spec.networkPolicy}") != "DefaultDeny":
            raise Failure("startup_network_policy_not_declared")
        self.stage("task_guard_image_binding")
        image_id = self.guard_read(self.scalar, "pod", name, "{.status.containerStatuses[0].imageID}", self.ns)
        if not runtime_image_matches(self.image, image_id):
            raise Failure("task_image_identity_mismatch")
        self.journal.data["runtime_image_id"] = image_id
        uid = self.scalar("pod", name, "{.metadata.uid}", self.ns)
        if not re.fullmatch(r"[a-f0-9-]{16,64}", uid):
            raise Failure("task_pod_identity_missing")
        original_uid = self.journal.data["context"]["pod_uid"]
        if original_uid != "pending" and uid != original_uid:
            raise Failure("workload_pod_identity_changed")
        container_id = self.scalar("pod", name, "{.status.containerStatuses[0].containerID}", self.ns)
        if (not re.fullmatch(r"[a-z][a-z0-9+\-]*://[a-f0-9]{32,128}", container_id)
                or self.journal.data.get("task_container_id", container_id) != container_id):
            raise Failure("workload_container_identity_changed")
        self.journal.data["task_container_id"] = container_id
        self.journal.data["context"]["pod_uid"] = uid
        self.journal.save()

    def collect_receiver(self):
        context = self.journal.data.get("context", {})
        nonces = self.journal.data.get("nonces", [])
        if not context.get("receiver_uid") or len(nonces) != 3:
            return
        receiver_ns = self.name + "-receiver"
        if self.scalar("pod", "receiver", "{.metadata.uid}", receiver_ns) != context["receiver_uid"]:
            raise Failure("receiver_identity_changed")
        raw = self.kube("exec", "receiver", "-n", receiver_ns, "--", "python", "-I", "-c",
            "import sys;sys.stdout.buffer.write(open('/tmp/receipts.json','rb').read(4097))")
        receipts = strict(raw.decode(), 4096)
        if (set(receipts) != {"nonces"} or not isinstance(receipts["nonces"], list)
                or any(not isinstance(n, str) or n not in nonces for n in receipts["nonces"])
                or len(set(receipts["nonces"])) != len(receipts["nonces"])):
            raise Failure("invalid_receiver_receipts")
        previous = self.journal.data.get("receipts", {})
        seen = set(previous.get("nonces", [])) if previous.get("receiver_uid") == context["receiver_uid"] else set()
        seen.update(receipts["nonces"])
        self.journal.data["receipts"] = {"receiver_uid": context["receiver_uid"], "nonces": sorted(seen)}
        self.journal.save()

    def cleanup(self):
        self.ops.deadline = time.monotonic() + 1800
        self.account()
        failures = []
        resources = self.journal.data["resources"]
        # Preserve external evidence on failed/timed-out/interrupted Job paths.
        if self.kubeconfig is None and resources.get("cluster", {}).get("status") == "created":
            try:
                values = self.delegated_state()
                candidate = Path(values.get("kubeconfig", ""))
                if (values.get("cluster") == resources["cluster"].get("name")
                        and candidate.parent == self.journal.folder
                        and re.fullmatch(r"eks-[a-f0-9]{8}\.kubeconfig", candidate.name)):
                    self.cluster, self.kubeconfig = values["cluster"], candidate
            except Exception:
                self.journal.data.setdefault("collection_errors", []).append("context_unavailable")
        if self.kubeconfig is not None:
            for stage in ("before_stop", "after_stop"):
                try:
                    if stage == "after_stop":
                        job = resources.get(f"kube:Job:{self.ns}:model-task", {})
                        if job.get("status") == "created":
                            self.delete_job()
                        receiver_ip = self.journal.data.get("receiver_ip")
                        if receiver_ip and self.journal.data.get("nonces"):
                            self.control(receiver_ip, self.journal.data["nonces"][2])
                    self.collect_receiver()
                except Exception:
                    self.journal.data.setdefault("collection_errors", []).append(stage)
                    try:
                        self.collect_receiver()
                    except Exception:
                        pass
            self.journal.save()
        # Deleting the dedicated cluster confirms all of its run-owned Kubernetes
        # children gone, including uncertain child creates. IDN-2 also resolves
        # unknown associations only after an independent parent-absence check.
        # Independent external creates remain unresolved rather than guess-deleted.
        unresolved_association = False
        if "association" in resources and resources["association"].get("status") not in {"deleted", "deleted_with_cluster"}:
            record = resources["association"]
            try:
                if not record.get("association_id"):
                    # IDN-2: defer unknown children until parent deletion is proven.
                    unresolved_association = True
                    raise Failure("unknown_association_create")
                self.cluster = resources["cluster"]["name"]
                data = self.aws("eks", "describe-pod-identity-association", "--cluster-name", self.cluster,
                    "--association-id", record["association_id"], query="association")
                if (data["associationArn"] != record["arn"] or data["namespace"] != self.ns
                        or data["serviceAccount"] != "model-task" or data["roleArn"] != resources["role"]["arn"]):
                    raise Failure("association_identity_mismatch")
                self.aws("eks", "delete-pod-identity-association", "--cluster-name", self.cluster,
                    "--association-id", record["association_id"])
                try:
                    self.aws("eks", "describe-pod-identity-association", "--cluster-name", self.cluster,
                             "--association-id", record["association_id"])
                    raise Failure("association_still_exists")
                except Failure as error:
                    if str(error) != "resource_not_found":
                        raise
                record["status"] = "deleted"
            except Failure as error:
                if str(error) == "resource_not_found":
                    record["status"] = "deleted"
                elif str(error) != "unknown_association_create":
                    failures.append("association_cleanup_unconfirmed")
            self.journal.save()
        if "cluster" in resources and resources["cluster"].get("status") != "deleted":
            try:
                state = self.journal.folder / "eks.state"
                if not state.exists():
                    raise Failure("delegated_cluster_state_unavailable")
                self.ops.call(["bash", str(ROOT / "deploy/eks.sh"), "down"],
                    env=dict(self.env, PROFILE=self.profile, REGION=REGION, DURABLE_STATE="1", STATE=str(state)), timeout=1500)
                resources["cluster"]["status"] = "deleted"
                for key, record in resources.items():
                    if key.startswith("kube:"):
                        record["status"] = "deleted_with_cluster"
            except Failure:
                failures.append("cluster_cleanup_unconfirmed")
            self.journal.save()
        if unresolved_association:
            try:
                cluster = resources.get("cluster", {})
                if (cluster.get("status") != "deleted" or not cluster.get("arn")
                        or resources["association"].get("cluster") != cluster.get("name")):
                    raise Failure("association_parent_not_confirmed_deleted")
                try:
                    self.aws("eks", "describe-cluster", "--name", cluster["name"])
                    raise Failure("association_parent_still_exists")
                except Failure as error:
                    if str(error) != "resource_not_found":
                        raise
                resources["association"]["status"] = "deleted_with_cluster"
            except Failure:
                failures.append("association_cleanup_unconfirmed")
            self.journal.save()
        if "role" in resources and resources["role"].get("status") != "deleted":
            record = resources["role"]
            try:
                if not record.get("role_id"):
                    raise Failure("unknown_role_create")
                role = self.aws("iam", "get-role", "--role-name", self.name, query="Role")
                tags = {t["Key"]: t["Value"] for t in role.get("Tags", [])}
                if role["RoleId"] != record["role_id"] or tags.get("sandprobe:run") != self.run_id:
                    raise Failure("role_identity_mismatch")
                policies = self.aws("iam", "list-role-policies", "--role-name", self.name, query="PolicyNames")
                if set(policies) - {self.name}:
                    raise Failure("unexpected_role_policy")
                if self.name in policies:
                    self.aws("iam", "delete-role-policy", "--role-name", self.name, "--policy-name", self.name)
                self.aws("iam", "delete-role", "--role-name", self.name)
                try:
                    self.aws("iam", "get-role", "--role-name", self.name)
                    raise Failure("role_still_exists")
                except Failure as error:
                    if str(error) != "resource_not_found":
                        raise
                record["status"] = "deleted"
            except Failure as error:
                if str(error) == "resource_not_found":
                    record["status"] = "deleted"
                else:
                    failures.append("role_cleanup_unconfirmed")
            self.journal.save()
        if "repository" in resources and resources["repository"].get("status") != "deleted":
            record = resources["repository"]
            try:
                if not record.get("arn"):
                    raise Failure("unknown_repository_create")
                repo = self.aws("ecr", "describe-repositories", "--repository-names", self.name, query="repositories[0]")
                tags = self.aws("ecr", "list-tags-for-resource", "--resource-arn", record["arn"], query="tags")
                if (repo["repositoryArn"] != record["arn"] or repo["createdAt"] != record["created_at"]
                        or {t["Key"]: t["Value"] for t in tags}.get("sandprobe:run") != self.run_id):
                    raise Failure("repository_identity_mismatch")
                self.aws("ecr", "delete-repository", "--repository-name", self.name, "--force")
                try:
                    self.aws("ecr", "describe-repositories", "--repository-names", self.name)
                    raise Failure("repository_still_exists")
                except Failure as error:
                    if str(error) != "resource_not_found":
                        raise
                record["status"] = "deleted"
            except Failure as error:
                if str(error) == "resource_not_found":
                    record["status"] = "deleted"
                else:
                    failures.append("repository_cleanup_unconfirmed")
            self.journal.save()
        if "local_image" in resources and resources["local_image"].get("status") != "deleted":
            try:
                image = resources["local_image"].get("image_id", "")
                if not re.fullmatch(r"sha256:[a-f0-9]{64}", image):
                    raise Failure("invalid_local_image_identity")
                self.ops.call(["docker", "image", "rm", image], timeout=60)
                resources["local_image"]["status"] = "deleted"
            except Failure:
                failures.append("local_image_cleanup_unconfirmed")
        # RUN-8: a failed kubectl client may leave the in-box probe running.
        # Release the canary address only after the original cluster is gone.
        self.ops.deadline = time.monotonic() + 900
        if "canary" in resources and resources["canary"].get("status") not in ("deleted", "not_created", "reconciled_no_cloud_create"):
            try:
                if resources.get("cluster", {}).get("status", "deleted") != "deleted":
                    raise Failure("probe_cluster_stop_unconfirmed")
                if self.canary_no_create(resources["canary"]):
                    resources["canary"]["status"] = "not_created"
                else:
                    if ("outcome_file" in resources["canary"] and
                            not self.canary_outcome_proves(resources["canary"], "stopped")):
                        raise Failure("canary_create_worker_unconfirmed")
                    if not (self.journal.folder / "canary.state").is_file():
                        raise Failure("canary_create_unresolved")
                    self.canary("down", timeout=900)
                    resources["canary"]["status"] = "deleted"
            except Exception:
                failures.append("canary_cleanup_unconfirmed")
        if self.archive_handle is not None:
            self.archive_handle.close()
            self.archive_handle = None
        artifact_folder = self.journal.folder / "image-artifact"
        if artifact_folder.exists():
            try:
                directory(artifact_folder)
                shutil.rmtree(artifact_folder)
            except Exception:
                failures.append("local_image_artifact_cleanup_unconfirmed")
        auth_file = self.journal.folder / "registry-auth.json"
        if auth_file.exists():
            auth_file.unlink()
        self.journal.data.update(cleanup_confirmed=not failures, cleanup_failures=failures,
                                 phase="cleaned" if not failures else "cleanup_incomplete")
        self.journal.save()
        return not failures


def main():
    def interrupted(signum, frame):
        raise KeyboardInterrupt()
    signal.signal(signal.SIGTERM, interrupted)
    parser = FixedErrorParser(description=__doc__)
    parser.add_argument("command", choices=["preflight", "run", "cleanup"])
    parser.add_argument("--model")
    parser.add_argument("--approval-ref")
    parser.add_argument("--run-id")
    parser.add_argument("--image-run-id")
    parser.add_argument("--profile", default=PROFILE)
    parser.add_argument("--controller", choices=["guest", "host"], default="guest")
    parser.add_argument("--model-python", default="")
    parser.add_argument("--upload-hosts", default="", help="explicit shipped workload names for TLS-only EGR-6")
    journal = None
    try:
        args = parser.parse_args()
        parse_hosts = runpy.run_path(str(ROOT / "deploy/workload_measurement.py"))["upload_hosts"]
        approved_hosts = parse_hosts(args.upload_hosts)
        if not re.fullmatch(r"[0-9]{12}", ACCOUNT) or not args.profile:
            raise Failure("aws_account_and_profile_required")
        if args.command == "cleanup":
            if not args.run_id:
                raise Failure("cleanup_run_identity_required")
            journal = Journal(STATE_ROOT, args.run_id)
        else:
            if not args.model:
                raise Failure("model_required")
            if not args.approval_ref:
                raise Failure("aws_eks_testing_approval_reference_required")
            journal = Journal(STATE_ROOT, secrets.token_hex(8), create=True)
        runner = Runner(journal, args.profile, upload_hosts=approved_hosts, controller=args.controller, model_python=args.model_python)
        if args.command == "cleanup":
            clean = runner.cleanup()
            print(json.dumps({"run_id": runner.run_id, "cleanup_confirmed": clean}))
            return 0 if clean else 5
        runner.preflight(args.model, args.approval_ref, args.image_run_id)
        if args.command == "preflight":
            print(json.dumps({"run_id": runner.run_id, "preflight": "passed", "live_resources": "none"}))
            return 0
        error = None
        try:
            runner.execute()
        except (Exception, KeyboardInterrupt) as failure:
            error = "evaluation_execution_failed"
            journal.data["execution_failure"] = failure_category(failure)
            journal.save()
        finally:
            try:
                clean = runner.cleanup()
            except (Exception, KeyboardInterrupt):
                clean = False
                journal.data.update(cleanup_confirmed=False, phase="cleanup_incomplete")
                journal.save()
        context = journal.data.get("context", {})
        report = evaluate(context, journal.data.get("guest", ""), journal.data.get("receipts"),
                          journal.data.get("nonces", []), clean)
        scoped = report
        assessment = None
        if journal.data.get("standard_assessment"):
            try:
                assessment = runner.finalize_workload_grade(scoped["workload"])
            except Exception:
                journal.data["workload_grading_failure"] = "workload_assessment_unavailable"
                journal.save()
        report = {"schema": "sandprobe.workload-evaluation/2", "run_id": runner.run_id,
                  "workload": scoped["workload"], "task": scoped["task"],
                  "configuration_assessment": assessment, "collection": "live_managed_run",
                  "primary_assessment": "rc_exposure_scorecard", "exposure_scorecard": journal.data.get("exposure_scorecard"),
                  "configuration_assessment_status": "collected" if assessment else "missing",
                  "configuration_grading_failure": journal.data.get("workload_grading_failure"),
                  "security_assurance": "not_established_against_active_guest_tampering",
                  "cleanup": scoped["cleanup"], "legacy_receiver_assessment": scoped}
        report["legacy_generic_assessment"] = journal.data.get("standard_assessment")
        report["legacy_generic_assessment_status"] = "collected" if report["legacy_generic_assessment"] else "missing"
        report["run_error"] = error
        report["execution_stage"] = journal.data.get("execution_stage")
        report["execution_failure"] = journal.data.get("execution_failure")
        journal.data["assessment"] = report
        journal.save()
        print(json.dumps(report, sort_keys=True))
        if scoped["security_grade"] == "F" or (assessment and assessment["configuration_grade"] in {"D", "F"}):
            exit_code = 6
        else:
            exit_code = 0 if (assessment and assessment["benchmark_requirements_met"] and clean and error is None) else 5
        print(completion_message(report["exposure_scorecard"], scoped["workload"] == "reported_passed",
                                 clean, assessment, exit_code, error is None), file=sys.stderr)
        return exit_code
    except (Exception, KeyboardInterrupt) as error:
        code = str(error) if isinstance(error, Failure) else "invalid_request_or_preflight_failed"
        # Failure values originate only in fixed messages, never SDK/subprocess text.
        print(json.dumps({"error": code, "run_id": journal.data["run_id"] if journal else None}), file=sys.stderr)
        return 2
    finally:
        if journal is not None:
            journal.close()


if __name__ == "__main__":
    sys.exit(main())
