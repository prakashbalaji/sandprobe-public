"""NET-2..4: render-only preparation; no AWS/Kubernetes calls or DNS resolution."""
import argparse
import ipaddress
import json
from pathlib import Path
import re
import runpy
import sys

REGION = "us-west-2"
HOSTNAME = f"bedrock-runtime.{REGION}.amazonaws.com"
LIGHTWEIGHT_MODEL = "mistral.ministral-3-3b-instruct"
WORKLOAD_ENVIRONMENT = runpy.run_path(str(Path(__file__).resolve().parents[2] / "deploy" / "workload_environment.py"))["prefix"]()
IDLE_COMMAND = WORKLOAD_ENVIRONMENT + ["python", "-I", "-c", "import time;time.sleep(1800)"]


def render(run_id, image, account, model, endpoint_ips, dns_ip, controller="guest", storage_profile="ephemeral", workspace_volume=None):
    if controller == "host" and model != LIGHTWEIGHT_MODEL:
        raise ValueError("host controller requires the fixed regional model")
    if controller not in {"guest", "host"}:
        raise ValueError("invalid controller pattern")
    if storage_profile not in {"ephemeral", "persistent-workspace", "persistent-artifacts"}:
        raise ValueError("invalid storage profile")
    if storage_profile != "ephemeral" and controller != "host":
        raise ValueError("persistent workspace requires host controller")
    if storage_profile != "ephemeral":
        if (not isinstance(workspace_volume, dict) or set(workspace_volume)!={"id","zone"}
                or not isinstance(workspace_volume["id"], str) or not re.fullmatch(r"vol-[a-f0-9]{17}",workspace_volume["id"])
                or not isinstance(workspace_volume["zone"], str) or not re.fullmatch(r"us-west-2[a-d]",workspace_volume["zone"])):
            raise ValueError("persistent workspace requires an explicit volume binding")
    elif workspace_volume is not None:
        raise ValueError("unexpected volume binding")
    if not re.fullmatch(r"[0-9a-f]{16}", run_id):
        raise ValueError("invalid run identity")
    if not re.fullmatch(r"[0-9]{12}", account):
        raise ValueError("invalid account")
    repository = f"{account}.dkr.ecr.{REGION}.amazonaws.com/sandprobe-agent-{run_id}"
    if not re.fullmatch(re.escape(repository) + r"@sha256:[0-9a-f]{64}", image):
        raise ValueError("expected a pinned run-owned task image")
    if model != LIGHTWEIGHT_MODEL and not re.fullmatch(r"anthropic\.[a-z0-9][a-z0-9.:-]{1,150}", model):
        raise ValueError("expected one supported regional foundation model")
    if not 1 <= len(endpoint_ips) <= 16 or len(set(endpoint_ips)) != len(endpoint_ips):
        raise ValueError("invalid endpoint address set")
    ips = []
    for text in endpoint_ips:
        address = ipaddress.ip_address(text)
        if address.version != 4 or not address.is_global or str(address) != text:
            raise ValueError("expected public runtime IPv4 addresses")
        ips.append(text)
    dns = ipaddress.ip_address(dns_ip)
    private_ranges = [ipaddress.ip_network(cidr) for cidr in ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]]
    if dns.version != 4 or not any(dns in network for network in private_ranges) or str(dns) != dns_ip:
        raise ValueError("expected the recorded private cluster DNS address")
    namespace = "sandprobe-agent-" + run_id
    labels = {"app.kubernetes.io/managed-by": "sandprobe", "sandprobe.run": run_id}
    def metadata(name):
        return {"name": name, "namespace": namespace, "labels": dict(labels)}
    selector = {"matchLabels": {"sandprobe.run": run_id}}
    container = {"name": "agent", "image": image, "imagePullPolicy": "Always",
                 "command": ["python", "-I", "/opt/sandprobe/task.py"], "workingDir": "/workspace",
                 "env": [{"name": "SANDPROBE_MODEL_ID", "value": model},
                         {"name": "AWS_REGION", "value": REGION},
                         {"name": "AWS_EC2_METADATA_DISABLED", "value": "true"},
                         {"name": "HOME", "value": "/opt/sandprobe/home"},
                         {"name": "XDG_CACHE_HOME", "value": "/workspace/.cache"}],
                 "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                     "privileged": False, "capabilities": {"drop": ["ALL"]}},
                 "resources": {"limits": {"cpu": "1", "memory": "1Gi"},
                               "requests": {"cpu": "100m", "memory": "128Mi"}},
                 "volumeMounts": [{"name": "workspace", "mountPath": "/workspace"},
                                  {"name": "scratch", "mountPath": "/tmp"}]}
    pod = {"metadata": {"labels": dict(labels)},
           "spec": {"runtimeClassName": "isolated-sandbox", "serviceAccountName": "model-task",
                    "automountServiceAccountToken": False, "enableServiceLinks": False,
                    "restartPolicy": "Never", "hostNetwork": False, "hostPID": False, "hostIPC": False,
                    "securityContext": {"runAsUser": 10001, "runAsGroup": 10001, "runAsNonRoot": True,
                                        "fsGroup": 10001, "seccompProfile": {"type": "RuntimeDefault"}},
                    "containers": [container],
                    "volumes": [{"name": name, "emptyDir": {"sizeLimit": "64Mi"}}
                                for name in ["workspace", "scratch"]]}}
    items = [
        {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": namespace, "labels": dict(labels)}},
        {"apiVersion": "v1", "kind": "ServiceAccount", "metadata": metadata("model-task"),
         "automountServiceAccountToken": False},
        {"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy", "metadata": metadata("deny-by-default"),
         "spec": {"podSelector": selector, "policyTypes": ["Ingress", "Egress"], "ingress": [], "egress": []}},
        {"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy", "metadata": metadata("model-task-egress"),
         "spec": {"podSelector": selector, "policyTypes": ["Egress"], "egress": [
             {"to": [{"ipBlock": {"cidr": ip + "/32"}} for ip in sorted(ips)],
              "ports": [{"protocol": "TCP", "port": 443}]},
             # DNS-1: Auto Mode runs CoreDNS on-node, not as selected cluster pods.
             {"to": [{"ipBlock": {"cidr": dns_ip + "/32"}}],
              "ports": [{"protocol": protocol, "port": 53} for protocol in ["UDP", "TCP"]]},
             {"to": [{"ipBlock": {"cidr": "169.254.170.23/32"}}],
              "ports": [{"protocol": "TCP", "port": 80}]},
         ]}},
        {"apiVersion": "batch/v1", "kind": "Job", "metadata": metadata("model-task"),
         "spec": {"backoffLimit": 0, "activeDeadlineSeconds": 180, "completions": 1,
                  "parallelism": 1, "template": pod}},
    ]
    plan = {"schema": "sandprobe.networked-agent-plan/1", "live_status": "not_executed",
            "security_grade": "not_assessed", "run_id": run_id,
            "endpoint_context": {"hostname": HOSTNAME, "ipv4": sorted(ips),
                                 "provenance": "caller_supplied_unverified"},
            "kubernetes": {"apiVersion": "v1", "kind": "List", "items": items},
            "iam_policy": {"Version": "2012-10-17", "Statement": [
                {"Effect": "Allow", "Action": ["bedrock:InvokeModel"],
                 "Resource": [f"arn:aws:bedrock:{REGION}::foundation-model/{model}"]}]},
            "prerequisites": ["AWS EKS security-testing approval", "Managed exact-ID lifecycle/cleanup runner",
                              "Pinned task image built and verified", "Pre-enabled regional model access/agreement",
                              "Run-owned Pod Identity role, scoped trust and exact service-account association",
                              "Live hostname/IP resolution provenance before applying the plan",
                              "Nitro-compatible network-policy controller/startup enforcement before scheduling",
                              "Fresh run-owned namespace with no additive allow policies"],
            "limits": ["Intent only; no enforcement, reachability or model success established.",
                       "DNS queries are permitted, including their data-carrying potential.",
                       "IP filtering is not hostname filtering; shared IPs may serve other TLS names.",
                       "Endpoint changes fail connectivity; regenerate rather than broaden policy.",
                       "The intended workload-role credential is authorized; operator credentials are never mounted.",
                       "No protected-resource/reset calibration or overall security grade is supplied."]}
    if controller == "host":
        container["command"] = list(IDLE_COMMAND)
        for resource in items:
            if resource.get("kind") == "NetworkPolicy" and resource["metadata"]["name"] == "model-task-egress":
                resource["spec"]["egress"] = resource["spec"]["egress"][:2]
        plan["iam_policy"] = None
        plan["deployment_pattern"] = "host_controller_no_guest_credentials"
        plan["prerequisites"][4] = "Pinned host model client/account; no guest role or identity association"
        plan["limits"][-2] = "Model credentials remain on the trusted controller; no guest identity is assigned."
    if storage_profile != "ephemeral":
        # RUN-23: bind the explicit create-returned EBS ID; never rely on an
        # unrecorded dynamic CSI create or adopt a volume through its tags.
        artifacts=storage_profile=="persistent-artifacts"
        claim="artifacts" if artifacts else "workspace"
        storage_class = ("sandprobe-artifacts-" if artifacts else "sandprobe-workspace-") + run_id
        items.insert(1, {"apiVersion": "storage.k8s.io/v1", "kind": "StorageClass",
                         "metadata": {"name": storage_class, "labels": dict(labels)},
                         "provisioner": "ebs.csi.eks.amazonaws.com",
                         "volumeBindingMode": "WaitForFirstConsumer",
                         "reclaimPolicy": "Retain", "allowVolumeExpansion": False,
                         "parameters": {"type": "gp3", "encrypted": "true"}})
        items.insert(2, {"apiVersion": "v1", "kind": "PersistentVolume",
                         "metadata": {"name": storage_class,"labels":dict(labels)},
                         "spec": {"capacity":{"storage":"1Gi"},"volumeMode":"Filesystem",
                                  "accessModes":["ReadWriteOncePod"],"persistentVolumeReclaimPolicy":"Retain",
                                  "storageClassName":storage_class,
                                  "claimRef":{"namespace":namespace,"name":claim},
                                  "csi":{"driver":"ebs.csi.eks.amazonaws.com","volumeHandle":workspace_volume["id"],"fsType":"ext4"},
                                  "nodeAffinity":{"required":{"nodeSelectorTerms":[{"matchExpressions":[{
                                      "key":"topology.kubernetes.io/zone","operator":"In","values":[workspace_volume["zone"]]}]}]}}}})
        items.insert(3, {"apiVersion": "v1", "kind": "PersistentVolumeClaim",
                         "metadata": metadata(claim),
                         "spec": {"accessModes": ["ReadWriteOncePod"], "volumeMode": "Filesystem",
                                  "storageClassName": storage_class,
                                  "volumeName":storage_class,
                                  "resources": {"requests": {"storage": "1Gi"}}}})
        if artifacts:
            pod["spec"]["volumes"].append({"name":"artifacts","persistentVolumeClaim":{"claimName":claim}})
            container["volumeMounts"].append({"name":"artifacts","mountPath":"/persist"})
        else:
            pod["spec"]["volumes"][0] = {"name": "workspace", "persistentVolumeClaim": {"claimName": claim}}
            pod["spec"]["securityContext"]["fsGroupChangePolicy"]="OnRootMismatch"
        plan["storage_profile"] = storage_profile
        plan["storage_context"]={"volume_id":workspace_volume["id"],"zone":workspace_volume["zone"],"mount_path":"/persist" if artifacts else "/workspace","provenance":"caller_supplied_unverified"}
        plan["prerequisites"].append("Run-owned PVC/PV/EBS identity binding, proven recreation and exact-ID storage cleanup")
        plan["limits"].append("Persistent workspace is a separate profile; this plan alone supplies no reset proof.")
    return plan


class FixedErrorParser(argparse.ArgumentParser):
    def error(self, message):
        raise ValueError("invalid arguments")


def main():
    parser = FixedErrorParser(description=__doc__)
    for name in ["run-id", "image", "account", "model", "dns-ip"]:
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--endpoint-ip", action="append", required=True)
    parser.add_argument("--controller", choices=["guest", "host"], default="guest")
    try:
        args = parser.parse_args()
        plan = render(args.run_id, args.image, args.account, args.model, args.endpoint_ip, args.dns_ip, controller=args.controller)
    except ValueError:
        print("profile: unsupported or unsafe configuration", file=sys.stderr)
        return 2
    json.dump(plan, sys.stdout, sort_keys=True, indent=2)
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
