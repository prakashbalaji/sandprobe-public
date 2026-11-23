import copy
import json
import subprocess
import sys
import unittest
from pathlib import Path

import render_profile as profile


class ProfileTests(unittest.TestCase):
    def test_persistent_artifacts_keeps_coding_workspace_cache_and_network(self):
        args=self.settings();args.update(controller="host",model=profile.LIGHTWEIGHT_MODEL)
        before=profile.render(**args)
        plan=profile.render(**args,storage_profile="persistent-artifacts",workspace_volume={"id":"vol-"+"b"*17,"zone":"us-west-2a"})
        previous=before["kubernetes"]["items"][-1]["spec"]["template"]["spec"]
        current=plan["kubernetes"]["items"][-1]["spec"]["template"]["spec"]
        previous["volumes"].append({"name":"artifacts","persistentVolumeClaim":{"claimName":"artifacts"}})
        previous["containers"][0]["volumeMounts"].append({"name":"artifacts","mountPath":"/persist"})
        self.assertEqual(current,previous)
        before_policies=[v for v in before["kubernetes"]["items"] if v["kind"]=="NetworkPolicy"]
        after_policies=[v for v in plan["kubernetes"]["items"] if v["kind"]=="NetworkPolicy"]
        self.assertEqual(before_policies,after_policies)
        self.assertEqual(plan["storage_context"]["mount_path"],"/persist")
    def test_persistent_workspace_preserves_network_and_agent_controls(self):
        args = self.settings()
        args.update(controller="host", model=profile.LIGHTWEIGHT_MODEL)
        baseline = profile.render(**args)
        binding={"id":"vol-"+"b"*17,"zone":"us-west-2a"}
        plan = profile.render(**args, storage_profile="persistent-workspace",workspace_volume=binding)
        self.assertEqual(plan["storage_profile"], "persistent-workspace")
        before = {v["kind"] + ":" + v["metadata"]["name"]: v for v in baseline["kubernetes"]["items"]}
        after = {v["kind"] + ":" + v["metadata"]["name"]: v for v in plan["kubernetes"]["items"]}
        for name in ("NetworkPolicy:deny-by-default", "NetworkPolicy:model-task-egress"):
            self.assertEqual(after[name], before[name])
        old = copy.deepcopy(before["Job:model-task"])
        old["spec"]["template"]["spec"]["volumes"][0] = {
            "name": "workspace", "persistentVolumeClaim": {"claimName": "workspace"}}
        old["spec"]["template"]["spec"]["securityContext"]["fsGroupChangePolicy"]="OnRootMismatch"
        self.assertEqual(after["Job:model-task"], old)
        sc = after["StorageClass:sandprobe-workspace-0123456789abcdef"]
        self.assertEqual(sc["provisioner"], "ebs.csi.eks.amazonaws.com")
        self.assertEqual(sc["parameters"], {"type": "gp3", "encrypted": "true"})
        self.assertEqual((sc["reclaimPolicy"], sc["volumeBindingMode"]), ("Retain", "WaitForFirstConsumer"))
        claim = after["PersistentVolumeClaim:workspace"]
        self.assertEqual(claim["metadata"]["namespace"], "sandprobe-agent-0123456789abcdef")
        self.assertEqual(claim["spec"]["storageClassName"], sc["metadata"]["name"])
        self.assertEqual(claim["spec"]["volumeName"],sc["metadata"]["name"])
        self.assertNotIn("selector", claim["spec"])
        pv=after["PersistentVolume:"+sc["metadata"]["name"]]["spec"]
        self.assertEqual(pv["csi"],{"driver":"ebs.csi.eks.amazonaws.com","volumeHandle":binding["id"],"fsType":"ext4"})
        self.assertEqual(pv["claimRef"],{"namespace":claim["metadata"]["namespace"],"name":"workspace"})
        self.assertEqual(pv["nodeAffinity"]["required"]["nodeSelectorTerms"][0]["matchExpressions"][0]["values"],[binding["zone"]])
        self.assertEqual(plan["storage_context"]["provenance"],"caller_supplied_unverified")
        self.assertEqual((plan["live_status"], plan["security_grade"]), ("not_executed", "not_assessed"))

    def test_persistent_workspace_rejects_unrecognized_or_guest_profile(self):
        for value in ("persistent-workspace", "existing-production-claim", "../claim", None):
            with self.subTest(value=value), self.assertRaises(ValueError):
                profile.render(**self.settings(), storage_profile=value)
        args=self.settings();args.update(controller="host",model=profile.LIGHTWEIGHT_MODEL)
        for binding in (None,{}, {"id":"named-existing-volume","zone":"us-west-2a"},
                        {"id":"vol-"+"b"*17,"zone":"other-region-a"},
                        {"id":"vol-"+"b"*17,"zone":"us-west-2a","mount":"/host"}):
            with self.subTest(binding=binding),self.assertRaises(ValueError):
                profile.render(**args,storage_profile="persistent-workspace",workspace_volume=binding)

    def settings(self):
        run = "0123456789abcdef"
        return dict(run_id=run, image=f"111122223333.dkr.ecr.us-west-2.amazonaws.com/sandprobe-agent-{run}@sha256:" + "a" * 64,
                    account="111122223333", model="anthropic.claude-3-haiku-20240307-v1:0",
                    endpoint_ips=["52.94.0.1"], dns_ip="172.20.0.10")

    def test_useful_but_scoped_plan(self):
        p = profile.render(**self.settings())
        self.assertEqual((p["live_status"], p["security_grade"]), ("not_executed", "not_assessed"))
        self.assertEqual(p["endpoint_context"]["provenance"], "caller_supplied_unverified")
        items = {v["kind"] + ":" + v["metadata"]["name"]: v for v in p["kubernetes"]["items"]}
        job = items["Job:model-task"]["spec"]
        self.assertEqual((job["backoffLimit"], job["parallelism"], job["activeDeadlineSeconds"]), (0, 1, 180))
        spec = job["template"]["spec"]
        self.assertEqual(spec["runtimeClassName"], "isolated-sandbox")
        self.assertNotIn("annotations", job["template"]["metadata"])
        self.assertFalse(spec["automountServiceAccountToken"])
        self.assertEqual(spec["securityContext"]["runAsUser"], 10001)
        self.assertEqual(spec["restartPolicy"], "Never")
        c = spec["containers"][0]
        self.assertEqual(c["securityContext"]["capabilities"]["drop"], ["ALL"])
        self.assertTrue(c["securityContext"]["readOnlyRootFilesystem"])
        self.assertFalse(c["securityContext"]["allowPrivilegeEscalation"])
        self.assertEqual({v["name"] for v in spec["volumes"]}, {"scratch", "workspace"})
        self.assertTrue(all("emptyDir" in v for v in spec["volumes"]))
        deny = items["NetworkPolicy:deny-by-default"]["spec"]
        self.assertEqual((deny["ingress"], deny["egress"]), ([], []))
        allow = items["NetworkPolicy:model-task-egress"]["spec"]["egress"]
        self.assertEqual(len(allow), 3)
        self.assertEqual(allow[1]["to"], [{"ipBlock":{"cidr":"172.20.0.10/32"}}])
        self.assertEqual([r["to"][0]["ipBlock"]["cidr"] for r in allow],
                         ["52.94.0.1/32", "172.20.0.10/32", "169.254.170.23/32"])
        statement = p["iam_policy"]["Statement"][0]
        self.assertEqual(statement["Action"], ["bedrock:InvokeModel"])
        self.assertEqual(statement["Resource"], ["arn:aws:bedrock:us-west-2::foundation-model/anthropic.claude-3-haiku-20240307-v1:0"])
        self.assertNotIn("*", json.dumps(p["iam_policy"]))

    def test_lightweight_open_model_keeps_exact_iam_scope(self):
        args = self.settings()
        args["model"] = profile.LIGHTWEIGHT_MODEL
        plan = profile.render(**args)
        statement = plan["iam_policy"]["Statement"][0]
        self.assertEqual(statement["Action"], ["bedrock:InvokeModel"])
        self.assertEqual(statement["Resource"], ["arn:aws:bedrock:us-west-2::foundation-model/"+profile.LIGHTWEIGHT_MODEL])
        for invalid in ["mistral.*", "us."+profile.LIGHTWEIGHT_MODEL, "mistral.other-model", "arn:aws:bedrock:us-west-2:111122223333:inference-profile/x"]:
            args["model"] = invalid
            with self.assertRaises(ValueError):
                profile.render(**args)

    def test_unsafe_or_unsupported_input(self):
        edits = [dict(run_id="../../production"), dict(account="*"), dict(image="image:latest"),
                 dict(model="us.anthropic.claude-3-haiku-20240307-v1:0"), dict(model="anthropic.*"),
                 dict(endpoint_ips=[]), dict(endpoint_ips=["127.0.0.1"]),
                 dict(endpoint_ips=["10.0.0.1"]), dict(endpoint_ips=["169.254.169.254"]),
                 dict(endpoint_ips=["::1"]), dict(endpoint_ips=["52.94.0.1"] * 2),
                 dict(dns_ip="169.254.169.254"), dict(dns_ip="8.8.8.8")]
        for edit in edits:
            with self.subTest(edit=edit), self.assertRaises(ValueError):
                args = copy.deepcopy(self.settings())
                args.update(edit)
                profile.render(**args)

    def test_cli_framing_error_is_sanitized(self):
        p = subprocess.run([sys.executable, str(Path(__file__).with_name("render_profile.py")),
                            "--unrecognized=synthetic-sensitive-input"], capture_output=True, text=True, timeout=10)
        self.assertEqual(p.returncode, 2)
        self.assertEqual(p.stdout, "")
        self.assertEqual(p.stderr, "profile: unsupported or unsafe configuration\n")

    def test_cli_error_does_not_echo_input(self):
        args = self.settings()
        args["run_id"] = "synthetic-sensitive-input"
        command = [sys.executable, str(Path(__file__).with_name("render_profile.py"))]
        for name, value in args.items():
            command.extend(["--" + name.replace("_", "-") if name != "endpoint_ips" else "--endpoint-ip",
                            value[0] if isinstance(value, list) else value])
        p = subprocess.run(command, capture_output=True, text=True, timeout=10)
        self.assertEqual(p.returncode, 2)
        self.assertEqual(p.stdout, "")
        self.assertEqual(p.stderr, "profile: unsupported or unsafe configuration\n")
