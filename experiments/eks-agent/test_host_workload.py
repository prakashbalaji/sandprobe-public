"""RUN-17: identical protocol, remote-only execution, bounded calls and identity absence."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import Mock

os.environ.setdefault("SANDPROBE_AWS_ACCOUNT", "111122223333")
os.environ.setdefault("SANDPROBE_AWS_PROFILE", "test-profile")

import host_workload
from lifecycle import Failure, Journal
from runner import Runner, ROOT, ACCOUNT
from assessment import guest_document
from render_profile import render


class HostWorkloadTests(unittest.TestCase):
    def fixture(self, directory, results=None, model_failure=False):
        data = {"model": host_workload.MODEL, "context": {"pod_uid": "original-pod"},
                "receiver_ip": "10.0.0.2", "nonces": ["a" * 48, "b" * 48, "c" * 48],
                "endpoint_resolution": {"ipv4": ["52.94.0.1"]}, "resources": {}}
        r = types.SimpleNamespace(source_root=ROOT, run_id="a" * 16, ns="owned-namespace", env={},
                                  model_python=sys.executable, cluster="owned-cluster",
                                  journal=types.SimpleNamespace(data=data, folder=Path(directory)))
        r.models = 0
        r.source = None
        outcomes = list(results or ["passed"])

        def call(args, payload=None, **kwargs):
            if Path(args[2]).name == "controller.py":
                return subprocess.run(args, input=payload, check=True, capture_output=True, timeout=10).stdout
            self.assertEqual(args[2:], [str(ROOT / "experiments/daytona-agent/model.py"), "request"])
            r.models += 1
            if model_failure:
                raise Failure("command_failed")
            request = json.loads(payload)
            self.assertEqual(request["modelId"], r.journal.data["model"])
            self.assertIn(len(request["messages"]), [1, 3])
            if len(request["messages"]) == 3:
                feedback = request["messages"][2]["content"][0]["text"]
                self.assertIn('"failed_public_examples"', feedback)
                self.assertIn('"case":9', feedback)
                self.assertIn('"raises":"ValueError"', feedback)
            # This source must never be executed by the host, even during a unit test.
            text = json.dumps({"solution.py": "raise RuntimeError('sandbox only')"})
            return json.dumps({"converse_attempted": True, "response": {"output": {"message": {"content": [{"text": text}]}}}}).encode()

        def kube(*args, payload=None, **kwargs):
            self.assertEqual(args[:2], ("exec", "-i"))
            self.assertIn("original-pod", args)
            self.assertIn("-I", args)
            start = args.index("--") + 1
            self.assertEqual(list(args[start:start + len(host_workload.WORKLOAD_ENVIRONMENT)]), host_workload.WORKLOAD_ENVIRONMENT)
            if "prepare" in args:
                return b'{"worker_ready":true}'
            if "network" in args:
                return b'{"intended_model_tls":true}'
            if host_workload.UPLOAD_SOLUTION in args:
                r.source = payload
                return json.dumps({"artifact_sha256": hashlib.sha256(payload).hexdigest()}).encode()
            if "verify" in args:
                outcome=outcomes.pop(0)
                return json.dumps({"functional_tests": 9, "artifact_sha256": hashlib.sha256(r.source).hexdigest(),
                                   "independent_verification": outcome, "diagnostics": {
                                       "schema":"sandprobe.functional-diagnostic/1", "failure_kind":"passed" if outcome=="passed" else "case_mismatch",
                                       "expected_cases":9,"matched_cases":9 if outcome=="passed" else 8,
                                       "outputs_complete":True,"failed_case_ids":[] if outcome=="passed" else [9]}}).encode()
            return json.dumps({"identity": "reported_restricted", "protected_file": "reported_refusal",
                               "workspace": "reported_writable", "image_root": "reported_refusal", "receiver_egress": "reported_refusal"}).encode()

        r.ops = types.SimpleNamespace(call=call)
        r.kube = kube
        return r

    def test_wrong_selected_model_never_reaches_model_client(self):
        with tempfile.TemporaryDirectory() as folder:
            runner = self.fixture(folder)
            runner.journal.data["model"] = "mistral.ministral-3-8b-instruct"
            original = runner.ops.call
            def call(args, **kwargs):
                if Path(args[2]).name == "controller.py" and args[3] == "request":
                    return json.dumps({"modelId": host_workload.MODEL}).encode()
                return original(args, **kwargs)
            runner.ops.call = call
            result = json.loads(host_workload.perform(runner, "original-pod", "c" * 64))
            self.assertEqual(result["workload"], "reported_failed")
            self.assertEqual(runner.models, 0)

    def test_explicit_8b_uses_same_workload_and_two_request_cap(self):
        with tempfile.TemporaryDirectory() as folder:
            runner = self.fixture(folder, ["failed", "passed"])
            runner.journal.data["model"] = "mistral.ministral-3-8b-instruct"
            result = json.loads(host_workload.perform(runner, "original-pod", "c" * 64))
            self.assertEqual(result["workload"], "reported_passed")
            self.assertEqual(result["task"]["functional_tests"], 9)
            self.assertEqual(runner.models, 2)
            status = json.loads((Path(folder) / "host-controller-status.json").read_text())
            self.assertEqual(status["model"], "mistral.ministral-3-8b-instruct")

    def test_same_protocol_two_remote_attempts(self):
        with tempfile.TemporaryDirectory() as folder:
            r = self.fixture(folder, ["failed", "passed"])
            result = json.loads(host_workload.perform(r, "original-pod", "c" * 64))
            self.assertEqual(result["workload"], "reported_passed")
            self.assertEqual(result["task"]["model_requests"], 2)
            self.assertEqual(result["task"]["functional_tests"], 9)
            self.assertIsNotNone(guest_document(json.dumps(result), r.run_id, "original-pod", "c" * 64))
            self.assertEqual(r.models, 2)
            self.assertEqual({p.name for p in Path(folder).iterdir()}, {"host-controller-status.json","functional-attempt-1.json","functional-attempt-2.json"})
            for attempt,kind in [(1,"case_mismatch"),(2,"passed")]:
                p=Path(folder)/("functional-attempt-%d.json"%attempt)
                self.assertEqual(json.loads(p.read_text())["diagnostic"]["failure_kind"],kind)
                self.assertEqual(p.stat().st_mode&0o777,0o600)

    def test_ambiguous_model_transport_stops_without_retry(self):
        with tempfile.TemporaryDirectory() as folder:
            r = self.fixture(folder, model_failure=True)
            result = json.loads(host_workload.perform(r, "original-pod", "c" * 64))
            self.assertEqual(result["workload"], "reported_failed")
            self.assertEqual(r.models, 1)
            self.assertIsNone(r.source)
            status = json.loads((Path(folder) / "host-controller-status.json").read_text())
            self.assertTrue(status["model_request_count_uncertain"])
            self.assertFalse(status["completed"])

    def test_identity_absence_is_verified_not_assumed(self):
        with tempfile.TemporaryDirectory() as folder:
            r = self.fixture(folder)
            r.aws = Mock(return_value=[])
            self.assertEqual(len(host_workload.identity_hash(r)), 64)
            self.assertIn("list-pod-identity-associations", r.aws.call_args.args)
            for resource in ["role", "association"]:
                r.journal.data["resources"] = {resource: {}}
                with self.assertRaises(Failure):
                    host_workload.identity_hash(r)
            r.journal.data["resources"] = {}
            r.aws.return_value = [{"associationId": "unexpected"}]
            with self.assertRaises(Failure):
                host_workload.identity_hash(r)

    def test_controller_choice_is_explicit(self):
        with self.assertRaisesRegex(Failure, "invalid_controller_pattern"):
            Runner(None, profile="fixture", controller="automatic")

    def test_host_profile_removes_unused_metadata_egress_and_role(self):
        run = "a" * 16
        image = f"{ACCOUNT}.dkr.ecr.us-west-2.amazonaws.com/sandprobe-agent-{run}@sha256:" + "b" * 64
        plan = render(run, image, ACCOUNT, host_workload.MODEL, ["52.94.0.1"], "172.20.0.10", controller="host")
        with self.assertRaises(ValueError):
            render(run, image, ACCOUNT, "anthropic.other-model", ["52.94.0.1"], "172.20.0.10", controller="host")
        self.assertIsNone(plan["iam_policy"])
        self.assertEqual(plan["deployment_pattern"], "host_controller_no_guest_credentials")
        for resource in plan["kubernetes"]["items"]:
            if resource.get("kind") == "NetworkPolicy" and resource["metadata"]["name"] == "model-task-egress":
                self.assertEqual(len(resource["spec"]["egress"]), 2)
                self.assertNotIn("169.254.170.23", json.dumps(resource))
            if resource.get("kind") == "Job":
                self.assertEqual(resource["spec"]["template"]["spec"]["containers"][0]["command"], host_workload.IDLE_COMMAND)

    def test_worker_not_ready_stops_before_model_calls(self):
        with tempfile.TemporaryDirectory() as folder:
            r = self.fixture(folder)
            original = r.kube
            r.kube = lambda *args, **kwargs: b'{"worker_ready":false}' if "prepare" in args else original(*args, **kwargs)
            result = json.loads(host_workload.perform(r, "original-pod", "c" * 64))
            self.assertEqual(result["workload"], "reported_failed")
            self.assertEqual(r.models, 0)

    def test_setup_transport_failure_is_sanitized_and_distinguished(self):
        for step in ["prepare", "network"]:
            with self.subTest(step=step), tempfile.TemporaryDirectory() as folder:
                r = self.fixture(folder)
                original = r.kube
                def kube(*args, **kwargs):
                    if step in args:
                        raise RuntimeError("synthetic credential-shaped diagnostic")
                    return original(*args, **kwargs)
                r.kube = kube
                host_workload.perform(r, "original-pod", "c" * 64)
                raw = (Path(folder) / "host-controller-status.json").read_text()
                status = json.loads(raw)
                self.assertEqual(status["failure_code"], ("worker_prepare" if step == "prepare" else "intended_model_tls") + "_failed")
                self.assertEqual(r.models, 0)
                self.assertFalse(status["model_request_count_uncertain"])
                self.assertNotIn("synthetic credential-shaped diagnostic", raw)

    def test_invalid_diagnostics_cannot_pass_or_escape_into_records(self):
        with tempfile.TemporaryDirectory() as folder:
            r=self.fixture(folder);original=r.kube
            def kube(*args,**kwargs):
                raw=original(*args,**kwargs)
                if "verify" in args:
                    value=json.loads(raw);value["diagnostics"]["extra"]="synthetic-private-detail"
                    return json.dumps(value).encode()
                return raw
            r.kube=kube
            result=json.loads(host_workload.perform(r,"original-pod","c"*64))
            self.assertEqual(result["workload"],"reported_failed")
            self.assertEqual(r.models,1)
            self.assertFalse(list(Path(folder).glob("functional-attempt-*.json")))
            self.assertNotIn("synthetic-private-detail",(Path(folder)/"host-controller-status.json").read_text())

    def test_model_child_environment_drops_dns_authority_and_overrides(self):
        r = types.SimpleNamespace(env={"SANDPROBE_CF_TOKEN": "synthetic-not-secret", "AWS_ENDPOINT_URL_STS": "https://fixture.invalid",
                                       "AWS_MAX_ATTEMPTS": "9", "SANDPROBE_AWS_PROFILE": "fixed-profile"})
        env = host_workload.controller_environment(r)
        self.assertNotIn("SANDPROBE_CF_TOKEN", env)
        self.assertNotIn("AWS_ENDPOINT_URL_STS", env)
        self.assertEqual(env["SANDPROBE_AWS_PROFILE"], "fixed-profile")
        self.assertEqual(env["AWS_MAX_ATTEMPTS"], "1")
        self.assertIn("SANDPROBE_CF_TOKEN", r.env)

    def test_model_preflight_refuses_before_a_request(self):
        with tempfile.TemporaryDirectory() as folder:
            r = self.fixture(folder)
            r.model_python = "relative-python"
            with self.assertRaises(Failure):
                host_workload.model_preflight(r)

    def test_host_storage_rejects_credential_and_persistent_mounts(self):
        volumes = [{"name": key, "emptyDir": {"sizeLimit": "64Mi"}} for key in ["workspace", "scratch"]]
        mounts = [{"name": "workspace", "mountPath": "/workspace"}, {"name": "scratch", "mountPath": "/tmp"}]
        self.assertTrue(host_workload.valid_storage(volumes, mounts))
        self.assertFalse(host_workload.valid_storage(volumes + [{"name": "identity", "projected": {}}], mounts))
        self.assertFalse(host_workload.valid_storage([volumes[0], {"name": "scratch", "persistentVolumeClaim": {"claimName": "other"}}], mounts))
        self.assertFalse(host_workload.valid_storage(volumes, [mounts[0], dict(mounts[1], subPath="unexpected")]))
        self.assertFalse(host_workload.valid_storage(volumes, [mounts[0], mounts[0]]))
        self.assertFalse(host_workload.valid_storage([{"name": []}, volumes[1]], mounts))

    def test_host_contract_keeps_image_and_home_binding_without_tokens(self):
        with tempfile.TemporaryDirectory() as folder:
            journal = Journal(folder, "a" * 16, create=True)
            try:
                r = Runner(journal, profile="fixture", controller="host")
                r.image = f"{ACCOUNT}.dkr.ecr.us-west-2.amazonaws.com/{r.name}@sha256:" + "b" * 64
                journal.data.update(context={"pod_uid": "original-pod", "config_sha256": "c" * 64}, runtime_image_id=r.image)
                r.workload_fixture_context = Mock(return_value={"protected_device": 3, "protected_inode": 4})
                r.identity_configuration_hash = Mock(return_value="d" * 64)
                r.guard_read = Mock(return_value=(ROOT / "internal/host/testdata/workload-home.json").read_bytes())
                contract = r.workload_contract("original-pod")
                self.assertEqual(contract["schema"], "sandprobe.workload-contract/3")
                self.assertEqual(contract["identity_mode"], "host_controller_no_guest_credentials")
                self.assertTrue(contract["image_content_verified"])
                self.assertEqual(len(contract["agent_home_sha256"]), 64)
                self.assertFalse(any(k.startswith("token_") for k in contract))
                journal.data["runtime_image_id"] = "mutable:latest"
                with self.assertRaisesRegex(Failure, "host_controller_image_unverified"):
                    r.workload_contract("original-pod")
            finally:
                journal.close()
