"""RUN-23: persistence is an owned lifecycle, never a renamed coverage exclusion."""
import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

os.environ.setdefault("SANDPROBE_AWS_ACCOUNT", "111122223333")
os.environ.setdefault("SANDPROBE_AWS_PROFILE", "test-profile")

import host_workload
import persistent_assessment as persistent
from lifecycle import Failure, Journal
from render_profile import render, LIGHTWEIGHT_MODEL
from runner import Runner, ACCOUNT


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


class PersistentAssessmentTests(unittest.TestCase):
    def fixture(self, directory):
        journal = Journal(directory, "a" * 16, create=True)
        self.addCleanup(journal.close)
        runner = Runner(journal, controller="host", storage_profile="persistent-artifacts")
        runner.kubeconfig = journal.folder / "eks-12345678.kubeconfig"
        runner.cluster = "sandprobe-12345678"
        runner.image = f"{ACCOUNT}.dkr.ecr.us-west-2.amazonaws.com/sandprobe-agent-{runner.run_id}@sha256:" + "d" * 64
        volume = {"id": "vol-" + "5" * 17, "zone": "us-west-2a"}
        job = render(runner.run_id, runner.image, ACCOUNT, LIGHTWEIGHT_MODEL, ["52.94.0.1"], "172.20.0.10",
                     controller="host", storage_profile="persistent-artifacts", workspace_volume=volume)["kubernetes"]["items"][-1]
        original_hash = hashlib.sha256(encoded(job)).hexdigest()
        job["spec"]["template"]["spec"]["containers"][0]["env"].append({"name": "SANDPROBE_CONFIG_SHA256", "value": original_hash})
        resources = journal.data["resources"]
        resources[f"kube:Namespace::{runner.ns}"] = {"uid": "1" * 32, "status": "created"}
        resources[f"kube:Job:{runner.ns}:model-task"] = {"uid": "2" * 32, "status": "created"}
        resources["workspace_volume"] = {**volume, "status": "created"}
        journal.data.update(context={"pod_uid": "3" * 32, "config_sha256": original_hash},
                            persistent_reset={"authority": "b" * 48, "original_job": job},
                            model=LIGHTWEIGHT_MODEL, endpoint_resolution={"ipv4": ["52.94.0.1"]}, dns_address="172.20.0.10")
        journal.save()
        return runner

    def state(self, runner, phase="created"):
        data = runner.journal.data
        job = copy.deepcopy(data["persistent_reset"]["original_job"])
        job["spec"]["template"]["spec"]["containers"][0]["env"].pop()
        job["metadata"]["name"] = "model-task-reset"
        return {"schema": "sandprobe.nitro-reset/1", "run_id": runner.run_id,
                "authority": data["persistent_reset"]["authority"], "namespace_uid": "1" * 32,
                "volume_id": "vol-" + "5" * 17, "original_job_uid": "2" * 32, "original_pod_uid": "3" * 32,
                "original_config_sha256": data["context"]["config_sha256"], "phase": phase,
                "job_uid": "4" * 32 if phase in {"created", "ready"} else "", "pod_uid": "", "pod_name": "",
                "config_sha256": hashlib.sha256(encoded(job)).hexdigest(), "container_id": ""}

    def write_state(self, runner, state):
        path = runner.journal.folder / "nitro-reset.state"
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(encoded(state))
        return path

    def test_only_explicit_host_profile_can_create_persistent_state(self):
        with tempfile.TemporaryDirectory() as root:
            journal = Journal(root, "a" * 16, create=True)
            self.addCleanup(journal.close)
            with self.assertRaises(Failure):
                Runner(journal, storage_profile="persistent-artifacts")
            with self.assertRaises(Failure):
                Runner(journal, controller="host", storage_profile="other")
            runner = Runner(journal, controller="host", storage_profile="persistent-artifacts")
            self.assertTrue(persistent.enabled(runner))
            with self.assertRaises(Failure):
                Runner(journal, controller="host", storage_profile="ephemeral")

    def test_separate_artifact_mount_preserves_local_coding_and_cache(self):
        with tempfile.TemporaryDirectory() as root:
            runner = self.fixture(root)
            pod = runner.journal.data["persistent_reset"]["original_job"]["spec"]["template"]["spec"]
            container = pod["containers"][0]
            self.assertTrue(host_workload.valid_storage(pod["volumes"], container["volumeMounts"], True))
            self.assertFalse(host_workload.valid_storage(pod["volumes"], container["volumeMounts"]))
            for key, value in [("mountPath", "/workspace"), ("subPath", "other"), ("readOnly", True), ("mountPropagation", "Bidirectional")]:
                changed = copy.deepcopy(container["volumeMounts"])
                changed[-1][key] = value
                self.assertFalse(host_workload.valid_storage(pod["volumes"], changed, True))
            changed = copy.deepcopy(pod["volumes"])
            changed[-1]["persistentVolumeClaim"]["claimName"] = "unowned"
            self.assertFalse(host_workload.valid_storage(changed, container["volumeMounts"], True))

    def test_import_preserves_lost_create_as_unknown_and_known_returned_uid(self):
        with tempfile.TemporaryDirectory() as root:
            runner = self.fixture(root)
            key = f"kube:Job:{runner.ns}:model-task-reset"
            self.write_state(runner, self.state(runner, "create_intent"))
            persistent.import_reset(runner)
            self.assertEqual(runner.journal.data["resources"][key]["status"], "intent")
            self.assertEqual(runner.journal.data["resources"][key]["uid"], "")
        with tempfile.TemporaryDirectory() as root:
            runner = self.fixture(root)
            state = self.state(runner)
            self.write_state(runner, state)
            persistent.import_reset(runner)
            self.assertEqual(runner.journal.data["resources"][key]["uid"], state["job_uid"])
            self.assertEqual(runner.journal.data["persistent_reset_state"], state)

    def test_import_rejects_other_authority_context_backend_and_manifest_hash(self):
        for field in ["authority", "run_id", "namespace_uid", "volume_id", "original_job_uid", "original_pod_uid", "original_config_sha256", "config_sha256"]:
            with self.subTest(field=field), tempfile.TemporaryDirectory() as root:
                runner = self.fixture(root)
                state = self.state(runner)
                state[field] = "f" * 64
                self.write_state(runner, state)
                with self.assertRaises(Failure):
                    persistent.import_reset(runner)
                self.assertNotIn(f"kube:Job:{runner.ns}:model-task-reset", runner.journal.data["resources"])

    def test_bridge_failure_still_imports_reset_state_without_retry(self):
        with tempfile.TemporaryDirectory() as root:
            runner = self.fixture(root)
            runner.delegated_state = Mock(return_value={"endpoint": "https://owned-cluster"})
            runner.journal.data.update(task_container_id="original-container", workload_contract={"frozen": True})
            runner.ops = Mock()
            def failed(*args, **kwargs):
                request = json.loads(kwargs["payload"])
                self.assertEqual(request["persistent"]["authority"], "b" * 48)
                self.write_state(runner, self.state(runner))
                raise Failure("command_failed")
            runner.ops.call.side_effect = failed
            with patch.object(persistent, "binding", return_value={"volume_id": "owned"}):
                with self.assertRaises(Failure):
                    runner.standard_grade("model-task-abc", "2" * 32, runner.journal.data["context"]["config_sha256"])
            runner.ops.call.assert_called_once()
            self.assertIn(f"kube:Job:{runner.ns}:model-task-reset", runner.journal.data["resources"])

    def test_both_original_and_replacement_jobs_stop_before_control(self):
        with tempfile.TemporaryDirectory() as root:
            runner = self.fixture(root)
            self.write_state(runner, self.state(runner))
            runner.delete_job = Mock()
            runner.stop_task_jobs()
            self.assertEqual(runner.delete_job.call_args_list[0].args, ())
            self.assertEqual(runner.delete_job.call_args_list[1].args, ("model-task-reset",))
            self.assertEqual(runner.delete_job.call_count, 2)

    def test_unknown_replacement_is_never_deleted_by_name(self):
        with tempfile.TemporaryDirectory() as root:
            runner = self.fixture(root)
            self.write_state(runner, self.state(runner, "create_intent"))
            persistent.import_reset(runner)
            runner.scalar = Mock()
            runner.kube = Mock()
            with self.assertRaises(Failure):
                runner.delete_job("model-task-reset")
            runner.scalar.assert_not_called()
            runner.kube.assert_not_called()

    def test_artifact_refusal_saved_before_model_release(self):
        with tempfile.TemporaryDirectory() as root:
            runner = self.fixture(root)
            proof = {"agent_uid": 10001, "agent_gid": 10001, "root_uid": 0, "root_gid": 0, "root_mode": 0o755,
                     "directory": True, "verified": False, "bytes": 0, "sha256": "", "failure_kind": "write_unavailable"}
            runner.kube = Mock(return_value=encoded(proof))
            with self.assertRaises(Failure):
                persistent.artifact(runner, "model-task-original", "preflight", b"synthetic")
            self.assertEqual(json.loads((runner.journal.folder / "storage-preflight.json").read_text()), proof)
            self.assertIn("/persist", runner.kube.call_args.args[-3])

    def test_install_uses_original_receiver_and_explicit_ebs_create(self):
        with tempfile.TemporaryDirectory() as root:
            runner = self.fixture(root)
            receiver_uid = "6" * 32
            runner.scalar = Mock(side_effect=[receiver_uid, "own-node", "us-west-2a"])
            runner.create = Mock()
            with patch.object(persistent.EBSWorkspace, "create", return_value={"id": "vol-" + "5" * 17, "zone": "us-west-2a"}) as create:
                plan = persistent.install(runner, runner.ns + "-receiver", receiver_uid)
            create.assert_called_once_with("us-west-2a")
            self.assertEqual([call.args[0]["kind"] for call in runner.create.call_args_list], ["StorageClass", "PersistentVolume", "PersistentVolumeClaim"])
            self.assertEqual(plan["storage_context"]["mount_path"], "/persist")
            claim = runner.create.call_args_list[-1].args[0]
            self.assertEqual(claim["spec"]["accessModes"], ["ReadWriteOncePod"])
            runner.journal.data["resources"]["workspace_volume"]["zone"] = "us-west-2b"
            self.assertEqual(runner.task_node_selector()["topology.kubernetes.io/zone"], "us-west-2b")

    def test_cleanup_accounts_for_independent_external_volume(self):
        for refused in [False, True]:
            with self.subTest(refused=refused), tempfile.TemporaryDirectory() as root:
                runner = self.fixture(root)
                runner.kubeconfig = None
                runner.account = Mock()
                runner.journal.data["resources"]["cluster"] = {"status": "deleted"}
                with patch.object(persistent.EBSWorkspace, "delete", side_effect=Failure("volume_attached") if refused else None) as delete:
                    confirmed = runner.cleanup()
                delete.assert_called_once()
                self.assertEqual(confirmed, not refused)
                self.assertEqual("workspace_volume_cleanup_unconfirmed" in runner.journal.data["cleanup_failures"], refused)


if __name__ == "__main__":
    unittest.main()
