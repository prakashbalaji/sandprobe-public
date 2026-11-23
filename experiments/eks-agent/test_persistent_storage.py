import copy
from datetime import datetime, timezone
import json
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch

from lifecycle import Commands, Failure, Journal
from persistent_storage import EBSWorkspace, KEY


class EBSWorkspaceTests(unittest.TestCase):
    def fixture(self, root):
        journal = Journal(root, "a"*16, create=True)
        self.addCleanup(journal.close)
        journal.data["resources"]["cluster"]={"status":"created","name":"sandprobe-owned-cluster"}
        journal.save()
        state={"volume_gone":False,"cluster_gone":False,"create_error":False,"delete_error":False,"calls":[],"edits":{}}
        volume_id="vol-"+"b"*17
        born=datetime.now(timezone.utc).isoformat()
        def aws(service,operation,*args,query=None):
            state["calls"].append((service,operation,args))
            record=journal.data["resources"].get(KEY,{})
            if (service,operation)==("ec2","create-volume"):
                on_disk=json.loads(journal.path.read_text())["resources"][KEY]
                self.assertEqual(on_disk["status"],"creating")
                self.assertNotIn("id",on_disk)
                self.assertEqual(query,"VolumeId")
                self.assertEqual(args[args.index("--client-token")+1],record["token"])
                self.assertIn("--encrypted",args)
                if state["create_error"]:raise Failure("command_failed")
                return volume_id
            if (service,operation)==("ec2","describe-volumes"):
                self.assertEqual(args,("--volume-ids",volume_id))
                self.assertEqual(json.loads(journal.path.read_text())["resources"][KEY]["id"],volume_id)
                if state["volume_gone"]:raise Failure("volume_not_found")
                result={"id":volume_id,"zone":"us-west-2a","created":born,"encrypted":True,"size":1,"kind":"gp3","snapshot":"","multi_attach":False,"attachments":[],"state":"available","tags":record["tags"]}
                result.update(copy.deepcopy(state["edits"]))
                return result
            if (service,operation)==("eks","describe-cluster"):
                self.assertEqual(args,("--name","sandprobe-owned-cluster"))
                if state["cluster_gone"]:raise Failure("resource_not_found")
                return {"name":"sandprobe-owned-cluster"}
            if (service,operation)==("ec2","delete-volume"):
                self.assertTrue(state["cluster_gone"])
                self.assertEqual(args,("--volume-id",volume_id))
                self.assertTrue(json.loads(journal.path.read_text())["resources"][KEY]["delete_intent"])
                state["volume_gone"]=True
                if state["delete_error"]:raise Failure("command_failed")
                return None
            self.fail("unexpected AWS operation")
        runner=types.SimpleNamespace(journal=journal,run_id="a"*16,account=lambda:None,aws=aws)
        return EBSWorkspace(runner),state

    def test_original_id_is_durable_before_read_and_cleanup_requires_cluster_absence(self):
        with tempfile.TemporaryDirectory() as root,patch("persistent_storage.time.sleep"):
            volume,state=self.fixture(root)
            self.assertEqual(volume.create("us-west-2a"),{"id":"vol-"+"b"*17,"zone":"us-west-2a"})
            with self.assertRaisesRegex(Failure,"resource_already_recorded"):volume.create("us-west-2a")
            with self.assertRaisesRegex(Failure,"cluster_deletion_unconfirmed"):volume.delete()
            volume.journal.data["resources"]["cluster"]["status"]="deleted"
            with self.assertRaisesRegex(Failure,"cluster_still_exists"):volume.delete()
            state["cluster_gone"]=True
            volume.delete()
            self.assertEqual(volume.record["status"],"deleted")
            self.assertEqual(volume.record["cleanup_proof"],"exact_id_describe_not_found")
            operations=[x[1] for x in state["calls"]]
            self.assertEqual(operations.count("create-volume"),1)
            self.assertEqual(operations.count("delete-volume"),1)

    def test_unknown_create_is_not_retried_or_discovered(self):
        with tempfile.TemporaryDirectory() as root:
            volume,state=self.fixture(root)
            state["create_error"]=True
            with self.assertRaises(Failure):volume.create("us-west-2a")
            count=len(state["calls"])
            for operation in (lambda:volume.create("us-west-2a"),volume.read,volume.delete):
                with self.assertRaises(Failure):operation()
            self.assertEqual(len(state["calls"]),count)
            self.assertEqual(volume.record["status"],"creating")

    def test_changed_metadata_and_attachments_never_authorize_delete(self):
        edits=[{"id":"vol-"+"c"*17},{"zone":"us-west-2b"},{"encrypted":False},
               {"size":True},{"kind":"io2"},{"snapshot":"snap-other"},{"multi_attach":True},
               {"created":"2000-01-01T00:00:00Z"},{"tags":[{"Key":[],"Value":"bad"}]},
               {"attachments":[{"InstanceId":"owned-but-still-attached"}]}]
        for edit in edits:
            with self.subTest(edit=edit),tempfile.TemporaryDirectory() as root:
                volume,state=self.fixture(root)
                volume.create("us-west-2a")
                volume.journal.data["resources"]["cluster"]["status"]="deleted"
                state.update(cluster_gone=True,edits=edit)
                with self.assertRaises(Failure):volume.delete()
                self.assertNotIn("delete-volume",[x[1] for x in state["calls"]])

    def test_ambiguous_delete_is_settled_only_by_new_exact_id_absence(self):
        with tempfile.TemporaryDirectory() as root,patch("persistent_storage.time.sleep"):
            volume,state=self.fixture(root)
            volume.create("us-west-2a")
            volume.journal.data["resources"]["cluster"]["status"]="deleted"
            state.update(cluster_gone=True,delete_error=True)
            with self.assertRaises(Failure):volume.delete()
            self.assertNotEqual(volume.record["status"],"deleted")
            EBSWorkspace(volume.runner).delete()
            self.assertEqual(volume.record["status"],"deleted")
            self.assertEqual([x[1] for x in state["calls"]].count("delete-volume"),1)

    def test_volume_absence_classifier_is_exact_and_operation_scoped(self):
        with tempfile.TemporaryDirectory() as root:
            program=Path(root)/"aws"
            for operation,code,expected in [("describe-volumes","InvalidVolume.NotFound","volume_not_found"),
                                            ("describe-volumes","InvalidVolumeXNotFound","command_failed"),
                                            ("describe-volumes","UnauthorizedOperation","command_failed"),
                                            ("delete-volume","InvalidVolume.NotFound","command_failed")]:
                program.write_text("#!/usr/bin/env python3\nimport sys\nsys.stderr.write("+repr("An error occurred ("+code+") when calling the operation")+")\nsys.exit(255)\n")
                program.chmod(0o700)
                with self.subTest(operation=operation,code=code),self.assertRaisesRegex(Failure,"^"+expected+"$"):
                    Commands(seconds=5).call([str(program),"--profile","test","--region","us-west-2","ec2",operation])


if __name__ == "__main__":
    unittest.main()
