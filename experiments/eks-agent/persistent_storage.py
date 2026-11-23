"""RUN-23: explicit owned EBS lifecycle; no tag-based adoption or implicit CSI creates."""
from datetime import datetime, timezone, timedelta
import json
import re
import secrets
import time

from lifecycle import Failure


VOLUME_ID = re.compile(r"vol-[a-f0-9]{17}")
ZONE = re.compile(r"us-west-2[a-d]")
KEY = "workspace_volume"
FIELDS = ("Volumes[0].{id:VolumeId,zone:AvailabilityZone,created:CreateTime,"
          "encrypted:Encrypted,size:Size,kind:VolumeType,snapshot:SnapshotId,"
          "multi_attach:MultiAttachEnabled,attachments:Attachments,state:State,tags:Tags}")


def instant(value):
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            raise ValueError()
        return parsed
    except (AttributeError, TypeError, ValueError):
        raise Failure("workspace_volume_timestamp_invalid") from None


class EBSWorkspace:
    def __init__(self, runner):
        self.runner = runner
        self.journal = runner.journal

    @property
    def record(self):
        record = self.journal.data["resources"].get(KEY)
        if not isinstance(record, dict):
            raise Failure("workspace_volume_not_recorded")
        return record

    def create(self, zone):
        if not isinstance(zone, str) or not ZONE.fullmatch(zone):
            raise Failure("workspace_volume_zone_invalid")
        cluster = self.journal.data["resources"].get("cluster", {})
        if cluster.get("status") != "created" or not cluster.get("name"):
            raise Failure("workspace_volume_cluster_unavailable")
        self.runner.account()
        token = "sp-workspace-" + self.runner.run_id + "-" + secrets.token_hex(12)
        tags = [{"Key": "sandprobe:run", "Value": self.runner.run_id},
                {"Key": "eks:eks-cluster-name", "Value": cluster["name"]}]
        self.journal.intent(KEY, zone=zone, cluster=cluster["name"], token=token,
                            requested=datetime.now(timezone.utc).isoformat(), tags=tags)
        # Query only the create-returned ID so malformed optional metadata cannot
        # discard ownership before it is durable. Never repeat this create.
        volume_id = self.runner.aws("ec2", "create-volume", "--availability-zone", zone,
            "--volume-type", "gp3", "--size", "1", "--encrypted", "--no-multi-attach-enabled",
            "--client-token", token, "--tag-specifications",
            json.dumps([{"ResourceType": "volume", "Tags": tags}], separators=(",", ":")), query="VolumeId")
        if not isinstance(volume_id, str) or not VOLUME_ID.fullmatch(volume_id):
            raise Failure("workspace_volume_create_id_unavailable")
        self.journal.recorded(KEY, id=volume_id)
        for _ in range(120):
            data = self.read()
            if data["state"] == "available":
                return {"id": volume_id, "zone": zone}
            if data["state"] != "creating":
                raise Failure("workspace_volume_not_available")
            time.sleep(1)
        raise Failure("workspace_volume_readiness_deadline")

    def read(self):
        record = self.record
        if not isinstance(record.get("id"), str) or not VOLUME_ID.fullmatch(record["id"]):
            raise Failure("workspace_volume_create_unresolved")
        data = self.runner.aws("ec2", "describe-volumes", "--volume-ids", record["id"], query=FIELDS)
        if not isinstance(data, dict):
            raise Failure("workspace_volume_metadata_missing")
        requested, created = instant(record.get("requested")), instant(data.get("created"))
        if (data.get("id") != record["id"] or data.get("zone") != record.get("zone")
                or data.get("encrypted") is not True or type(data.get("size")) is not int or data["size"] != 1
                or data.get("kind") != "gp3" or data.get("snapshot") not in (None, "")
                or data.get("multi_attach") is not False or not isinstance(data.get("attachments"), list)
                or created < requested - timedelta(minutes=1) or created > requested + timedelta(minutes=2)
                or (record.get("created") and data["created"] != record["created"])):
            raise Failure("workspace_volume_creation_identity_changed")
        # Tags are corroborating configuration, never the basis of ownership.
        tags = data.get("tags")
        if (not isinstance(tags, list) or len(tags)>50
                or any(not isinstance(tag, dict) or not isinstance(tag.get("Key"),str)
                       or not isinstance(tag.get("Value"),str) for tag in tags)):
            raise Failure("workspace_volume_tags_invalid")
        values = {tag.get("Key"): tag.get("Value") for tag in tags}
        if (len(values) != len(tags) or values.get("sandprobe:run") != self.runner.run_id
                or values.get("eks:eks-cluster-name") != record.get("cluster")):
            raise Failure("workspace_volume_context_changed")
        if not record.get("created"):
            record["created"] = data["created"]
            self.journal.save()
        return data

    def delete(self):
        record = self.record
        if record.get("status") == "deleted":
            return
        if not isinstance(record.get("id"), str) or not VOLUME_ID.fullmatch(record["id"]):
            raise Failure("workspace_volume_create_unresolved")
        self.runner.account()
        cluster = self.journal.data["resources"].get("cluster", {})
        if cluster.get("status") != "deleted" or cluster.get("name") != record.get("cluster"):
            raise Failure("workspace_volume_cluster_deletion_unconfirmed")
        try:
            self.runner.aws("eks", "describe-cluster", "--name", record["cluster"])
        except Failure as error:
            if str(error) != "resource_not_found":
                raise
        else:
            raise Failure("workspace_volume_cluster_still_exists")
        delete_sent = False
        for _ in range(120):
            try:
                data = self.read()
            except Failure as error:
                if str(error) != "volume_not_found":
                    raise
                record["status"], record["cleanup_proof"] = "deleted", "exact_id_describe_not_found"
                self.journal.save()
                return
            if data["attachments"]:
                raise Failure("workspace_volume_still_attached")
            if not delete_sent and data.get("state") in {"available", "error"}:
                record["delete_intent"] = True
                self.journal.save()
                self.runner.aws("ec2", "delete-volume", "--volume-id", record["id"])
                delete_sent = True
            elif data.get("state") not in {"available", "deleting", "deleted", "error"}:
                raise Failure("workspace_volume_deletion_state_unknown")
            time.sleep(1)
        raise Failure("workspace_volume_deletion_unconfirmed")
