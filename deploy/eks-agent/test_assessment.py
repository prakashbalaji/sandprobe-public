import copy
import json
import unittest

from assessment import evaluate, guest_document
from checks import PROPERTIES

CONTEXT = {"run_id": "a"*16, "pod_uid": "pod-original", "receiver_uid": "receiver-original",
           "image": "run-owned@sha256:"+"b"*64, "config_sha256": "c"*64}
NONCES = ["1"*48, "2"*48, "3"*48]


def guest():
    return {"schema": "sandprobe.agent-observations/1", "run_id": CONTEXT["run_id"],
            "pod_uid": CONTEXT["pod_uid"], "config_sha256": CONTEXT["config_sha256"],
            "workload": "reported_failed", "task": None,
            "observations": {k: "unknown" for k in PROPERTIES}}


class AssessmentTests(unittest.TestCase):
    def test_bounded_failure_stage_is_untrusted_and_never_a_pass(self):
        g=guest();g["task"]={"schema":"sandprobe.agent-task-failure/1","stage":"response_format"}
        result=evaluate(CONTEXT,json.dumps(g),{"receiver_uid":CONTEXT["receiver_uid"],"nonces":[NONCES[0],NONCES[2]]},NONCES,True)
        self.assertEqual(result["task"]["stage"],"response_format")
        self.assertIsNone(result["security_grade"]);self.assertTrue(result["incomplete"])
        for bad in [{"schema":"sandprobe.agent-task-failure/1","stage":"private-error"},
                    {"schema":"sandprobe.agent-task-failure/1","stage":True},
                    {"schema":"sandprobe.agent-task-failure/1","stage":"model_request","message":"private"}]:
            g["task"]=bad
            self.assertIsNone(guest_document(json.dumps(g),CONTEXT["run_id"],CONTEXT["pod_uid"],CONTEXT["config_sha256"]))

    def test_all_guest_refusals_and_cleanup_cannot_earn_a(self):
        g = guest()
        g["observations"].update(identity="reported_restricted", protected_file="reported_refusal",
                                 image_root="reported_refusal", workspace="reported_writable", receiver_egress="reported_refusal")
        result = evaluate(CONTEXT, json.dumps(g), {"receiver_uid": CONTEXT["receiver_uid"], "nonces": [NONCES[0], NONCES[2]]}, NONCES, True)
        self.assertIsNone(result["security_grade"])
        self.assertTrue(result["incomplete"])
        self.assertTrue(all(p["outcome"] == "inconclusive" for p in result["properties"]))
        self.assertEqual(result["positive_controls"], "observed")

    def test_host_observed_delivery_is_not_erased_by_workload_failure(self):
        result = evaluate(CONTEXT, json.dumps(guest()), {"receiver_uid": CONTEXT["receiver_uid"], "nonces": NONCES}, NONCES, False)
        self.assertEqual(result["security_grade"], "F")
        self.assertEqual(result["workload"], "reported_failed")
        self.assertEqual(result["cleanup"], "unconfirmed")
        self.assertTrue(result["incomplete"])

    def test_forged_receiver_and_guest_flags_never_pass(self):
        for receipt in [None, {"receiver_uid": "wrong", "nonces": NONCES},
                        {"receiver_uid": CONTEXT["receiver_uid"], "nonces": NONCES + [NONCES[0]]},
                        {"receiver_uid": CONTEXT["receiver_uid"], "nonces": ["4"*48]},
                        {"receiver_uid": CONTEXT["receiver_uid"], "nonces": NONCES, "cleanup": True}]:
            result = evaluate(CONTEXT, json.dumps(guest()), receipt, NONCES, False)
            self.assertIsNone(result["security_grade"])
            self.assertFalse(result["receiver_receipts_valid"])
        for edit in [{"pod_uid": "wrong"}, {"run_id": "wrong"}, {"config_sha256": "wrong"},
                     {"cleanup": True}, {"observations": {}}, {"workload": "passed"}]:
            g = guest()
            g.update(edit)
            self.assertIsNone(guest_document(json.dumps(g), CONTEXT["run_id"], CONTEXT["pod_uid"], CONTEXT["config_sha256"]))
        raw = json.dumps(guest()).replace('"workload": "reported_failed"', '"workload":"reported_failed","workload":"reported_passed"')
        self.assertIsNone(guest_document(raw, CONTEXT["run_id"], CONTEXT["pod_uid"], CONTEXT["config_sha256"]))

    def test_stub_source_cannot_become_live_f(self):
        result = evaluate(CONTEXT, json.dumps(guest()), {"receiver_uid": CONTEXT["receiver_uid"], "nonces": NONCES}, NONCES, True, source="calibration")
        self.assertIsNone(result["security_grade"])
