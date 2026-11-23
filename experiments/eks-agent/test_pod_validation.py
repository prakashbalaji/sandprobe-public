import os
os.environ.setdefault("SANDPROBE_AWS_ACCOUNT", "111122223333")  # AWS's documentation placeholder
os.environ.setdefault("SANDPROBE_AWS_PROFILE", "test-profile")
import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from lifecycle import Failure, Journal
from runner import ACCOUNT, Runner
from render_profile import render


class PodValidationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not shutil.which("go"):
            raise unittest.SkipTest("Go guard renderer required in CI")
        cls.tools = tempfile.TemporaryDirectory()
        cls.binary = str(Path(cls.tools.name)/"template-check")
        subprocess.run(["go", "build", "-o", cls.binary, str(Path(__file__).with_name("testdata")/"template_eval.go")], check=True, capture_output=True, timeout=90)

    @classmethod
    def tearDownClass(cls):
        cls.tools.cleanup()

    def fixture(self, runner):
        pod = render(runner.run_id, f"{ACCOUNT}.dkr.ecr.us-west-2.amazonaws.com/{runner.name}@sha256:"+"a"*64,
                     ACCOUNT, "anthropic.claude-3-haiku-20240307-v1:0", ["52.94.0.1"], "10.0.0.10")["kubernetes"]["items"][-1]["spec"]["template"]
        spec = pod["spec"]
        spec["nodeSelector"] = {"karpenter.sh/nodepool": runner.name, "eks.amazonaws.com/nitro-sandbox":"true"}
        spec["tolerations"] = [{"key": "sandprobe.run", "operator": "Equal", "value": runner.run_id, "effect": "NoSchedule"}]
        c = spec["containers"][0]
        c["command"] = ["python", "-I", "/opt/sandprobe/execute.py"]
        c["env"] += [{"name": "SANDPROBE_RUN_ID", "value": runner.run_id},
                     {"name": "SANDPROBE_RECEIVER_IP", "value": "10.0.0.20"},
                     {"name": "SANDPROBE_AGENT_NONCE", "value": "2"*48},
                     {"name": "SANDPROBE_CONFIG_SHA256", "value": "b"*64},
                     {"name": "SANDPROBE_POD_UID", "valueFrom": {"fieldRef": {"fieldPath": "metadata.uid"}}},
                     {"name": "AWS_CONTAINER_CREDENTIALS_FULL_URI", "value": "http://169.254.170.23/v1/credentials"},
                     {"name": "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE", "value": "/var/run/secrets/pods.eks.amazonaws.com/serviceaccount/eks-pod-identity-token"}]
        spec["volumes"].append({"name": "eks-pod-identity-token", "projected": {"defaultMode": 420, "sources": [{"serviceAccountToken": {
            "audience": "pods.eks.amazonaws.com", "path": "eks-pod-identity-token", "expirationSeconds": 86400}}]}})
        c["volumeMounts"].append({"name": "eks-pod-identity-token", "mountPath": "/var/run/secrets/pods.eks.amazonaws.com/serviceaccount", "readOnly": True})
        return pod

    def configure(self, runner, pod):
        def projection(kind, name, expr, namespace):
            fields = {"{.spec.containers[0].securityContext}": pod["spec"]["containers"][0]["securityContext"],
                      "{.spec.securityContext}": pod["spec"]["securityContext"],
                      "{.spec.volumes}": pod["spec"]["volumes"],
                      "{.spec.containers[0].volumeMounts}": pod["spec"]["containers"][0]["volumeMounts"],
                      "{.spec.nodeSelector}": pod["spec"]["nodeSelector"], "{.spec.tolerations}": pod["spec"]["tolerations"],
                      "{.spec.containers[0].volumeDevices}": pod["spec"]["containers"][0].get("volumeDevices")}
            return copy.deepcopy(fields[expr])
        runner.projection = projection
        def template_result(name, source):
            result = subprocess.run([self.binary], input=json.dumps({"Source": source, "Data": pod}).encode(), capture_output=True, timeout=10)
            if result.returncode:
                raise Failure("template_guard_failed")
            return result.stdout.decode()
        runner.template_result = template_result
        runner.kube = lambda *args, **kwargs: b"present\n"
        runner.journal.data.update(model="anthropic.claude-3-haiku-20240307-v1:0", receiver_ip="10.0.0.20",
                                  nonces=["1"*48,"2"*48,"3"*48], context={"config_sha256":"b"*64})

    def test_valid_configuration_and_injected_mutations(self):
        with tempfile.TemporaryDirectory() as root:
            j = Journal(root, "a"*16, create=True)
            runner = Runner(j)
            pod = self.fixture(runner)
            self.configure(runner, pod)
            runner.validate_task_structure("owned-pod")
            mutations = {
                "root-override": lambda p: p["spec"]["containers"][0]["securityContext"].update(runAsUser=0),
                "seccomp-override": lambda p: p["spec"]["containers"][0]["securityContext"].update(seccompProfile={"type":"Unconfined"}),
                "host-volume": lambda p: p["spec"]["volumes"].append({"name":"host","hostPath":{"path":"/"}}),
                "secret-source": lambda p: p["spec"]["volumes"][0].update(secret={"secretName":"unexpected"}),
                "mount-options": lambda p: p["spec"]["containers"][0]["volumeMounts"][0].update(subPath="other"),
                "env-secret": lambda p: p["spec"]["containers"][0]["env"].append({"name":"EXTRA","value":"synthetic-private"}),
                "changed-env": lambda p: p["spec"]["containers"][0]["env"][0].update(value="other-model"),
                "duplicate-env": lambda p: p["spec"]["containers"][0]["env"].append(copy.deepcopy(p["spec"]["containers"][0]["env"][0])),
                "missing-token": lambda p: p["spec"]["volumes"].pop(),
                "token-audience": lambda p: p["spec"]["volumes"][-1]["projected"]["sources"][0]["serviceAccountToken"].update(audience="other"),
                "token-env": lambda p: p["spec"]["containers"][0]["env"].pop(),
                "lifecycle": lambda p: p["spec"]["containers"][0].update(lifecycle={"postStart":{"exec":{"command":["unexpected"]}}}),
                "command": lambda p: p["spec"]["containers"][0].update(command=["other"]),
                "selector": lambda p: p["spec"]["nodeSelector"].update(extra="other"),
                "missing-nitro-selector": lambda p: p["spec"]["nodeSelector"].pop("eks.amazonaws.com/nitro-sandbox"),
                "changed-nitro-selector": lambda p: p["spec"]["nodeSelector"].update({"eks.amazonaws.com/nitro-sandbox":"false"}),
                "toleration": lambda p: p["spec"]["tolerations"].append({"operator":"Exists"}),
            }
            for name, mutate in mutations.items():
                with self.subTest(name=name):
                    bad = copy.deepcopy(pod)
                    mutate(bad)
                    self.configure(runner, bad)
                    with self.assertRaises(Failure):
                        runner.validate_task_structure("owned-pod")
            j.close()

    def test_observed_nitro_structure_and_bounded_token_lifetime(self):
        # GAT-3: only structural metadata, with run-owned names normalized.
        observed=json.loads((Path(__file__).with_name("testdata")/"nitro_pod_structure.json").read_text())
        with tempfile.TemporaryDirectory() as root:
            j=Journal(root,"a"*16,create=True);runner=Runner(j);pod=self.fixture(runner)
            spec=pod["spec"];container=spec["containers"][0]
            container["securityContext"]=observed["container_security_context"]
            container["volumeMounts"]=observed["mounts"]
            for field,key in [("securityContext","pod_security_context"),("volumes","volumes"),
                              ("nodeSelector","node_selector"),("tolerations","tolerations")]:
                spec[field]=observed[key]
            self.configure(runner,pod)
            runner.validate_task_structure("observed-fixture")
            token=next(v for v in spec["volumes"] if v["name"]=="eks-pod-identity-token")["projected"]["sources"][0]["serviceAccountToken"]
            self.assertEqual(token["expirationSeconds"],86360)
            for lifetime in [3600,86360,86400]:
                token["expirationSeconds"]=lifetime
                runner.validate_task_structure("observed-fixture")
            for lifetime in [3599,86401,0,-1,True,3600.0,"86360",None]:
                with self.subTest(lifetime=lifetime):
                    token["expirationSeconds"]=lifetime
                    with self.assertRaisesRegex(Failure,"unexpected_identity_token_context"):
                        runner.validate_task_structure("observed-fixture")
            token["expirationSeconds"]=86360
            for key,value in [("path","other"),("audience","other"),("extra","unexpected")]:
                original=copy.deepcopy(token);token[key]=value
                with self.subTest(key=key),self.assertRaisesRegex(Failure,"unexpected_identity_token_context"):
                    runner.validate_task_structure("observed-fixture")
                token.clear();token.update(original)
            j.close()
