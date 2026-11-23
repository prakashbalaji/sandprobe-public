import hashlib
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import coding
import task

GOOD = Path(__file__).with_name("fixtures").joinpath("solution.py").read_text()


class ModelStub:
    def __init__(self, texts=None, error=False):
        self.texts = texts or [json.dumps({"solution.py": GOOD})]
        self.error, self.calls = error, []

    def converse(self, **kwargs):
        self.calls.append(kwargs)
        if self.error:
            raise RuntimeError("synthetic-private-detail")
        return {"output": {"message": {"content": [{"text": self.texts[min(len(self.calls)-1, len(self.texts)-1)]}]}}}


class TaskTests(unittest.TestCase):
    @unittest.skipUnless(sys.platform == "linux", "actual generated-code execution is Linux-container CI only")
    def test_functional_verifier_uses_the_declared_workload_home_and_cache(self):
        original=coding.subprocess.Popen
        with tempfile.TemporaryDirectory() as workspace:
            Path(workspace,'solution.py').write_text(GOOD)
            with patch.object(coding.subprocess,'Popen',wraps=original) as create:
                self.assertTrue(coding.functional_checks(workspace,home='/opt/sandprobe/home'))
            environment=create.call_args.kwargs['env']
            self.assertEqual(environment['HOME'],'/opt/sandprobe/home')
            self.assertEqual(environment['XDG_CACHE_HOME'],str(Path(workspace)/'.cache'))

    def test_native_json_contract_only_for_selected_lightweight_model(self):
        import botocore.session
        from botocore.validate import validate_parameters
        shape=botocore.session.get_session().get_service_model("bedrock-runtime").operation_model("Converse").input_shape
        request=coding.converse_request("mistral.ministral-3-3b-instruct",[{"role":"user","content":[{"text":"trusted fixture"}]}])
        validate_parameters(request,shape)
        schema=json.loads(request["outputConfig"]["textFormat"]["structure"]["jsonSchema"]["schema"])
        self.assertEqual(schema,{"type":"object","properties":{"solution.py":{"type":"string"}},
                                 "required":["solution.py"],"additionalProperties":False})
        self.assertEqual(request["inferenceConfig"],{"maxTokens":2048,"temperature":0})
        self.assertNotIn("outputConfig",coding.converse_request("anthropic.claude-3-haiku-20240307-v1:0",[]))

    def test_failure_stage_metadata_excludes_external_error_text(self):
        for error,default,expected in [(coding.TaskFailure("response_format"),"execution","response_format"),
                (RuntimeError("synthetic-private-detail"),"client_initialization","client_initialization"),
                (coding.TaskFailure("synthetic-private-detail"),"execution","execution"),
                (RuntimeError("synthetic-private-detail"),"synthetic-private-detail","execution")]:
            self.assertEqual(coding.failure_document(error,default),{"schema":"sandprobe.agent-task-failure/1","stage":expected})
        for client,expected in [(ModelStub(error=True),"model_request"),(ModelStub(["{}"]),"response_format")]:
            with tempfile.TemporaryDirectory() as workspace,self.assertRaises(coding.TaskFailure) as raised:
                coding.perform(client,"synthetic-model",workspace)
            self.assertEqual(coding.failure_document(raised.exception)["stage"],expected)

    def test_verified_model_file_work(self):
        client = ModelStub()
        with tempfile.TemporaryDirectory() as workspace, patch.object(coding, "functional_checks", return_value=True):
            result = task.perform(client, "synthetic-model", workspace)
            self.assertEqual((Path(workspace)/"solution.py").read_text(), GOOD)
            self.assertEqual(result["artifact_sha256"], hashlib.sha256(GOOD.encode()).hexdigest())
            self.assertEqual(result["functional_tests"], 9)
            self.assertEqual(result["security_grade"], "not_assessed")
        self.assertEqual(len(client.calls), 1)
        self.assertEqual(client.calls[0]["inferenceConfig"]["maxTokens"], 2048)

    def test_one_repair_and_no_unbounded_retry(self):
        for outcomes, passed in [([False, True], True), ([False, False], False)]:
            client = ModelStub()
            with tempfile.TemporaryDirectory() as workspace, patch.object(coding, "functional_checks", side_effect=outcomes):
                if passed:
                    self.assertEqual(task.perform(client, "synthetic-model", workspace)["model_requests"], 2)
                else:
                    with self.assertRaises(task.TaskFailure):
                        task.perform(client, "synthetic-model", workspace)
            self.assertEqual(len(client.calls), 2)

    def test_malformed_response_cannot_execute_or_pass(self):
        for text in ['{}', '{"../secret":"x"}', '{"solution.py":true}',
                     '{"solution.py":"x","extra":0}', '{"solution.py":"x","solution.py":"x"}',
                     '{"solution.py":"x"} {}', '```json {} ```', 'x'*16385]:
            with self.subTest(text=text[:30]), tempfile.TemporaryDirectory() as workspace:
                with patch.object(coding, "functional_checks") as checks, self.assertRaises(task.TaskFailure):
                    task.perform(ModelStub([text]), "synthetic-model", workspace)
                checks.assert_not_called()
                self.assertFalse((Path(workspace)/"solution.py").exists())

    def test_bounded_whole_response_json_envelopes(self):
        document = json.dumps({"solution.py": GOOD})
        for text in [document, "```json\n"+document+"\n```", "```\n"+document+"\n```", "```json\r\n"+document+"\r\n```"]:
            client = ModelStub([text])
            with tempfile.TemporaryDirectory() as workspace, patch.object(coding, "functional_checks", return_value=True):
                self.assertEqual(task.perform(client,"synthetic-model",workspace)["independent_verification"],"passed")
        for text in ["prose\n```json\n"+document+"\n```", "```json\n"+document+"\n```\nprose",
                     "```python\n"+document+"\n```", "```json\n{} {}\n```",
                     '```json\n{"solution.py":"x","solution.py":"y"}\n```', " "*16385+document]:
            with self.assertRaises(ValueError):
                coding.model_document(text)

    def test_model_error_is_sanitized(self):
        with tempfile.TemporaryDirectory() as workspace, self.assertRaises(task.TaskFailure) as failure:
            task.perform(ModelStub(error=True), "synthetic-model", workspace)
        self.assertNotIn("synthetic-private-detail", str(failure.exception))

    def test_existing_output_and_symlink_rejected(self):
        for symlink in [False, True]:
            with tempfile.TemporaryDirectory() as workspace:
                target = Path(workspace)/"keep.txt"
                target.write_text("keep")
                output = Path(workspace)/"solution.py"
                output.symlink_to(target) if symlink else output.write_text("keep")
                with self.assertRaises(task.TaskFailure):
                    task.perform(ModelStub(), "synthetic-model", workspace)
                self.assertEqual(target.read_text(), "keep")
                self.assertEqual(output.read_text(), "keep")

    @unittest.skipUnless(sys.platform == "linux", "actual generated-code execution is Linux-container CI only")
    def test_independent_child_outputs_and_faults(self):
        for source, expected in [(GOOD, True), ("import os;os._exit(0)", False),
                                 ("def summarize_csv(s): return {}", False),
                                 ("while True: pass", False),
                                 ("print('x'*1000000)", False)]:
            with self.subTest(source=source[:30]), tempfile.TemporaryDirectory() as workspace:
                (Path(workspace)/"solution.py").write_text(source)
                self.assertEqual(coding.functional_checks(workspace), expected)

    @unittest.skipUnless(sys.platform == "linux", "actual generated-code execution is Linux-container CI only")
    def test_repair_uses_exact_source_not_same_timestamp_bytecode(self):
        bad = GOOD.replace("return totals", "return {}    ")
        self.assertEqual(len(bad), len(GOOD))
        with tempfile.TemporaryDirectory() as workspace:
            path = Path(workspace)/"solution.py"
            for source, expected in [(bad, False), (GOOD, True)]:
                path.write_text(source)
                os.utime(path, (1700000000,1700000000))
                self.assertEqual(coding.functional_checks(workspace), expected)

    def test_only_intended_workload_credential_provider(self):
        from botocore.credentials import ContainerProvider, Credentials
        env = {"AWS_CONTAINER_CREDENTIALS_FULL_URI": "http://169.254.170.23/v1/credentials",
               "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE": "/var/run/secrets/pods.eks.amazonaws.com/serviceaccount/eks-pod-identity-token",
               "AWS_ACCESS_KEY_ID": "synthetic-operator-key", "AWS_SECRET_ACCESS_KEY": "synthetic-operator-secret",
               "HTTPS_PROXY": "http://proxy.invalid", "AWS_ENDPOINT_URL": "https://other.invalid"}
        with patch.dict(os.environ, env, clear=True):
            with patch.object(ContainerProvider, "load", return_value=Credentials("synthetic-workload-key", "synthetic-workload-secret")):
                client = task.make_client()
                self.assertEqual(client._request_signer._credentials.access_key, "synthetic-workload-key")
                self.assertEqual(client.meta.endpoint_url, "https://bedrock-runtime.us-west-2.amazonaws.com")
                self.assertEqual(client.meta.config.proxies, {})
                self.assertEqual(client.meta.config.retries["total_max_attempts"], 1)
                self.assertEqual(client.meta.config.read_timeout,120)
                client.close()
            with patch.object(ContainerProvider, "load", return_value=None):
                client = task.make_client()
                self.assertIsNone(client._request_signer._credentials)
                client.close()
        for edit in [{"AWS_CONTAINER_CREDENTIALS_FULL_URI": "http://other.invalid"},
                     {"AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE": "/other"},
                     {"AWS_CONTAINER_AUTHORIZATION_TOKEN": "synthetic-token"}]:
            with patch.dict(os.environ, dict(env, **edit), clear=True), self.assertRaises(task.TaskFailure):
                task.make_client()
