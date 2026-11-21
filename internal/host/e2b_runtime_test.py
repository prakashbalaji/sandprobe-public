"""Offline PRV-8 helper contract tests; never creates or contacts a sandbox."""
import base64
import contextlib
import importlib.util
import io
import json
import sys
sys.dont_write_bytecode = True
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location(
    "e2b_runtime", Path(__file__).with_name("e2b_runtime.py")
)
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)

class RuntimeContract(unittest.TestCase):
    def request(self, op, **kwargs):
        return dict(
            op=op, sandbox_id="offline-test123", domain="e2b.app",
            envd_version="0.5.0", access_token="synthetic-runtime-token",
            **kwargs,
        )

    def call(self, request):
        output = io.StringIO()
        with patch("sys.stdin", io.StringIO(json.dumps(request))), contextlib.redirect_stdout(output):
            helper.main()
        return output.getvalue()

    def test_sdk_version_before_any_runtime(self):
        with patch.object(helper.importlib.metadata, "version", return_value="wrong"):
            with self.assertRaises(ValueError):
                self.call({"op": "check"})

    def test_real_constructor_binds_only_existing_sandbox(self):
        from e2b import Sandbox
        from e2b.connection_config import ConnectionConfig
        from packaging.version import Version
        # These would contact management or extend lifespan if ever called.
        with patch.object(Sandbox, "create", side_effect=AssertionError("create forbidden")), patch.object(Sandbox, "connect", side_effect=AssertionError("connect forbidden")):
            box = Sandbox(
                sandbox_id="offline-test123", sandbox_domain="e2b.app",
                envd_version=Version("0.5.0"), envd_access_token="synthetic-runtime-token",
                connection_config=ConnectionConfig(
                    domain="e2b.app", api_url="https://api.e2b.app",
                    extra_sandbox_headers={
                        "X-Access-Token": "synthetic-runtime-token",
                        "E2b-Sandbox-Id": "offline-test123",
                        "E2b-Sandbox-Port": "49983",
                    },
                ),
            )
        self.assertEqual(box.envd_api_url, "https://sandbox.e2b.app")
        self.assertFalse(box._envd_api.follow_redirects)
        self.assertEqual(box.connection_config.sandbox_headers["E2b-Sandbox-Id"], "offline-test123")
        self.assertEqual(box.connection_config.sandbox_headers["E2b-Sandbox-Port"], "49983")
        self.assertEqual(box.connection_config.sandbox_headers["X-Access-Token"], "synthetic-runtime-token")
        self.assertIsNone(box.connection_config.api_key)

    def test_exec_and_upload_use_user_and_only_runtime_token(self):
        seen = {}
        class FakeSandbox:
            def __init__(self, **kwargs):
                seen["binding"] = kwargs
                self.commands = SimpleNamespace(run=self.run)
                self.files = SimpleNamespace(write=self.write)
            def run(self, command, **kwargs):
                seen["exec"] = (command, kwargs)
                kwargs["on_stdout"]('{"observation":true}')
                return SimpleNamespace(exit_code=0, stdout='{"observation":true}')
            def write(self, path, data, **kwargs):
                seen["upload"] = (path, data, kwargs)
        with patch("e2b.Sandbox", FakeSandbox):
            self.assertEqual(self.call(self.request("exec", command="uname -m")), '{"observation":true}')
            self.assertEqual(self.call(self.request("upload", path="/tmp/own/probe", data=base64.b64encode(b"binary").decode())), "{}")
        self.assertEqual(seen["exec"][1]["user"], "user")
        self.assertFalse(seen["exec"][1]["retain_output"])
        self.assertEqual(seen["exec"][1]["envs"], {"SANDPROBE_TWIN": "1"})
        self.assertEqual(seen["upload"][2]["user"], "user")
        self.assertEqual(seen["upload"][1], b"binary")
        self.assertEqual(seen["binding"]["envd_access_token"], "synthetic-runtime-token")
        self.assertIsNone(seen["binding"]["connection_config"].api_key)

    def test_stdout_and_stderr_are_bounded_before_sdk_retention(self):
        for stream in ("on_stdout", "on_stderr"):
            class FloodingSandbox:
                def __init__(self, **kwargs):
                    self.commands = SimpleNamespace(run=self.run)
                def run(self, command, **kwargs):
                    self_outer.assertFalse(kwargs["retain_output"])
                    for _ in range(17):
                        kwargs[stream]("x" * 65536)
                    raise AssertionError("unbounded stream accepted")
            self_outer = self
            with self.subTest(stream=stream), patch("e2b.Sandbox", FloodingSandbox):
                with self.assertRaisesRegex(ValueError, "output too large"):
                    self.call(self.request("exec", command="probe"))

if __name__ == "__main__":
    unittest.main()
