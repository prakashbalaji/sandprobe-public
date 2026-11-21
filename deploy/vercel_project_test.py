"""PRV-9 setup contract; entirely local, never contacts Vercel."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("vercel_project", Path(__file__).with_name("vercel-project.py"))
setup = importlib.util.module_from_spec(spec)
spec.loader.exec_module(setup)


class ProjectSetupTest(unittest.TestCase):
    def test_single_create_and_exclusive_intent(self):
        for ambiguous in (False, True):
            with self.subTest(ambiguous=ambiguous), tempfile.TemporaryDirectory() as directory:
                base = Path(directory)
                key, state = base / "key", base / "project.state"
                key.write_text("fixture-not-a-credential")
                key.chmod(0o600)
                calls = []

                class Opener:
                    def open(self, req, timeout):
                        calls.append(req.method)
                        self_state = json.loads(state.read_text())
                        if req.method == "POST":
                            assert self_state["status"] == "intent"
                            if ambiguous:
                                raise OSError("fixture-not-a-credential")
                        else:
                            assert self_state["project_id"] == "prj_fixture"
                        return contextlib.closing(io.BytesIO(json.dumps({"id": "prj_fixture", "accountId": "team_fixture", "name": "sandprobe"}).encode()))

                args = ["vercel-project.py", "--key-file", str(key), "--team", "team_fixture", "--state", str(state)]
                with patch("sys.argv", args), patch.object(setup.urllib.request, "build_opener", return_value=Opener()), contextlib.redirect_stdout(io.StringIO()):
                    if ambiguous:
                        with self.assertRaisesRegex(ValueError, "transport failed"):
                            setup.main()
                    else:
                        setup.main()
                    with self.assertRaises(FileExistsError):
                        setup.main()
                self.assertEqual(calls, ["POST"] if ambiguous else ["POST", "GET"])
                self.assertNotIn("fixture-not-a-credential", state.read_text())
                self.assertEqual(state.stat().st_mode & 0o777, 0o600)


    def test_bad_token_never_leaves_intent_or_calls_provider(self):
        for kind in ("missing", "public"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                base = Path(directory)
                key, state = base / "key", base / "project.state"
                if kind == "public":
                    key.write_text("fixture-not-a-credential")
                    key.chmod(0o644)
                args = ["vercel-project.py", "--key-file", str(key), "--team", "team_fixture", "--state", str(state)]
                with patch("sys.argv", args), patch.object(setup.urllib.request, "build_opener") as network:
                    with self.assertRaises(ValueError):
                        setup.main()
                    network.assert_not_called()
                self.assertFalse(state.exists())


if __name__ == "__main__":
    unittest.main()
