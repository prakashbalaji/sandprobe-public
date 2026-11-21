import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

from lifecycle import Commands, Failure, Journal


class LifecycleTests(unittest.TestCase):
    def test_kubectl_errors_export_only_fixed_categories(self):
        with tempfile.TemporaryDirectory() as root:
            executable=Path(root)/"kubectl"
            executable.write_text("#!"+sys.executable+"\nimport sys\nsys.stderr.write(sys.argv[1]);sys.exit(1)\n")
            executable.chmod(0o755)
            for text,expected in [
                ("getting credentials: exec: executable aws failed synthetic-private-detail","kubernetes_authentication_failed"),
                ("dial tcp synthetic-private-detail: i/o timeout","kubernetes_request_timeout"),
                ("ServiceUnavailable synthetic-private-detail","kubernetes_api_unavailable"),
                ("unknown synthetic-private-detail","command_failed")]:
                with self.subTest(expected=expected),self.assertRaisesRegex(Failure,"^"+expected+"$"):
                    Commands().call([str(executable),text])

    def test_private_durable_state_and_exclusive_lock(self):
        with tempfile.TemporaryDirectory() as root:
            j = Journal(root, "a"*16, create=True)
            j.intent("role", name="owned")
            j.recorded("role", role_id="immutable")
            self.assertEqual(stat.S_IMODE(j.path.stat().st_mode), 0o600)
            with self.assertRaises(BlockingIOError):
                Journal(root, "a"*16)
            j.close()
            loaded = Journal(root, "a"*16)
            self.assertEqual(loaded.data["resources"]["role"]["role_id"], "immutable")
            loaded.close()

    def test_symlinks_hardlinks_and_permissive_files_rejected(self):
        for mode in ["symlink", "hardlink", "public"]:
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as root:
                j = Journal(root, "a"*16, create=True)
                path = j.path
                j.close()
                if mode == "public":
                    path.chmod(0o644)
                else:
                    target = Path(root)/"target"
                    path.rename(target)
                    path.symlink_to(target) if mode == "symlink" else os.link(target, path)
                with self.assertRaises((Failure, OSError)):
                    Journal(root, "a"*16)

    def test_bounded_commands_and_sanitized_errors(self):
        commands = Commands()
        self.assertEqual(commands.call([sys.executable, "-c", "print('ok')"]).strip(), b"ok")
        with self.assertRaisesRegex(Failure, "command_output_too_large"):
            commands.call([sys.executable, "-c", "print('x'*100)"], limit=10)
        with self.assertRaisesRegex(Failure, "^command_failed$"):
            commands.call([sys.executable, "-c", "import sys;sys.stderr.write('synthetic-private-detail');sys.exit(1)"])
        with self.assertRaisesRegex(Failure, "command_unavailable_or_timed_out"):
            commands.call([sys.executable, "-c", "import time;time.sleep(5)"], timeout=0.05)

    def test_fifo_state_is_rejected_without_blocking(self):
        with tempfile.TemporaryDirectory() as root:
            j = Journal(root, "a"*16, create=True)
            path = j.path
            j.close()
            path.unlink()
            os.mkfifo(path, 0o600)
            with self.assertRaises(Failure):
                Journal(root, "a"*16)

    def test_interrupt_reaps_create_command_before_propagating(self):
        process = Mock(pid=12345)
        process.communicate.side_effect = KeyboardInterrupt()
        events = []
        process.wait.side_effect = lambda: events.append("wait")
        with patch("lifecycle.subprocess.Popen", return_value=process) as start, patch("lifecycle.os.killpg", side_effect=lambda *a: events.append("kill")):
            with self.assertRaises(KeyboardInterrupt):
                Commands().call(["synthetic-create-command"])
        self.assertTrue(start.call_args.kwargs["start_new_session"])
        self.assertEqual(events, ["kill", "wait"])

    def test_delegated_durable_metadata_rejects_nonregular_paths(self):
        import importlib.util
        module_path = Path(__file__).resolve().parents[1]/"durable_state.py"
        spec = importlib.util.spec_from_file_location("durable_metadata", module_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as root:
            path = Path(root)/"eks.state"
            module.write("init", path, ["did=12345678"])
            module.write("append", path, ["cluster=sandprobe-12345678"])
            self.assertEqual(path.read_text(), "did=12345678\ncluster=sandprobe-12345678\n")
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            path.unlink()
            os.mkfifo(path, 0o600)
            with self.assertRaises((OSError, ValueError)):
                module.write("append", path, ["did=12345678"])
