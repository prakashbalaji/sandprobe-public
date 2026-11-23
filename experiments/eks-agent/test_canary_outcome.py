"""RUN-16 no-create proof must survive fault injection, never absence alone."""
import os
os.environ.setdefault("SANDPROBE_AWS_ACCOUNT", "111122223333")  # AWS's documentation placeholder
os.environ.setdefault("SANDPROBE_AWS_PROFILE", "test-profile")
import hashlib
import json
import os
from pathlib import Path
import runpy
import sys
import tempfile
import time
import subprocess
import unittest
from unittest.mock import patch

from lifecycle import Commands, Failure
from runner import Runner
from lifecycle import Journal

API = runpy.run_path(str(Path(__file__).resolve().parents[2] / "deploy" / "canary_outcome.py"))


class CanaryOutcomeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.path = self.root / "outcome.json"
        self.state = self.root / "canary.state"
        self.delegate = self.root / "delegate.sh"
        self.delegate.write_text("trusted delegate")
        self.digest = hashlib.sha256(self.delegate.read_bytes()).hexdigest()
        self.run, self.nonce = "a" * 16, "b" * 48

    def begin(self):
        API["begin"](self.path, self.run, self.nonce, self.state, self.delegate)

    def proof(self, **changes):
        args = dict(path=self.path, run=self.run, nonce=self.nonce, state=self.state, digest=self.digest)
        args.update(changes)
        return API["no_create"](**args)

    def test_only_bound_terminal_precreate_failure_is_proof(self):
        self.assertFalse(self.proof())
        self.begin()
        self.assertFalse(self.proof())
        with self.assertRaises(ValueError):
            API["finish"](self.path, self.nonce, "failed", False)
        API["finish"](self.path, self.nonce, "failed", True)
        self.assertTrue(self.proof())
        for changes in [dict(run="c"*16), dict(nonce="c"*48), dict(digest="c"*64), dict(state=self.root/"other")]:
            self.assertFalse(self.proof(**changes))
        with self.assertRaises(ValueError):
            API["mutation"](self.path, self.nonce, self.state, self.delegate)

    def test_lost_response_after_barrier_never_no_create(self):
        self.begin()
        API["mutation"](self.path, self.nonce, self.state, self.delegate)
        self.assertFalse(self.proof())
        API["finish"](self.path, self.nonce, "interrupted", True)
        self.assertFalse(self.proof())

    def test_malformed_and_unsafe_proof_rejected(self):
        self.begin()
        API["finish"](self.path, self.nonce, "failed", True)
        valid = self.path.read_text()
        for raw in ["[]", "{}", "null", valid[:-1]+',"SCHEMA":"duplicate"}', valid.replace('"terminal":true','"terminal":1')]:
            self.path.write_text(raw)
            self.assertFalse(self.proof())
        self.path.write_text(valid)
        self.path.chmod(0o644)
        self.assertFalse(self.proof())
        self.path.chmod(0o600)
        other = self.root / "other"
        self.path.rename(other)
        self.path.symlink_to(other)
        self.assertFalse(self.proof())

    def test_changed_delegate_cannot_cross_barrier(self):
        self.begin()
        self.delegate.write_text("changed")
        with self.assertRaises(ValueError):
            API["mutation"](self.path, self.nonce, self.state, self.delegate)

    def test_success_and_error_reap_surviving_descendant(self):
        for code in [0, 1]:
            marker = self.root / str(code)
            child = "import time,pathlib;time.sleep(1);pathlib.Path("+repr(str(marker))+").write_text('late')"
            program = "import subprocess,sys;subprocess.Popen([sys.executable,'-c',"+repr(child)+"]);sys.exit("+str(code)+")"
            commands = Commands()
            if code:
                with self.assertRaisesRegex(Failure, "^command_failed$"):
                    commands.call([sys.executable, "-c", program], quiesce_group=True)
            else:
                commands.call([sys.executable, "-c", program], quiesce_group=True)
            self.assertTrue(commands.last_group_quiescent)
            time.sleep(1.1)
            self.assertFalse(marker.exists())

    def test_timeout_quiesces_and_uncertainty_does_not_seal(self):
        commands = Commands()
        with self.assertRaisesRegex(Failure, "command_unavailable_or_timed_out"):
            commands.call([sys.executable, "-c", "import time;time.sleep(5)"], timeout=.1, quiesce_group=True)
        self.assertTrue(commands.last_group_quiescent)
        with patch("process_group._quiescent", side_effect=RuntimeError()):
            with self.assertRaisesRegex(Failure, "command_quiescence_unconfirmed"):
                commands.call([sys.executable, "-c", "pass"], quiesce_group=True)
        self.assertFalse(commands.last_group_quiescent)

    def test_real_delegate_refusal_is_nonmutating_and_isolated(self):
        with JournalContext(self.root / "journals") as journal:
            r = Runner(journal)
            digest = hashlib.sha256((Path(__file__).resolve().parents[2]/"deploy"/"canary.sh").read_bytes()).hexdigest()
            journal.intent("canary", delegated_state="canary.state", namespace="sandprobe-canary-"+r.run_id,
                outcome_file="canary-outcome.json", outcome_nonce=self.nonce, delegate_sha256=digest)
            tools = self.root / "bin"
            tools.mkdir()
            log = self.root/"commands"
            aws = tools/"aws"
            aws.write_text("#!/bin/sh\nprintf '%s\\n' \"$*\" >>\"$CALL_LOG\"\ncase \"$*\" in *describe-instances*) echo i-existing; exit 0;; *) exit 99;; esac\n")
            aws.chmod(0o700)
            r.env.update(PATH=str(tools)+os.pathsep+os.environ["PATH"], CALL_LOG=str(log))
            with self.assertRaisesRegex(Failure,"^command_failed$"):
                r.canary("up",10)
            calls = log.read_text()
            self.assertIn("Values=sandprobe-canary-"+r.run_id,calls)
            self.assertEqual(len(calls.splitlines()),1)
            self.assertTrue(r.canary_no_create(journal.data["resources"]["canary"]))
            r.account = lambda: None
            self.assertTrue(r.cleanup())
            self.assertEqual(journal.data["resources"]["canary"]["status"],"not_created")
            self.assertEqual(log.read_text(),calls)

    def test_nonterminal_worker_blocks_teardown_even_with_state(self):
        with JournalContext(self.root/"journals") as journal:
            r = Runner(journal)
            journal.intent("canary", outcome_file="canary-outcome.json",outcome_nonce=self.nonce,delegate_sha256=self.digest)
            API["begin"](journal.folder/"canary-outcome.json",r.run_id,self.nonce,journal.folder/"canary.state",self.delegate)
            (journal.folder/"canary.state").write_text("did=owned")
            r.account = lambda: None
            with patch.object(r,"canary") as teardown:
                self.assertFalse(r.cleanup())
                teardown.assert_not_called()

    def test_real_script_barrier_precedes_first_mutation(self):
        script = (Path(__file__).resolve().parents[2]/"deploy"/"canary.sh").read_text()
        up = script.split("\nup() {",1)[1]
        self.assertLess(up.index("canary_outcome.py"),up.index("aws s3api create-bucket"))
        self.assertLess(up.index('durable_state.py" init'),up.index("canary_outcome.py"))

    def test_real_delegate_failed_barrier_prevents_all_cloud_creates(self):
        tools = self.root/"bin"
        tools.mkdir()
        log = self.root/"calls"
        for name, body in {
            "aws":"echo \"$*\" >>\"$CALL_LOG\"; case \"$*\" in *describe-instances*) exit 0;; *) exit 99;; esac",
            "cf":"case \"$*\" in 'zones list') echo '[{\"name\":\"ac0.dev\",\"id\":\"z1\"}]';; *) echo '[]';; esac",
        }.items():
            executable=tools/name
            executable.write_text("#!/bin/sh\n"+body+"\n");executable.chmod(0o700)
        env=dict(os.environ,PROFILE="test-profile",PATH=str(tools)+os.pathsep+os.environ["PATH"],CALL_LOG=str(log),
            STATE=str(self.state),DURABLE_STATE="1",SANDPROBE_CANARY_OUTCOME_FILE=str(self.path),
            SANDPROBE_CANARY_OUTCOME_NONCE=self.nonce,SANDPROBE_CANARY_NAME="sandprobe-canary-"+self.run)
        script=Path(__file__).resolve().parents[2]/"deploy"/"canary.sh"
        result=subprocess.run(["bash",str(script),"up"],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=10)
        self.assertNotEqual(result.returncode,0)
        self.assertTrue(self.state.exists())
        self.assertEqual(len(log.read_text().splitlines()),1)
        self.assertFalse(self.proof())


class JournalContext:
    def __init__(self,root,run="a"*16):
        self.journal = Journal(root,run,create=True)
    def __enter__(self):
        return self.journal
    def __exit__(self,*args):
        self.journal.close()


if __name__ == "__main__":
    unittest.main()
