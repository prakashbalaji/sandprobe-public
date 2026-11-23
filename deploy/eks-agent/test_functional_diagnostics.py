import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch, Mock

import coding

GOOD=Path(__file__).with_name("fixtures").joinpath("solution.py").read_text()

def envelope(kind="passed", complete=True, matched=9, failed=None):
    return {"functional_tests":9,"independent_verification":"passed" if kind=="passed" else "failed", "artifact_sha256":"a"*64,
            "diagnostics":{"schema":"sandprobe.functional-diagnostic/1","failure_kind":kind,"outputs_complete":complete,
                           "matched_cases":matched,"expected_cases":9,"failed_case_ids":failed or []}}

class FunctionalDiagnosticsTests(unittest.TestCase):
    def test_exact_shape_and_consistent_case_accounting(self):
        value=envelope();self.assertEqual(coding.validated_verification_diagnostic(value),value["diagnostics"])
        variants=[]
        for key,bad in [("failure_kind","synthetic-private-detail"),("matched_cases",True),("expected_cases",8),("outputs_complete",False),("failed_case_ids",[1,1]),("failed_case_ids",[True]),("extra","synthetic-private-detail")]:
            v=copy.deepcopy(value);v["diagnostics"][key]=bad;variants.append(v)
        v=envelope();v["independent_verification"]="failed";variants.append(v)
        v=envelope("case_mismatch",True,8,[9]);v["diagnostics"]["matched_cases"]=9;variants.append(v)
        variants.append(envelope("dependency_error",False,1))
        for v in variants:
            with self.assertRaises(ValueError):coding.validated_verification_diagnostic(v)

    def test_setup_failure_and_deadline_do_not_claim_checked_cases(self):
        with tempfile.TemporaryDirectory() as workspace:
            diagnostic={"unexpected":"synthetic-private-detail"}
            with patch.object(coding.subprocess,"Popen",side_effect=OSError("synthetic-private-detail")):
                self.assertFalse(coding.functional_checks(workspace,"a"*64,diagnostics=diagnostic))
            self.assertEqual(diagnostic["failure_kind"],"checker_setup_failed")
            self.assertFalse(diagnostic["outputs_complete"])
            self.assertNotIn("synthetic-private-detail",json.dumps(diagnostic))
            diagnostic={}
            child=Mock(pid=4242)
            child.communicate.side_effect=subprocess.TimeoutExpired("synthetic-private-detail",5)
            with patch.object(coding.subprocess,"Popen",return_value=child),patch.object(coding.os,"killpg") as kill:
                self.assertFalse(coding.functional_checks(workspace,"a"*64,diagnostics=diagnostic))
            self.assertEqual(diagnostic["failure_kind"],"deadline")
            self.assertFalse(diagnostic["outputs_complete"])
            child.wait.assert_called_once();kill.assert_called_once()

    @unittest.skipUnless(sys.platform=="linux","known-source execution is Linux CI only")
    def test_real_known_sources_distinguish_failure_types_without_text(self):
        cases=[(GOOD,"passed"),("def summarize_csv(text): return {}","case_mismatch"),
               ("import sandprobe_missing_dependency_fixture","dependency_error"),
               ("def summarize_csv(:","syntax_error"),
               ("raise MemoryError('synthetic-private-detail')","memory_error"),
               ("raise RuntimeError('synthetic-private-detail')","execution_error"),
               ("print('synthetic-private-detail')\ndef summarize_csv(text): return {}","invalid_output")]
        for source,kind in cases:
            with self.subTest(kind=kind),tempfile.TemporaryDirectory() as workspace:
                Path(workspace,"solution.py").write_text(source)
                diagnostic={};passed=coding.functional_checks(workspace,hashlib.sha256(source.encode()).hexdigest(),diagnostics=diagnostic)
                self.assertEqual(passed,kind=="passed");self.assertEqual(diagnostic["failure_kind"],kind)
                value=envelope(kind,diagnostic["outputs_complete"],diagnostic["matched_cases"],diagnostic["failed_case_ids"])
                coding.validated_verification_diagnostic(value)
                self.assertNotIn("synthetic-private-detail",json.dumps(diagnostic))
                if kind=="case_mismatch":self.assertEqual(diagnostic["failed_case_ids"],[1,3,4,5,6,7,8,9])

        with tempfile.TemporaryDirectory() as workspace:
            Path(workspace,"solution.py").write_text(GOOD)
            diagnostic={}
            self.assertFalse(coding.functional_checks(workspace,"0"*64,diagnostics=diagnostic))
            self.assertEqual(diagnostic["failure_kind"],"artifact_unverified")
            self.assertFalse(diagnostic["outputs_complete"])
