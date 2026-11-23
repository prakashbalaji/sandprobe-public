import runpy
from pathlib import Path
import unittest

message=runpy.run_path(str(Path(__file__).resolve().parents[2]/"deploy"/"managed_status.py"))["completion_message"]

class ManagedCompletionTests(unittest.TestCase):
    def card(self,complete=False):return {"valid":True,"score":4,"of":6,"coverage":{"complete":complete}}
    def test_rc_completion_with_gaps_is_separate_from_exit5(self):
        text=message(self.card(),True,True,{"benchmark_requirements_met":False},5)
        self.assertIn("completed with gaps",text);self.assertIn("RC exposure 4/6",text)
        self.assertIn("the RC assessment completed",text);self.assertIn("workload verified",text)
    def test_missing_results_workload_and_cleanup_stay_distinct(self):
        self.assertIn("RC assessment unavailable",message(None,True,True))
        self.assertIn("workload not verified",message(self.card(),False,True))
        self.assertIn("cleanup unconfirmed",message(self.card(),True,False))
        self.assertIn("execution interrupted",message(self.card(),True,True,execution_ok=False))
    def test_complete_needs_coverage_and_requirements(self):
        self.assertIn("assessment completed |",message(self.card(True),True,True,{"benchmark_requirements_met":True},0))
        self.assertIn("completed with gaps",message(self.card(False),True,True,{"benchmark_requirements_met":True},0))
    def test_no_untrusted_values_are_emitted_as_scores(self):
        for value in [None,{}, {"valid":True,"score":True,"of":6},{"valid":True,"score":"synthetic-private-detail","of":6}]:
            text=message(value,False,True,exit_code="synthetic-private-detail")
            self.assertNotIn("synthetic-private-detail",text);self.assertIn("RC exposure unavailable",text)
