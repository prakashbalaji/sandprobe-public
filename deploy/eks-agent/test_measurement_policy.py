"""MEAS-6: both managed entrypoints refuse unsafe choices before cloud calls."""
import argparse
import json
from pathlib import Path
import runpy
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
parse_hosts = runpy.run_path(str(ROOT / "deploy/workload_measurement.py"))["upload_hosts"]


class MeasurementPolicyTests(unittest.TestCase):
    def test_shared_policy_and_default(self):
        self.assertEqual(parse_hosts(""), [])
        allowed = json.loads((ROOT / "internal/catalog/upload_hosts.json").read_text())
        self.assertEqual(len(set(allowed)), len(allowed))
        for host in allowed:
            self.assertEqual(parse_hosts(host), [host])
        for value in ["*", "all", "github.com,github.com", "https://github.com", "169.254.169.254",
                      "GITHUB.COM", " github.com", "github.com,", ",".join(allowed[:5])]:
            with self.assertRaisesRegex(ValueError, "^invalid workload host selection$"):
                parse_hosts(value)

    def test_daytona_rejects_before_commands_or_credentials(self):
        module = runpy.run_path(str(ROOT / "deploy/daytona-agent/run.py"))
        with patch.dict(module["main"].__globals__, aws=lambda *a: self.fail("cloud call before validation")):
            with self.assertRaisesRegex(ValueError, "^invalid workload host selection$"):
                module["main"](argparse.Namespace(upload_hosts="169.254.169.254"))

    def test_nitro_rejects_before_commands_or_journal_access(self):
        from runner import Runner
        with self.assertRaisesRegex(ValueError, "^invalid workload host selection$"):
            Runner(None, profile="fixture", upload_hosts=["169.254.169.254"])
