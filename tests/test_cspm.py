import json
import os
import sys
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "firmware"))

import importlib.util
_spec = importlib.util.spec_from_file_location(
    "cspm",
    os.path.join(REPO, "firmware", "cspm.py"),
)
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)

FIXTURE = os.path.join(REPO, "fixtures", "assets.json")


def load_assets():
    with open(FIXTURE, encoding="utf-8") as fh:
        return json.load(fh)


class TestCSPMAuditor(unittest.TestCase):

    def setUp(self):
        self.auditor = mod.CSPMAuditor(load_assets())

    def test_run_produces_violations(self):
        violations = self.auditor.run()
        self.assertGreater(len(violations), 0)

    def test_violation_structure(self):
        violations = self.auditor.run()
        for v in violations:
            for key in ("asset", "provider", "type", "rule_id", "rule_name", "severity"):
                self.assertIn(key, v)

    def test_public_storage_flagged(self):
        violations = self.auditor.run()
        self.assertTrue(any(v["rule_id"] == "PUB-001" for v in violations))

    def test_critical_rule_flagged(self):
        violations = self.auditor.run()
        self.assertTrue(any(v["rule_id"] == "SQL-001" for v in violations))

    def test_compliant_asset_no_violation(self):
        asset = {
            "provider": "aws", "type": "s3", "id": "secure-bucket",
            "config": {"public_access": False, "encryption": True, "versioning": True,
                       "logging": True}
        }
        auditor = mod.CSPMAuditor([asset])
        violations = auditor.run()
        ids = {v["asset"] for v in violations}
        self.assertNotIn("secure-bucket", ids)

    def test_scores_present(self):
        self.auditor.run()
        self.assertGreater(len(self.auditor.scores), 0)

    def test_severity_summary(self):
        self.auditor.run()
        self.assertGreaterEqual(len(self.auditor.violations), 1)


class TestEmbeddedDemo(unittest.TestCase):

    def test_no_assets_uses_demo(self):
        auditor = mod.CSPMAuditor(None)
        violations = auditor.run()
        self.assertGreater(len(violations), 0)


if __name__ == "__main__":
    unittest.main()