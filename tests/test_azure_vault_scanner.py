import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import azure_vault_scanner as mod

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXTURE = os.path.join(REPO, "fixtures", "vaults.json")


class TestDaysUntil(unittest.TestCase):

    def test_past_date_negative(self):
        self.assertLess(mod._days_until("2020-01-01T00:00:00Z"), 0)

    def test_far_future_positive(self):
        self.assertGreater(mod._days_until("2999-01-01T00:00:00Z"), 0)

    def test_invalid_returns_none(self):
        self.assertIsNone(mod._days_until("not-a-date"))


class TestAccessPolicyAuditor(unittest.TestCase):

    def test_purge_permission_flagged(self):
        vault_details = {
            "properties": {
                "accessPolicies": [
                    {"tenantId": "t", "objectId": "o1", "displayName": "deploy-bot",
                     "permissionsToSecrets": [{"permissions": ["get", "purge"]}]}
                ]
            }
        }
        findings = mod.AccessPolicyAuditor().audit(vault_details, "kv")
        cats = [f.category for f in findings]
        self.assertTrue(any("purge" in c.lower() for c in cats))


class TestOfflineVaultAuditor(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        with open(FIXTURE, encoding="utf-8") as fh:
            cls.fixture = json.load(fh)

    def setUp(self):
        self.auditor = mod.OfflineVaultAuditor()

    def test_fixture_audit_produces_findings(self):
        findings = self.auditor.audit(self.fixture["vaults"])
        self.assertGreater(len(findings), 0)
        for f in findings:
            self.assertIn(f.severity, ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"))
            self.assertTrue(f.category)
            self.assertTrue(f.resource)
            self.assertTrue(f.message)

    def test_access_policy_over_permission_detected(self):
        findings = self.auditor.audit(self.fixture["vaults"])
        self.assertTrue(any(f.severity == "CRITICAL" for f in findings))

    def test_soft_delete_disabled_detected(self):
        findings = self.auditor.audit(self.fixture["vaults"])
        self.assertTrue(any(f.category == "Soft Delete Disabled" for f in findings))

    def test_weak_key_detected(self):
        findings = self.auditor.audit(self.fixture["vaults"])
        self.assertTrue(any(f.category == "Weak Key Size" for f in findings))

    def test_expired_certificate_detected(self):
        findings = self.auditor.audit(self.fixture["vaults"])
        self.assertTrue(any(f.category == "Expired Certificate" for f in findings))


class TestFixtureLoader(unittest.TestCase):

    def test_load_fixture(self):
        vaults = mod.load_vault_fixtures(FIXTURE)
        self.assertEqual(len(vaults), 1)

    def test_load_missing_file(self):
        with self.assertRaises(FileNotFoundError):
            mod.load_vault_fixtures("does-not-exist.json")


class TestReportStructure(unittest.TestCase):

    def test_json_report_structure(self):
        with open(FIXTURE, encoding="utf-8") as fh:
            vaults = json.load(fh)["vaults"]
        findings = mod.OfflineVaultAuditor().audit(vaults)
        report = mod.findings_to_json_offline(vaults, findings)
        self.assertEqual(report["finding_count"], len(findings))
        self.assertGreater(report["critical_high_count"], 0)
        for f in report["findings"]:
            self.assertIn("severity", f)
            self.assertIn("remediation", f)


if __name__ == "__main__":
    unittest.main()