from django.test import TestCase

from local.api_app.models.finding_models import FindingModel


class ReportSourceTests(TestCase):
    """report_source marks model-written advice ("ai") vs rule-derived text ("")."""

    def _finding(self, **over):
        base = {"scan_id": "scan1", "created_by": "u1", "cwe": "CWE-89", "title": "SQLi", "severity": "high"}
        base.update(over)
        return base

    def test_defaults_to_empty_and_round_trips(self):
        out = FindingModel.insert_many([
            self._finding(file_path="app.py [1,1]"),
            self._finding(file_path="util.py [3,3]", report_source="ai"),
        ])
        self.assertEqual([o["report_source"] for o in out], ["", "ai"])

    def test_is_exposed_by_the_scan_listing(self):
        FindingModel.insert_many([self._finding(report_source="ai")])
        listed = FindingModel.find_by_scan("scan1")["findings"]
        self.assertEqual(listed[0]["report_source"], "ai")

    def test_is_kept_when_an_unchanged_finding_is_copied_forward(self):
        FindingModel.insert_many([
            self._finding(file_path="app.py [1,1]"),
            self._finding(file_path="util.py [3,3]", report_source="ai"),
        ])
        self.assertEqual(FindingModel.copy_forward("scan1", "scan2", {"app.py", "util.py"}), 2)
        by_path = {f["file_path"]: f for f in FindingModel.find_by_scan("scan2")["findings"]}
        self.assertEqual(by_path["app.py [1,1]"]["report_source"], "")
        self.assertEqual(by_path["util.py [3,3]"]["report_source"], "ai")
