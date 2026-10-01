from unittest.mock import Mock

from django.test import TestCase

from local.api_app.models.finding_models import FindingModel
from local.api_app.models.scan_models import ScanModel
from local.api_app.models.sbom_models import SbomModel
from local.api_app.views.finding_views import (
    FindingListCreateView,
    SbomFindingListCreateView,
    SbomLicenseFindingList,
)


def _call(view_cls, scan_id, query_params=None):
    """Call the view's .get() bypassing the @require_permission auth wrapper
    (functools.wraps exposes the original function via __wrapped__), mirroring
    how test_dashboard.py unit-tests view methods directly with a Mock request."""
    unwrapped = view_cls.get.__wrapped__
    request = Mock(query_params=query_params or {})
    return unwrapped(view_cls(), request, scan_id=scan_id)


class FindingListViewsTests(TestCase):
    def test_code_findings_404_for_nonexistent_scan(self):
        response = _call(FindingListCreateView, "no-such-scan")
        self.assertEqual(response.status_code, 404)

    def test_code_findings_200_empty_for_real_scan_with_no_findings(self):
        scan = ScanModel.create({"project_id": "p", "scan_name": "S"})
        response = _call(FindingListCreateView, scan["id"])
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["findings"], [])

    def test_code_findings_200_with_real_findings(self):
        scan = ScanModel.create({"project_id": "p", "scan_name": "S"})
        FindingModel.insert_many([{"scan_id": scan["id"], "title": "SQLi", "severity": "high"}])
        response = _call(FindingListCreateView, scan["id"])
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.data["findings"]), 1)

    def test_code_findings_sorted_newest_first_when_requested(self):
        from datetime import datetime, timezone, timedelta
        scan = ScanModel.create({"project_id": "p", "scan_name": "S"})
        now = datetime.now(timezone.utc)
        older = FindingModel.insert_many([{
            "scan_id": scan["id"], "title": "old", "severity": "low",
            "created_at": now - timedelta(seconds=10),
        }])[0]
        newer = FindingModel.insert_many([{
            "scan_id": scan["id"], "title": "new", "severity": "high",
            "created_at": now,
        }])[0]
        response = _call(FindingListCreateView, scan["id"], query_params={"sort": "-created_at"})
        self.assertEqual(response.status_code, 200)
        ids = [f["id"] for f in response.data["findings"]]
        self.assertEqual(ids, [newer["id"], older["id"]])

    def test_code_findings_rejects_unrecognized_sort_value(self):
        scan = ScanModel.create({"project_id": "p", "scan_name": "S"})
        response = _call(FindingListCreateView, scan["id"], query_params={"sort": "bogus"})
        self.assertEqual(response.status_code, 400)

    def test_sbom_findings_404_for_nonexistent_scan(self):
        response = _call(SbomFindingListCreateView, "no-such-scan")
        self.assertEqual(response.status_code, 404)

    def test_sbom_findings_200_empty_for_real_scan_with_no_findings(self):
        scan = SbomModel.create({"project_id": "p", "scan_name": "SB"})
        response = _call(SbomFindingListCreateView, scan["id"])
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["findings"], [])

    def test_sbom_license_findings_404_for_nonexistent_scan(self):
        response = _call(SbomLicenseFindingList, "no-such-scan")
        self.assertEqual(response.status_code, 404)

    def test_sbom_license_findings_200_empty_for_real_scan_with_no_findings(self):
        scan = SbomModel.create({"project_id": "p", "scan_name": "SB"})
        response = _call(SbomLicenseFindingList, scan["id"])
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["licenses"], [])
