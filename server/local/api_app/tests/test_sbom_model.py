import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from django.test import TestCase, override_settings
from local.api_app.models.sbom_models import SbomModel
from local.api_app.models.orm import SbomScan
from scanner.services import sbom_artifacts


class SbomModelTests(TestCase):
    def test_create_defaults(self):
        s = SbomModel.create({"project_id": "p1", "scan_name": "SB", "triggered_by": "u"})
        self.assertEqual(s["status"], "queued")
        self.assertEqual(s["severity_counts"],
                         {"critical": 0, "high": 0, "medium": 0, "low": 0, "negligible": 0})
        self.assertEqual(s["sbom_format"], "syft-json")

    def test_insert_findings_and_serialize_shape(self):
        s = SbomModel.create({"project_id": "p", "scan_name": "SB"})
        SbomModel.insert_findings([{
            "scan_id": s["id"], "package_name": "lodash", "package_version": "1.0.0",
            "package_type": "npm", "cve_id": "CVE-1", "severity": "High",
            "description": "x", "cvss": [{"type": "Primary", "version": "3.1",
            "vector": "v", "metrics": {"baseScore": 9.8}}], "fix_versions": ["1.0.1"],
        }])
        page = SbomModel.find_by_sbom_scan(s["id"], page=1, limit=10)
        f = page["findings"][0]
        self.assertEqual(f["package"], {"name": "lodash", "version": "1.0.0", "type": "npm"})
        self.assertEqual(f["severity"], "high")
        self.assertEqual(f["cvss_score"], 9.8)
        self.assertEqual(f["cvss"][0]["base_score"], 9.8)

    def test_insert_license_findings_and_find_by_risk(self):
        s = SbomModel.create({"project_id": "p", "scan_name": "SB"})
        SbomModel.insert_license_findings([{
            "scan_id": s["id"], "package_name": "pkg", "package_version": "1",
            "package_type": "npm", "license": {"id": "GPL", "risk_level": "high"},
            "decision": "deny", "locations": ["/x"],
        }])
        high = SbomModel.find_license_by_risk(s["id"], "high")
        self.assertEqual(high[0]["license"]["id"], "GPL")
        self.assertEqual(high[0]["decision"], "deny")

    def test_update_scan_fields_and_progress(self):
        s = SbomModel.create({"project_id": "p", "scan_name": "SB"})
        SbomModel.update_progress(s["id"], dependencies_scanned=5, vulnerabilities=2)
        self.assertEqual(SbomModel.find_by_id(s["id"])["dependencies_scanned"], 5)
        SbomModel.update_scan_fields(s["id"], {"sbom_artifact": "/tmp/sbom.json"})
        # no crash; field persisted (not in serialize output, but stored)

    def test_find_by_id_counts_distinct_affected_packages_not_cves(self):
        # 4 CVEs across 2 distinct packages (one package has 3 CVEs): the UI derives
        # "clean packages" from this, so it must be 2, not 4 (and never negative).
        s = SbomModel.create({"project_id": "p", "scan_name": "SB"})
        SbomModel.insert_findings([
            {"scan_id": s["id"], "package_name": "flask", "package_version": "0.12", "cve_id": "CVE-1"},
            {"scan_id": s["id"], "package_name": "flask", "package_version": "0.12", "cve_id": "CVE-2"},
            {"scan_id": s["id"], "package_name": "flask", "package_version": "0.12", "cve_id": "CVE-3"},
            {"scan_id": s["id"], "package_name": "pyyaml", "package_version": "3.12", "cve_id": "CVE-4"},
        ])
        self.assertEqual(SbomModel.find_by_id(s["id"])["affected_dependencies"], 2)
        self.assertEqual(SbomModel.find_by_id(SbomModel.create({"project_id": "p", "scan_name": "E"})["id"])["affected_dependencies"], 0)

    def test_delete_scan_removes_findings(self):
        s = SbomModel.create({"project_id": "p", "scan_name": "SB"})
        SbomModel.insert_findings([{"scan_id": s["id"], "package_name": "a"}])
        self.assertTrue(SbomModel.delete_scan(s["id"]))
        self.assertEqual(SbomModel.find_sbom_findings_all(s["id"]), [])

    def test_delete_scan_removes_output_directory(self):
        # SBOM/grype/grant reports and the cosign signature bundle are written to
        # output/<scan_id>/ by scanner/services/sbom_pipeline.py -- deleting the scan
        # must also remove that directory, or every deleted scan leaks its artifacts
        # on disk forever.
        s = SbomModel.create({"project_id": "p", "scan_name": "SB"})
        output_dir = Path("output") / s["id"]
        output_dir.mkdir(parents=True, exist_ok=True)
        (output_dir / "sbom-cyclonedx.json").write_text("{}")
        try:
            self.assertTrue(SbomModel.delete_scan(s["id"]))
            self.assertFalse(output_dir.exists())
        finally:
            shutil.rmtree(output_dir, ignore_errors=True)

    def test_delete_scan_removes_artifacts_from_the_data_directory(self):
        with tempfile.TemporaryDirectory() as data_dir, override_settings(DATA_DIR=Path(data_dir)):
            s = SbomModel.create({"project_id": "p", "scan_name": "SB"})
            artifacts = sbom_artifacts.output_dir(s["id"])
            artifacts.mkdir(parents=True)
            (artifacts / "sbom-cyclonedx.json").write_text("{}")
            self.assertTrue(SbomModel.delete_scan(s["id"]))
            self.assertFalse(artifacts.exists())

    def test_delete_scan_is_safe_when_output_directory_missing(self):
        s = SbomModel.create({"project_id": "p", "scan_name": "SB"})
        self.assertTrue(SbomModel.delete_scan(s["id"]))

    def test_sbom_signing_payload_is_json_serializable(self):
        # Regression: sbom_signing is a JSONField (default encoder). `verified_at`
        # must be an ISO string, not a raw datetime, or json.dumps raises TypeError
        # and the SBOM scan crashes after signing.
        s = SbomModel.create({"project_id": "p", "scan_name": "SB"})
        signing = {
            "sbom_signed": True,
            "verified": True,
            "bundle_file": "/tmp/sbom.bundle.json",
            "verified_at": datetime.now(timezone.utc).isoformat(),
            "signature_algorithm": "cosign",
        }
        SbomModel.update_scan_fields(s["id"], {"sbom_signing": signing})
        stored = SbomScan.objects.get(id=s["id"]).sbom_signing
        self.assertEqual(stored, signing)
        # A raw datetime is not JSON-serializable — guard against reintroduction.
        with self.assertRaises(TypeError):
            SbomModel.update_scan_fields(
                s["id"], {"sbom_signing": {"verified_at": datetime.now(timezone.utc)}}
            )
