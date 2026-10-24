import csv
import io
import json
import tempfile
import zipfile
from pathlib import Path
from unittest import mock

from django.test import TestCase, override_settings
from django.urls import reverse
from rest_framework.request import Request
from rest_framework.test import APIRequestFactory

from local.api_app.models.sbom_models import SbomModel
from local.api_app.views.sbom_report_views import SbomDependenciesView, SbomDownloadView, SbomExportView
from scanner.services import sbom_artifacts, sbom_inventory


def _get(view, scan_id, params=None, **kwargs):
    # Tests call the view method past the permission decorator.
    request = Request(APIRequestFactory().get("/x/", params or {}))
    request.user = {"id": "tester", "email": "tester@x.com", "role": "admin"}
    return view.get.__wrapped__(view(), request, scan_id, **kwargs)


def _finding(scan_id, name, version, cve, severity, **extra):
    return {"scan_id": scan_id, "package_name": name, "package_version": version, "package_type": "npm",
            "cve_id": cve, "severity": severity, "description": f"{cve} in {name}",
            "cvss": [{"metrics": {"baseScore": 7.5}}], "fix_versions": ["9.9.9"], **extra}


def _syft(*packages):
    return {"artifacts": [{"name": n, "version": v, "type": t} for n, v, t in packages]}


class SbomReportTestCase(TestCase):
    def setUp(self):
        data_dir = tempfile.TemporaryDirectory()
        self.addCleanup(data_dir.cleanup)
        override = override_settings(DATA_DIR=Path(data_dir.name))
        override.enable()
        self.addCleanup(override.disable)
        self.scan = SbomModel.create({"project_id": "p", "scan_name": "SB"})
        self.scan_id = self.scan["id"]

    def write_sbom(self, document, name="sbom-cyclonedx.json"):
        directory = sbom_artifacts.output_dir(self.scan_id)
        directory.mkdir(parents=True, exist_ok=True)
        (directory / name).write_text(json.dumps(document), encoding="utf-8")
        return directory


class InventoryReaderTests(SbomReportTestCase):
    def read(self, document):
        directory = self.write_sbom(document)
        return sbom_inventory.read_inventory(directory / "sbom-cyclonedx.json")

    def test_syft_json(self):
        self.assertEqual(self.read(_syft(("lodash", "4.17.15", "npm"))),
                         [{"name": "lodash", "version": "4.17.15", "type": "npm"}])

    def test_cyclonedx_takes_the_ecosystem_from_the_purl(self):
        found = self.read({"bomFormat": "CycloneDX", "components": [
            {"name": "requests", "version": "2.0", "type": "library", "purl": "pkg:pypi/requests@2.0"},
            {"name": "no-purl", "version": "1", "type": "library"}]})
        self.assertEqual([p["type"] for p in found], ["pypi", "library"])

    def test_spdx_json(self):
        found = self.read({"spdxVersion": "SPDX-2.3", "packages": [
            {"name": "left-pad", "versionInfo": "1.3.0", "externalRefs": [
                {"referenceType": "purl", "referenceLocator": "pkg:npm/left-pad@1.3.0"}]}]})
        self.assertEqual(found, [{"name": "left-pad", "version": "1.3.0", "type": "npm"}])

    def test_unknown_document_is_empty(self):
        self.assertEqual(self.read({"hello": "world"}), [])

    def test_worst_severity_and_summary(self):
        self.assertEqual(sbom_inventory.worst_severity(["low", "high", "medium"]), "high")
        self.assertEqual(sbom_inventory.worst_severity([None]), "unknown")
        self.assertEqual(sbom_inventory.risk_summary({}), "No known vulnerabilities.")
        self.assertEqual(sbom_inventory.risk_summary({"high": 2, "critical": 1}),
                         "3 vulnerabilities (1 critical, 2 high)")
        self.assertEqual(sbom_inventory.risk_summary({"low": 1}), "1 vulnerability (1 low)")


class DependenciesViewTests(SbomReportTestCase):
    def setUp(self):
        super().setUp()
        self.write_sbom(_syft(("express", "4.18.2", "npm"), ("lodash", "4.17.15", "npm"),
                              ("axios", "0.21.1", "npm"), ("zlib", "1.0", "npm")))
        SbomModel.insert_findings([
            _finding(self.scan_id, "lodash", "4.17.15", "CVE-1", "critical"),
            _finding(self.scan_id, "lodash", "4.17.15", "CVE-2", "high"),
            _finding(self.scan_id, "axios", "0.21.1", "CVE-3", "low"),
        ])
        SbomModel.insert_license_findings([{
            "scan_id": self.scan_id, "package_name": "lodash", "package_version": "4.17.15",
            "package_type": "npm", "license": {"id": "MIT"}, "decision": "allow", "locations": []}])

    def test_lists_every_package_riskiest_first_with_real_data(self):
        body = _get(SbomDependenciesView, self.scan_id).data
        self.assertTrue(body["inventory_complete"])
        rows = body["dependencies"]
        self.assertEqual([r["package_name"] for r in rows], ["lodash", "axios", "express", "zlib"])
        lodash = rows[0]
        self.assertEqual(lodash["risk_rating"], "critical")
        self.assertEqual(lodash["risk_summary"], "2 vulnerabilities (1 critical, 1 high)")
        self.assertEqual(lodash["vulnerabilities"], 2)
        self.assertEqual(lodash["licenses"], ["MIT"])
        self.assertEqual(rows[2]["risk_rating"], "none")
        self.assertEqual(rows[2]["risk_summary"], "No known vulnerabilities.")
        self.assertEqual(body["pagination"]["total"], 4)

    def test_pagination_and_search(self):
        page = _get(SbomDependenciesView, self.scan_id, {"page": 2, "limit": 3}).data
        self.assertEqual([r["package_name"] for r in page["dependencies"]], ["zlib"])
        self.assertEqual(page["pagination"], {"total": 4, "page": 2, "limit": 3, "pages": 2})
        found = _get(SbomDependenciesView, self.scan_id, {"search": "AXI"}).data
        self.assertEqual([r["package_name"] for r in found["dependencies"]], ["axios"])
        by_license = _get(SbomDependenciesView, self.scan_id, {"search": "mit"}).data
        self.assertEqual([r["package_name"] for r in by_license["dependencies"]], ["lodash"])

    def test_falls_back_to_packages_with_findings_when_the_sbom_file_is_gone(self):
        (sbom_artifacts.output_dir(self.scan_id) / "sbom-cyclonedx.json").unlink()
        body = _get(SbomDependenciesView, self.scan_id).data
        self.assertFalse(body["inventory_complete"])
        self.assertEqual([r["package_name"] for r in body["dependencies"]], ["lodash", "axios"])

    def test_unreadable_sbom_file_also_falls_back(self):
        (sbom_artifacts.output_dir(self.scan_id) / "sbom-cyclonedx.json").write_text("{not json")
        self.assertFalse(_get(SbomDependenciesView, self.scan_id).data["inventory_complete"])

    def test_unknown_scan_is_404_and_bad_paging_is_400(self):
        self.assertEqual(_get(SbomDependenciesView, "nope").status_code, 404)
        self.assertEqual(_get(SbomDependenciesView, self.scan_id, {"page": "x"}).status_code, 400)


class ExportViewTests(SbomReportTestCase):
    def setUp(self):
        super().setUp()
        SbomModel.insert_findings([
            _finding(self.scan_id, "lodash", "4.17.15", "CVE-1", "high"),
            _finding(self.scan_id, "evil", "1.0", "CVE-2", "low", description='=HYPERLINK("http://x","y")'),
        ])
        SbomModel.insert_license_findings([{
            "scan_id": self.scan_id, "package_name": "lodash", "package_version": "4.17.15",
            "package_type": "npm", "decision": "deny", "locations": ["/a", "/b"],
            "license": {"id": "GPL-3.0", "risk_category": "Strong Copyleft", "risk_level": "high",
                        "osi_approved": True, "reference": "https://spdx.org/licenses/GPL-3.0.html"}}])

    def export(self, **params):
        return _get(SbomExportView, self.scan_id, params)

    def test_vulnerabilities_csv(self):
        response = self.export(kind="vulnerabilities", file_format="csv")
        self.assertEqual(response.status_code, 200)
        self.assertIn(f"sbom_{self.scan_id}_vulnerabilities.csv", response["Content-Disposition"])
        text = response.content.decode("utf-8")
        self.assertTrue(text.startswith("\ufeff"))
        rows = list(csv.reader(io.StringIO(text.lstrip("\ufeff"))))
        self.assertEqual(rows[0][:5], ["Package", "Version", "Type", "CVE / Advisory", "Severity"])
        self.assertEqual(len(rows), 3)
        by_package = {r[0]: r for r in rows[1:]}
        self.assertEqual(by_package["lodash"][3:6], ["CVE-1", "high", "7.5"])
        self.assertEqual(by_package["lodash"][7], "9.9.9")

    def test_csv_text_that_looks_like_a_formula_is_quoted(self):
        rows = list(csv.reader(io.StringIO(self.export(kind="vulnerabilities", file_format="csv")
                                           .content.decode("utf-8").lstrip("\ufeff"))))
        description = {r[0]: r[6] for r in rows[1:]}["evil"]
        self.assertTrue(description.startswith("'="), description)

    def test_vulnerabilities_json(self):
        response = self.export(kind="vulnerabilities", file_format="json")
        self.assertEqual(response["Content-Type"], "application/json")
        document = json.loads(response.content)
        self.assertEqual(document["scan_id"], self.scan_id)
        self.assertEqual(document["count"], 2)
        self.assertEqual({f["cve_id"] for f in document["vulnerabilities"]}, {"CVE-1", "CVE-2"})

    def test_licenses_csv_and_json(self):
        rows = list(csv.reader(io.StringIO(self.export(kind="licenses", file_format="csv")
                                           .content.decode("utf-8").lstrip("\ufeff"))))
        self.assertEqual(rows[0][:4], ["Package", "Version", "Type", "License"])
        self.assertEqual(rows[1][:4], ["lodash", "4.17.15", "npm", "GPL-3.0"])
        self.assertEqual(rows[1][7:9], ["deny", "/a; /b"])
        document = json.loads(self.export(kind="licenses", file_format="json").content)
        self.assertEqual(document["licenses"][0]["license"]["id"], "GPL-3.0")

    def test_a_scan_with_no_findings_exports_an_empty_report(self):
        other = SbomModel.create({"project_id": "p", "scan_name": "empty"})["id"]
        response = _get(SbomExportView, other, {"kind": "licenses", "file_format": "json"})
        self.assertEqual(json.loads(response.content)["count"], 0)

    def test_bad_parameters_and_unknown_scan(self):
        self.assertEqual(self.export(kind="x", file_format="csv").status_code, 400)
        self.assertEqual(self.export(kind="licenses", file_format="xml").status_code, 400)
        self.assertEqual(_get(SbomExportView, "nope").status_code, 404)

    def test_routes_resolve(self):
        self.assertEqual(reverse("sbom_export_by_scan", kwargs={"scan_id": "a"}), "/api/findings/sbom/export/a/")
        self.assertEqual(reverse("sbom_dependencies_by_scan", kwargs={"scan_id": "a"}),
                         "/api/findings/sbom/dependencies/a/")
        self.assertEqual(reverse("sbom_download_by_scan", kwargs={"scan_id": "a", "kind": "signed"}),
                         "/api/findings/sbom/download/a/signed/")


class DownloadViewTests(SbomReportTestCase):
    def sign(self):
        directory = self.write_sbom(_syft(("lodash", "4.17.15", "npm")))
        (directory / "sbom.bundle.json").write_text('{"bundle": true}')
        SbomModel.update_scan_fields(self.scan_id, {"sbom_signing": {
            "sbom_signed": True, "verified": True, "bundle_file": str(directory / "sbom.bundle.json"),
            "verified_at": "2026-10-22T10:00:00+00:00", "signature_algorithm": "cosign"}})
        return directory

    def test_sbom_download_returns_the_stored_file(self):
        self.write_sbom(_syft(("lodash", "4.17.15", "npm")))
        response = _get(SbomDownloadView, self.scan_id, kind="sbom")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(json.loads(response.content)["artifacts"][0]["name"], "lodash")
        self.assertIn("attachment", response["Content-Disposition"])

    def test_uploaded_sboms_are_found_by_their_normalized_name(self):
        self.write_sbom(_syft(("a", "1", "npm")), name="normalized-sbom.json")
        self.assertEqual(_get(SbomDownloadView, self.scan_id, kind="sbom").status_code, 200)

    def test_missing_sbom_file_is_a_clear_404(self):
        response = _get(SbomDownloadView, self.scan_id, kind="sbom")
        self.assertEqual(response.status_code, 404)
        self.assertIn("no longer available", response.data["error"])

    def test_signed_download_is_a_zip_with_sbom_bundle_key_and_instructions(self):
        directory = self.sign()
        key = directory / "cosign.pub"
        key.write_text("PUBLIC KEY")
        with mock.patch("local.api_app.views.sbom_report_views.cosign_paths", return_value=("k", str(key), "c")):
            response = _get(SbomDownloadView, self.scan_id, kind="signed")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "application/zip")
        with zipfile.ZipFile(io.BytesIO(response.content)) as zf:
            self.assertEqual(sorted(zf.namelist()),
                             ["VERIFY.txt", "cosign.pub", "sbom-cyclonedx.json", "sbom.bundle.json"])
            self.assertEqual(zf.read("cosign.pub"), b"PUBLIC KEY")
            self.assertIn("cosign verify-blob sbom-cyclonedx.json --key cosign.pub --bundle sbom.bundle.json",
                          zf.read("VERIFY.txt").decode())

    def test_signed_download_without_a_signature_is_404(self):
        self.write_sbom(_syft(("lodash", "4.17.15", "npm")))
        response = _get(SbomDownloadView, self.scan_id, kind="signed")
        self.assertEqual(response.status_code, 404)
        self.assertIn("not signed", response.data["error"])

    def test_signed_record_without_its_bundle_file_is_404(self):
        directory = self.sign()
        (directory / "sbom.bundle.json").unlink()
        self.assertEqual(_get(SbomDownloadView, self.scan_id, kind="signed").status_code, 404)

    def test_unknown_kind_and_unknown_scan(self):
        self.write_sbom(_syft(("lodash", "4.17.15", "npm")))
        self.assertEqual(_get(SbomDownloadView, self.scan_id, kind="../../etc/passwd").status_code, 400)
        self.assertEqual(_get(SbomDownloadView, "nope", kind="sbom").status_code, 404)


class SigningStatusTests(SbomReportTestCase):
    def test_scan_api_shows_the_signing_result_without_server_paths(self):
        SbomModel.update_scan_fields(self.scan_id, {"sbom_signing": {
            "sbom_signed": True, "verified": True, "bundle_file": "C:\\secret\\place\\sbom.bundle.json",
            "verified_at": "2026-10-22T10:00:00+00:00", "signature_algorithm": "cosign"}})
        signing = SbomModel.find_by_id(self.scan_id)["signing"]
        self.assertEqual(signing, {"signed": True, "verified": True, "verified_at": "2026-10-22T10:00:00+00:00",
                                   "algorithm": "cosign", "skipped_reason": None})
        self.assertNotIn("secret", json.dumps(SbomModel.find_by_id(self.scan_id)))

    def test_edition_without_signing_reports_why(self):
        SbomModel.update_scan_fields(self.scan_id, {"sbom_signing": {
            "sbom_signed": False, "verified": False, "bundle_file": None, "verified_at": None,
            "signature_algorithm": "cosign", "skipped_reason": "edition"}})
        signing = SbomModel.find_by_id(self.scan_id)["signing"]
        self.assertFalse(signing["signed"])
        self.assertEqual(signing["skipped_reason"], "edition")

    def test_scan_with_no_signing_record_has_none(self):
        self.assertIsNone(SbomModel.find_by_id(self.scan_id)["signing"])


@override_settings(SECRET_KEY="report-api-test-secret")
class ThroughTheHttpStackTests(SbomReportTestCase):
    """The same endpoints through URL routing, auth and DRF content negotiation, which calling the
    view methods directly skips. (`?format=csv` answered 404 there: DRF reserves `format`.)"""

    def setUp(self):
        super().setUp()
        for target in ("local.auth_app.permissions.decorators.verify_payload_user",):
            patcher = mock.patch(target, return_value=None)
            patcher.start()
            self.addCleanup(patcher.stop)
        SbomModel.insert_findings([_finding(self.scan_id, "lodash", "4.17.15", "CVE-1", "high")])
        self.write_sbom(_syft(("lodash", "4.17.15", "npm"), ("express", "4.18.2", "npm")))

    def get(self, path):
        from local.auth_app.utils.jwt import generate_token
        token = generate_token({"id": "u1", "role": "admin"})
        return self.client.get(path, HTTP_AUTHORIZATION=f"Bearer {token}")

    def test_csv_and_json_exports(self):
        csv_response = self.get(f"/api/findings/sbom/export/{self.scan_id}/?kind=vulnerabilities&file_format=csv")
        self.assertEqual(csv_response.status_code, 200)
        self.assertTrue(csv_response["Content-Type"].startswith("text/csv"))
        self.assertIn("CVE-1", csv_response.content.decode("utf-8"))
        json_response = self.get(f"/api/findings/sbom/export/{self.scan_id}/?kind=licenses&file_format=json")
        self.assertEqual(json_response.status_code, 200)
        self.assertEqual(json.loads(json_response.content)["count"], 0)

    def test_dependencies_and_sbom_download(self):
        deps = self.get(f"/api/findings/sbom/dependencies/{self.scan_id}/")
        self.assertEqual(deps.status_code, 200)
        self.assertEqual([r["package_name"] for r in deps.json()["dependencies"]], ["lodash", "express"])
        sbom = self.get(f"/api/findings/sbom/download/{self.scan_id}/sbom/")
        self.assertEqual(sbom.status_code, 200)

    def test_requires_a_login(self):
        self.assertEqual(self.client.get(f"/api/findings/sbom/dependencies/{self.scan_id}/").status_code, 401)
        self.assertEqual(self.client.get(f"/api/findings/sbom/export/{self.scan_id}/").status_code, 401)
