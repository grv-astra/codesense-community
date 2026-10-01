import io, os, zipfile
from datetime import datetime, timezone
from unittest import mock

from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase, override_settings
from rest_framework.parsers import FormParser, JSONParser, MultiPartParser
from rest_framework.request import Request
from rest_framework.test import APIRequestFactory

from licenses.services import entitlements as ent
from local.api_app.models.orm import ScanEvent
from local.api_app.views import scan_views
from local.api_app.views.scan_views import ScanCreateView


def _multipart_request(url, data):
    """Build a DRF Request carrying multipart form/file data, bypassing the
    @require_permission auth wrapper entirely (tests call view.post.__wrapped__
    directly). Mirrors test_scan_views.py's helper of the same name."""
    factory = APIRequestFactory()
    django_request = factory.post(url, data=data, format="multipart")
    request = Request(django_request, parsers=[MultiPartParser(), FormParser(), JSONParser()])
    request.user = {"id": "tester"}
    return request


def _valid_zip_bytes():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("file.txt", "hello")
    return buf.getvalue()


@override_settings(CODESENSE_EDITION="community", ENTITLEMENTS_PUBLIC_KEY=None)
class ScanLimitGateTests(TestCase):
    def setUp(self):
        patcher = mock.patch.dict(os.environ, {}, clear=False)
        patcher.start()
        os.environ.pop("ENTITLEMENTS_PUBLIC_KEY", None)
        os.environ.pop("CODESENSE_EDITION", None)
        self.addCleanup(patcher.stop)
        ent.reload()
        self.addCleanup(ent.reload)

    def test_quota_helper_blocks_at_community_code_limit(self):
        now = datetime.now(timezone.utc)
        ScanEvent.objects.bulk_create(
            [ScanEvent(scan_type="code", completed_at=now) for _ in range(25)]
        )
        allowed, body, code = scan_views._enforce_scan_quota("code")
        self.assertFalse(allowed)
        self.assertEqual(code, 403)
        self.assertIn("edition", str(body).lower())

    def test_zip_size_helper_blocks_oversized(self):
        class _I:  # noqa: D401
            def __init__(self, n): self.file_size = n
        allowed, body, code = scan_views._enforce_codebase_size([_I(300 * 1024 * 1024)])
        self.assertFalse(allowed)
        self.assertEqual(code, 413)

    def test_helpers_pass_under_limit(self):
        self.assertTrue(scan_views._enforce_scan_quota("code")[0])
        self.assertTrue(scan_views._enforce_codebase_size([])[0])


@override_settings(CODESENSE_EDITION="community", ENTITLEMENTS_PUBLIC_KEY=None)
class ScanCreateViewEditionLimitEndToEndTests(TestCase):
    """End-to-end coverage (real HTTP-level requests against ScanCreateView,
    mirroring test_scan_views.py's _multipart_request + post.__wrapped__
    pattern) proving the edition-limit helpers are actually wired into the
    view, not just unit-correct in isolation."""

    def setUp(self):
        patcher = mock.patch.dict(os.environ, {}, clear=False)
        patcher.start()
        os.environ.pop("ENTITLEMENTS_PUBLIC_KEY", None)
        os.environ.pop("CODESENSE_EDITION", None)
        self.addCleanup(patcher.stop)
        ent.reload()
        self.addCleanup(ent.reload)

    # licenses.services.limits.can_start_scan is imported function-locally inside
    # _enforce_scan_quota (`from licenses.services import limits`), so patching
    # the name on local.api_app.views.scan_views would be a no-op -- the patch
    # has to target the source module that the function-local import resolves.
    @mock.patch("licenses.services.limits.can_start_scan", return_value=False)
    def test_quota_exceeded_blocks_scan_create_with_403(self, _mock_can_start):
        good_zip = SimpleUploadedFile("good.zip", _valid_zip_bytes(), content_type="application/zip")
        request = _multipart_request("/api/scans/create/", {
            "scan_name": "quota-blocked", "project_id": "p1", "zip_file": good_zip,
        })
        response = ScanCreateView.post.__wrapped__(ScanCreateView(), request)
        self.assertEqual(response.status_code, 403)
        body = response.content.decode().lower()
        self.assertTrue("edition" in body or "limit" in body)

    # A real 250MB+ zip is wasteful to construct in a test; instead mock the
    # helper itself to prove the CALL SITE in ScanCreateView.post honors its
    # (False, body, 413) result -- the helper's own oversized-detection logic
    # is already covered by test_zip_size_helper_blocks_oversized above.
    @mock.patch(
        "local.api_app.views.scan_views._enforce_codebase_size",
        return_value=(False, {"detail": "too big"}, 413),
    )
    def test_oversized_codebase_blocks_scan_create_with_413(self, _mock_enforce_size):
        good_zip = SimpleUploadedFile("good.zip", _valid_zip_bytes(), content_type="application/zip")
        request = _multipart_request("/api/scans/create/", {
            "scan_name": "oversized-blocked", "project_id": "p1", "zip_file": good_zip,
        })
        response = ScanCreateView.post.__wrapped__(ScanCreateView(), request)
        self.assertEqual(response.status_code, 413)
