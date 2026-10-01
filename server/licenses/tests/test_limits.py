import os
from datetime import datetime, timedelta, timezone
from unittest import mock

from django.test import TestCase, override_settings

from local.api_app.models.orm import ScanEvent, Project
from licenses.services import entitlements as ent
from licenses.services import limits


def _mk_project(deleted=False):
    return Project.objects.create(
        name="p", created_at=datetime.now(timezone.utc), deleted=deleted
    )


@override_settings(CODESENSE_EDITION="community", ENTITLEMENTS_PUBLIC_KEY=None)
class LimitsTests(TestCase):
    def setUp(self):
        patcher = mock.patch.dict(os.environ, {}, clear=False)
        patcher.start()
        os.environ.pop("CODESENSE_EDITION", None)
        os.environ.pop("ENTITLEMENTS_PUBLIC_KEY", None)
        self.addCleanup(patcher.stop)
        ent.reload()
        self.addCleanup(ent.reload)

    def test_scans_in_window_counts_only_recent_rows_of_that_type(self):
        now = datetime.now(timezone.utc)
        ScanEvent.objects.create(scan_type="code", completed_at=now)
        ScanEvent.objects.create(scan_type="code", completed_at=now - timedelta(days=40))
        ScanEvent.objects.create(scan_type="sbom", completed_at=now)
        self.assertEqual(limits.scans_in_window("code"), 1)
        self.assertEqual(limits.scans_in_window("sbom"), 1)

    def test_record_scan_appends_a_row(self):
        limits.record_scan("code")
        self.assertEqual(ScanEvent.objects.filter(scan_type="code").count(), 1)

    def test_can_start_scan_boundary(self):
        now = datetime.now(timezone.utc)
        ScanEvent.objects.bulk_create(
            [ScanEvent(scan_type="code", completed_at=now) for _ in range(24)]
        )
        self.assertTrue(limits.can_start_scan("code"))     # 24 < 25
        ScanEvent.objects.create(scan_type="code", completed_at=now)
        self.assertFalse(limits.can_start_scan("code"))    # 25 >= 25

    def test_can_create_project_boundary(self):
        self.assertTrue(limits.can_create_project())
        _mk_project()
        self.assertFalse(limits.can_create_project())
        _mk_project(deleted=True)   # soft-deleted doesn't count
        self.assertFalse(limits.can_create_project())

    def test_codebase_size_ok(self):
        self.assertTrue(limits.codebase_size_ok(200 * 1024 * 1024))
        self.assertFalse(limits.codebase_size_ok(300 * 1024 * 1024))

    @override_settings(CODESENSE_EDITION="enterprise")
    def test_enterprise_unlimited(self):
        ent.reload()
        now = datetime.now(timezone.utc)
        ScanEvent.objects.bulk_create(
            [ScanEvent(scan_type="code", completed_at=now) for _ in range(1000)]
        )
        self.assertTrue(limits.can_start_scan("code"))
        self.assertTrue(limits.codebase_size_ok(10**12))

    @override_settings(CODESENSE_EDITION="enterprise")
    def test_enterprise_unlimited_project_and_seat(self):
        ent.reload()
        now = datetime.now(timezone.utc)
        for i in range(50):
            Project.objects.create(name=f"p{i}", created_at=now)
        self.assertTrue(limits.can_create_project())
        from local.auth_app.models.orm import User
        for i in range(50):
            User.objects.create(email=f"u{i}@x.com", password="x",
                                created_at=now, updated_at=now)
        self.assertTrue(limits.can_add_user())

    def test_can_add_user_boundary(self):
        from local.auth_app.models.orm import User
        now = datetime.now(timezone.utc)
        for i in range(2):
            User.objects.create(email=f"u{i}@x.com", password="x",
                                created_at=now, updated_at=now)
        self.assertTrue(limits.can_add_user())          # 2 < 3
        User.objects.create(email="u2@x.com", password="x",
                            created_at=now, updated_at=now)
        self.assertFalse(limits.can_add_user())         # 3 >= 3
        User.objects.create(email="u3@x.com", password="x",
                            created_at=now, updated_at=now, deleted=True)
        self.assertFalse(limits.can_add_user())         # soft-deleted doesn't count

    def test_can_start_scan_sbom_branch(self):
        now = datetime.now(timezone.utc)
        ScanEvent.objects.bulk_create(
            [ScanEvent(scan_type="sbom", completed_at=now) for _ in range(25)]
        )
        self.assertFalse(limits.can_start_scan("sbom"))
        self.assertTrue(limits.can_start_scan("code"))   # independent per type

    def test_unknown_scan_type_raises(self):
        with self.assertRaises(ValueError):
            limits.can_start_scan("container")

    def test_usage_snapshot_shape(self):
        now = datetime.now(timezone.utc)
        Project.objects.create(name="p", created_at=now)
        ScanEvent.objects.create(scan_type="code", completed_at=now)
        snap = limits.usage_snapshot()
        self.assertEqual(set(snap), {"projects", "code_scans_in_window",
                                     "sbom_scans_in_window", "seats"})
        self.assertEqual(snap["projects"], 1)
        self.assertEqual(snap["code_scans_in_window"], 1)

    def test_codebase_size_exact_boundary(self):
        self.assertTrue(limits.codebase_size_ok(250 * 1024 * 1024))       # == limit, <=
        self.assertFalse(limits.codebase_size_ok(250 * 1024 * 1024 + 1))
