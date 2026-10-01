import os
from datetime import datetime, timezone
from unittest import mock

from django.test import TestCase, override_settings
from rest_framework.exceptions import ValidationError

from local.auth_app.services.setup import is_setup_needed, create_initial_admin
from local.auth_app.models.permission_model import PermissionModel
from local.auth_app.models.orm import User


class SetupServiceTests(TestCase):
    def test_setup_needed_when_no_admin(self):
        self.assertTrue(is_setup_needed())

    def test_create_initial_admin_rejects_weak_password(self):
        with self.assertRaises(ValidationError):
            create_initial_admin("weak@x.com", "weak", "Weak Admin")
        # no admin should have been created
        self.assertTrue(is_setup_needed())

    def test_create_initial_admin_seeds_admin_and_blocks_second_run(self):
        admin = create_initial_admin("root@x.com", "Str0ng!Pass1", "Root")
        self.assertEqual(admin["role"], "admin")  # roles are stored lowercase
        self.assertFalse(is_setup_needed())
        # default role permissions seeded
        self.assertEqual(PermissionModel.get_permissions_for_role("user"),
                         {k: False for k in PermissionModel.get_all_permission_keys()})
        with self.assertRaises(RuntimeError):
            create_initial_admin("second@x.com", "Str0ng!Pass1", "Second")

    @override_settings(CODESENSE_EDITION="community", ENTITLEMENTS_PUBLIC_KEY=None)
    def test_create_initial_admin_ignores_seat_quota_even_when_exhausted(self):
        """CRITICAL invariant: the first-run wizard must never be blocked by the seat
        gate, or a fresh Community install with 3+ pre-existing users (e.g. restored
        from a backup) could never create its first admin and be permanently locked
        out. create_initial_admin() uses a separate code path from the gated
        UserModuleView.post (see user_views.py) -- this pins that behavior."""
        patcher = mock.patch.dict(os.environ, {}, clear=False)
        patcher.start()
        os.environ.pop("CODESENSE_EDITION", None)
        os.environ.pop("ENTITLEMENTS_PUBLIC_KEY", None)
        self.addCleanup(patcher.stop)

        from licenses.services import entitlements as ent
        ent.reload()
        self.addCleanup(ent.reload)

        now = datetime.now(timezone.utc)
        for i in range(3):
            User.objects.create(email=f"seat{i}@x.com", password="x",
                                created_at=now, updated_at=now)

        admin = create_initial_admin("root@x.com", "Str0ng!Pass1", "Root")
        self.assertEqual(admin["role"], "admin")
        self.assertFalse(is_setup_needed())
