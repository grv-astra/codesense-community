from django.test import TestCase
from rest_framework.request import Request
from rest_framework.test import APIRequestFactory

from local.auth_app.views.auth_views import GetPermissionsView


def _request(role):
    # Tests call the view method past the auth decorator, so request.user is set by hand.
    request = Request(APIRequestFactory().get("/api/auth/permissions/x/"))
    request.user = {"id": "tester", "email": "tester@x.com", "role": role}
    return request


class GetPermissionsViewAccessTests(TestCase):
    """Reading another role's permission matrix is admin-only; your own role is always readable."""

    def _get(self, caller_role, requested_role):
        return GetPermissionsView.get.__wrapped__(GetPermissionsView(), _request(caller_role), requested_role)

    def test_admin_can_read_every_role(self):
        for role in ("admin", "manager", "user"):
            self.assertEqual(self._get("admin", role).status_code, 200, role)

    def test_user_can_read_only_their_own_role(self):
        self.assertEqual(self._get("user", "user").status_code, 200)
        self.assertEqual(self._get("user", "admin").status_code, 403)
        self.assertEqual(self._get("user", "manager").status_code, 403)

    def test_manager_cannot_read_other_roles(self):
        self.assertEqual(self._get("manager", "manager").status_code, 200)
        self.assertEqual(self._get("manager", "user").status_code, 403)

    def test_role_comparison_ignores_case(self):
        self.assertEqual(self._get("User", "user").status_code, 200)
        self.assertEqual(self._get("Admin", "manager").status_code, 200)
