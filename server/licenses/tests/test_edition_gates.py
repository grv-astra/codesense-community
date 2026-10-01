import os
from datetime import datetime, timezone
from unittest import mock

from django.test import TestCase, override_settings
from rest_framework.parsers import FormParser, JSONParser, MultiPartParser
from rest_framework.request import Request
from rest_framework.test import APIRequestFactory

from licenses.services import entitlements as ent
from local.api_app.models.orm import Project
from local.auth_app.models.orm import User


def _json_request(url, data, user=None):
    """Build a DRF Request carrying JSON data, bypassing the auth decorator
    entirely (tests call view.post.__wrapped__ directly, mirroring
    test_scan_views.py's _json_request helper) -- request.user must be set
    manually since the decorator normally does that."""
    factory = APIRequestFactory()
    django_request = factory.post(url, data=data, format="json")
    request = Request(django_request, parsers=[JSONParser(), FormParser(), MultiPartParser()])
    request.user = user if user is not None else {"id": "tester", "email": "tester@x.com", "role": "admin"}
    return request


@override_settings(CODESENSE_EDITION="community", ENTITLEMENTS_PUBLIC_KEY=None)
class ProjectAndSeatQuotaTests(TestCase):
    def setUp(self):
        patcher = mock.patch.dict(os.environ, {}, clear=False)
        patcher.start()
        os.environ.pop("CODESENSE_EDITION", None)
        os.environ.pop("ENTITLEMENTS_PUBLIC_KEY", None)
        self.addCleanup(patcher.stop)
        ent.reload()
        self.addCleanup(ent.reload)

    def test_project_create_blocked_at_limit(self):
        from licenses.services import limits
        Project.objects.create(name="p1", created_at=datetime.now(timezone.utc))
        self.assertFalse(limits.can_create_project())

    def test_seat_create_blocked_at_limit(self):
        from licenses.services import limits
        now = datetime.now(timezone.utc)
        for i in range(3):
            User.objects.create(email=f"u{i}@x.com", password="x",
                                created_at=now, updated_at=now)
        self.assertFalse(limits.can_add_user())


@override_settings(CODESENSE_EDITION="community", ENTITLEMENTS_PUBLIC_KEY=None)
class ProjectCreateViewQuotaGateTests(TestCase):
    """End-to-end proof that ProjectListCreateView.post actually 403s at the
    edition's project quota (Community = 1 project)."""

    def setUp(self):
        patcher = mock.patch.dict(os.environ, {}, clear=False)
        patcher.start()
        os.environ.pop("CODESENSE_EDITION", None)
        os.environ.pop("ENTITLEMENTS_PUBLIC_KEY", None)
        self.addCleanup(patcher.stop)
        ent.reload()
        self.addCleanup(ent.reload)

    def test_second_project_blocked_at_community_limit(self):
        from local.api_app.views.project_views import ProjectListCreateView
        Project.objects.create(name="existing", created_at=datetime.now(timezone.utc))
        request = _json_request(
            "/api/projects/",
            {"name": "second", "preset": "default", "description": ""},
        )
        response = ProjectListCreateView.post.__wrapped__(ProjectListCreateView(), request)
        self.assertEqual(response.status_code, 403)
        self.assertEqual(Project.objects.filter(deleted=False).count(), 1)


@override_settings(CODESENSE_EDITION="community", ENTITLEMENTS_PUBLIC_KEY=None)
class UserCreateViewSeatQuotaGateTests(TestCase):
    """End-to-end proof that UserModuleView.post actually 403s at the
    edition's seat quota (Community = 3 seats), and that the very first user
    created on a fresh install is NOT blocked (the setup wizard's own path
    never touches this view, but this proves the boundary directly too)."""

    def setUp(self):
        patcher = mock.patch.dict(os.environ, {}, clear=False)
        patcher.start()
        os.environ.pop("CODESENSE_EDITION", None)
        os.environ.pop("ENTITLEMENTS_PUBLIC_KEY", None)
        self.addCleanup(patcher.stop)
        ent.reload()
        self.addCleanup(ent.reload)

    def _user_request(self, data):
        return _json_request("/api/users/", data)

    def test_fourth_user_blocked_at_community_limit(self):
        from local.auth_app.views.user_views import UserModuleView
        now = datetime.now(timezone.utc)
        for i in range(3):
            User.objects.create(email=f"seat{i}@x.com", password="x",
                                created_at=now, updated_at=now)
        request = self._user_request({
            "email": "seat4@x.com", "password": "Str0ng!Pass0rd9",
            "name": "Fourth Seat", "company": "Acme", "role": "user",
        })
        response = UserModuleView.post.__wrapped__(UserModuleView(), request)
        self.assertEqual(response.status_code, 403)
        self.assertFalse(User.objects.filter(email="seat4@x.com").exists())

    def test_user_create_view_not_blocked_when_no_users_exist_yet(self):
        """UserModuleView.post's own lower boundary -- 0 existing users doesn't
        trip the seat gate. NOT a test of the setup wizard (see test_setup.py
        for that); the wizard uses a fully separate code path
        (create_initial_admin -> UserModel.create_user) that never reaches
        this view."""
        from local.auth_app.views.user_views import UserModuleView
        self.assertEqual(User.objects.filter(deleted=False).count(), 0)
        request = self._user_request({
            "email": "first@x.com", "password": "Str0ng!Pass0rd9",
            "name": "First User", "company": "Acme", "role": "user",
        })
        response = UserModuleView.post.__wrapped__(UserModuleView(), request)
        self.assertEqual(response.status_code, 201)
        self.assertTrue(User.objects.filter(email="first@x.com").exists())
