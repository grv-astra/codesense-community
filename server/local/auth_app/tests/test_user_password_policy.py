from unittest import mock

from django.test import TestCase
from rest_framework.parsers import FormParser, JSONParser, MultiPartParser
from rest_framework.request import Request
from rest_framework.test import APIRequestFactory

from local.auth_app.models.orm import User
from local.auth_app.models.user_model import UserModel
from local.auth_app.utils.password import hash_password, verify_password
from local.auth_app.views.user_views import UserModuleView


def _patch_request(data):
    # Tests call the view method past the auth decorator, so request.user is set by hand.
    django_request = APIRequestFactory().patch("/api/users/x/", data=data, format="json")
    request = Request(django_request, parsers=[JSONParser(), FormParser(), MultiPartParser()])
    request.user = {"id": "tester", "email": "tester@x.com", "role": "admin"}
    return request


class UserEditPasswordPolicyTests(TestCase):
    """Editing a user must enforce the same password policy as creating one."""

    def setUp(self):
        # register_user writes the shared account-integrity registry; keep it out of the test.
        patcher = mock.patch("local.auth_app.views.user_views.register_user")
        patcher.start()
        self.addCleanup(patcher.stop)
        created = UserModel.create_user(
            email="edit@x.com", hashed_password=hash_password("Str0ng!Pass0rd9"),
            name="Edit Me", company="Acme", role="user",
        )
        self.user_id = created["id"]

    def _patch(self, data):
        return UserModuleView.patch.__wrapped__(UserModuleView(), _patch_request(data), self.user_id)

    def test_weak_password_is_rejected_and_not_stored(self):
        for weak, reason in (("abc", "at least 8"), ("alllowercase1!", "uppercase"),
                             ("NoDigitsHere!", "digit"), ("NoSpecial123", "special")):
            response = self._patch({"password": weak})
            self.assertEqual(response.status_code, 400, weak)
            self.assertIn(reason, response.data["detail"], weak)
        stored = User.objects.get(id=self.user_id).password
        self.assertTrue(verify_password("Str0ng!Pass0rd9", stored))

    def test_strong_password_is_accepted_and_hashed(self):
        response = self._patch({"password": "An0ther!Pass0rd"})
        self.assertEqual(response.status_code, 202)
        stored = User.objects.get(id=self.user_id).password
        self.assertNotEqual(stored, "An0ther!Pass0rd")
        self.assertTrue(verify_password("An0ther!Pass0rd", stored))

    def test_edit_without_password_leaves_it_alone(self):
        response = self._patch({"name": "Renamed"})
        self.assertEqual(response.status_code, 202)
        stored = User.objects.get(id=self.user_id).password
        self.assertTrue(verify_password("Str0ng!Pass0rd9", stored))
