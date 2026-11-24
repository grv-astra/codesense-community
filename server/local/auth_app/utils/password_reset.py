"""Offline password reset for an existing account (used by ``codesense-server reset-password``).

There is no "forgot password" flow in the desktop app and the frozen backend ships without
manage.py, so a locked-out admin needs a supported way back in. This writes the new bcrypt
hash exactly like the users API does and, if the account is tracked in the account-integrity
registry, refreshes that entry too -- otherwise the next sign-in fails with "protected
account details were modified locally".
"""
from rest_framework.exceptions import ValidationError

from local.auth_app.models.orm import User
from local.auth_app.models.user_model import UserModel
from local.auth_app.utils import account_integrity
from local.auth_app.utils.password import hash_password, validate_strong_password


class ResetError(Exception):
    """A reset that cannot proceed; the message is safe to show the operator."""


def _policy_problem(password):
    try:
        validate_strong_password(password)
    except ValidationError as exc:
        detail = exc.detail
        first = detail[0] if isinstance(detail, (list, tuple)) and detail else detail
        return str(first)
    return None


def reset_password(email, new_password):
    """Set ``new_password`` for the active account with ``email``.

    Returns ``{"email", "registry_updated", "registry_path"}``. Raises ResetError when the
    password fails the policy or the account is missing/ambiguous; nothing is written then.
    """
    wanted = (email or "").strip().lower()
    if not wanted:
        raise ResetError("An email address is required.")

    problem = _policy_problem(new_password or "")
    if problem:
        raise ResetError(problem)

    matches = list(User.objects.filter(email__iexact=wanted, deleted=False)[:2])
    if not matches:
        raise ResetError(f"No active account with email {wanted}.")
    if len(matches) > 1:
        raise ResetError(f"More than one active account matches {wanted}; nothing was changed.")

    user_id = str(matches[0].id)
    UserModel.update_user(user_id=user_id, update_data={"password": hash_password(new_password)})
    try:
        refreshed = account_integrity.refresh_registered_user(UserModel.find_raw_by_id(user_id))
    except (OSError, ValueError) as exc:
        raise ResetError(
            f"The password WAS changed, but the account-integrity registry at "
            f"{account_integrity.registry_path()} could not be updated ({exc}). "
            f"Sign-in may be refused until it is."
        ) from exc
    return {
        "email": wanted,
        "registry_updated": refreshed,
        "registry_path": account_integrity.registry_path(),
    }
