"""Tests that UserEntity carries the mfa_type field and the new exception exists."""

from __future__ import annotations

from apps.users.domain.exceptions import MFAPhoneRequiredError
from apps.users.tests.unit.fakes import make_user


def test_user_entity_has_mfa_type_defaulting_to_none():
    user = make_user()
    assert user.mfa_type is None


def test_user_entity_accepts_mfa_type_values():
    for v in ("totp", "sms", "email"):
        user = make_user(mfa_type=v)
        assert user.mfa_type == v


def test_mfa_phone_required_error_has_correct_http_status():
    err = MFAPhoneRequiredError("no phone")
    assert err.http_status == 422
    assert err.code == "ERR_AUTH_MFA_PHONE_REQUIRED"
