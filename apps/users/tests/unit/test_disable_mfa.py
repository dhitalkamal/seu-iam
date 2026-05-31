"""Tests for DisableMFAUseCase: code path for totp, password path for sms/email."""

from __future__ import annotations

import pytest

from apps.users.application.use_cases.disable_mfa import DisableMFAUseCase
from apps.users.domain.exceptions import InvalidCredentialsError, InvalidTOTPError, MFANotEnabledError
from apps.users.tests.unit.fakes import FakeTOTPService, FakeUserRepository, make_user


def _repo(user):
    return FakeUserRepository([user])


def test_disable_totp_with_valid_code_clears_mfa():
    user = make_user(mfa_enabled=True, mfa_secret=FakeTOTPService.FIXED_SECRET, mfa_type="totp")
    repo = _repo(user)
    DisableMFAUseCase(repo, FakeTOTPService()).execute(user.id, code=FakeTOTPService.VALID_CODE)
    saved = repo.get_by_id(user.id)
    assert saved.mfa_enabled is False
    assert saved.mfa_secret is None
    assert saved.mfa_type is None


def test_disable_totp_wrong_code_raises():
    user = make_user(mfa_enabled=True, mfa_secret=FakeTOTPService.FIXED_SECRET, mfa_type="totp")
    with pytest.raises(InvalidTOTPError):
        DisableMFAUseCase(_repo(user), FakeTOTPService()).execute(user.id, code="000000")


def test_disable_mfa_not_enabled_raises():
    user = make_user(mfa_enabled=False)
    with pytest.raises(MFANotEnabledError):
        DisableMFAUseCase(_repo(user), FakeTOTPService()).execute(user.id, code="123456")


def test_disable_sms_with_correct_password_clears_mfa():
    from django.contrib.auth.hashers import make_password

    user = make_user(
        mfa_enabled=True,
        mfa_type="sms",
        mfa_secret=None,
        password_hash=make_password("correct"),
    )
    repo = _repo(user)
    DisableMFAUseCase(repo, FakeTOTPService()).execute(user.id, current_password="correct")
    saved = repo.get_by_id(user.id)
    assert saved.mfa_enabled is False
    assert saved.mfa_type is None


def test_disable_sms_wrong_password_raises():
    from django.contrib.auth.hashers import make_password

    user = make_user(
        mfa_enabled=True,
        mfa_type="sms",
        mfa_secret=None,
        password_hash=make_password("correct"),
    )
    with pytest.raises(InvalidCredentialsError):
        DisableMFAUseCase(_repo(user), FakeTOTPService()).execute(user.id, current_password="wrong")


def test_disable_email_with_correct_password_clears_mfa():
    from django.contrib.auth.hashers import make_password

    user = make_user(
        mfa_enabled=True,
        mfa_type="email",
        mfa_secret=None,
        password_hash=make_password("correct"),
    )
    repo = _repo(user)
    DisableMFAUseCase(repo, FakeTOTPService()).execute(user.id, current_password="correct")
    saved = repo.get_by_id(user.id)
    assert saved.mfa_enabled is False
    assert saved.mfa_type is None
