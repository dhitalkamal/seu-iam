"""Unit tests for confirming a password reset with OTP."""

from __future__ import annotations

import pytest
from django.contrib.auth.hashers import check_password

from apps.users.application.use_cases.confirm_password_reset import ConfirmPasswordResetUseCase
from apps.users.domain.exceptions import OTPExpiredError, OTPInvalidError, UserNotFoundError
from apps.users.tests.unit.fakes import (
    FakeOTPService,
    FakePasswordHistoryService,
    FakeTokenBlacklistService,
    FakeUserRepository,
    make_user,
)


def _uc(
    repo: FakeUserRepository,
    otp: FakeOTPService,
    blacklist: FakeTokenBlacklistService | None = None,
) -> ConfirmPasswordResetUseCase:
    return ConfirmPasswordResetUseCase(repo, otp, blacklist or FakeTokenBlacklistService(), FakePasswordHistoryService())


def test_confirm_reset_updates_password():
    """Valid OTP and new password updates the stored password hash."""
    user = make_user(is_email_verified=True)
    repo = FakeUserRepository([user])
    otp_svc = FakeOTPService()
    otp_svc.generate_and_store(user.id)

    _uc(repo, otp_svc).execute(email=user.email, otp=FakeOTPService.FIXED_OTP, new_password="NewSecurePass1!")

    assert check_password("NewSecurePass1!", repo.get_by_id(user.id).password_hash)


def test_confirm_reset_blacklists_all_user_tokens():
    """All sessions are invalidated after a successful password reset."""
    user = make_user(is_email_verified=True)
    repo = FakeUserRepository([user])
    otp_svc = FakeOTPService()
    otp_svc.generate_and_store(user.id)
    blacklist_svc = FakeTokenBlacklistService()

    _uc(repo, otp_svc, blacklist_svc).execute(email=user.email, otp=FakeOTPService.FIXED_OTP, new_password="NewSecurePass1!")

    assert user.id in blacklist_svc.invalidated_users


def test_confirm_reset_consumes_otp():
    """The OTP is deleted after a successful reset so it cannot be reused."""
    user = make_user(is_email_verified=True)
    repo = FakeUserRepository([user])
    otp_svc = FakeOTPService()
    otp_svc.generate_and_store(user.id)

    _uc(repo, otp_svc).execute(email=user.email, otp=FakeOTPService.FIXED_OTP, new_password="NewSecurePass1!")

    assert user.id not in otp_svc._store  # type: ignore[attr-defined]


def test_confirm_reset_raises_on_wrong_otp():
    """An incorrect OTP raises OTPInvalidError."""
    user = make_user(is_email_verified=True)
    repo = FakeUserRepository([user])
    otp_svc = FakeOTPService()
    otp_svc.generate_and_store(user.id)

    with pytest.raises(OTPInvalidError):
        _uc(repo, otp_svc).execute(email=user.email, otp="WRONGOTP", new_password="NewSecurePass1!")


def test_confirm_reset_raises_on_expired_otp():
    """No stored OTP raises OTPExpiredError."""
    user = make_user(is_email_verified=True)
    repo = FakeUserRepository([user])

    with pytest.raises(OTPExpiredError):
        _uc(repo, FakeOTPService()).execute(email=user.email, otp="ABCD1234", new_password="NewSecurePass1!")


def test_confirm_reset_raises_for_unknown_email():
    """Unknown email raises UserNotFoundError."""
    repo = FakeUserRepository()

    with pytest.raises(UserNotFoundError):
        _uc(repo, FakeOTPService()).execute(email="ghost@example.com", otp="ABCD1234", new_password="NewSecurePass1!")
