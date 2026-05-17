"""Unit tests for email verification via OTP."""

from __future__ import annotations

import pytest

from apps.users.application.use_cases.verify_email import VerifyEmailUseCase
from apps.users.domain.exceptions import (
    EmailAlreadyVerifiedError,
    OTPExpiredError,
    OTPInvalidError,
    UserNotFoundError,
)
from apps.users.tests.unit.fakes import FakeOTPService, FakeUserRepository, make_user


def test_verify_email_marks_user_as_verified():
    """Valid OTP submission sets is_email_verified to True."""
    user = make_user(is_email_verified=False)
    repo = FakeUserRepository([user])
    otp_svc = FakeOTPService()
    otp_svc.generate_and_store(user.id)

    VerifyEmailUseCase(repo, otp_svc).execute(email=user.email, otp=FakeOTPService.FIXED_OTP)

    assert repo.get_by_id(user.id).is_email_verified is True


def test_verify_email_cannot_be_submitted_again_after_success():
    """After verification, a second attempt raises EmailAlreadyVerifiedError (user is verified, OTP is gone)."""
    user = make_user(is_email_verified=False)
    repo = FakeUserRepository([user])
    otp_svc = FakeOTPService()
    otp_svc.generate_and_store(user.id)

    VerifyEmailUseCase(repo, otp_svc).execute(email=user.email, otp=FakeOTPService.FIXED_OTP)

    with pytest.raises(EmailAlreadyVerifiedError):
        VerifyEmailUseCase(repo, otp_svc).execute(email=user.email, otp=FakeOTPService.FIXED_OTP)


def test_verify_email_raises_when_already_verified():
    """Submitting an OTP for an already-verified account raises EmailAlreadyVerifiedError."""
    user = make_user(is_email_verified=True)
    repo = FakeUserRepository([user])
    otp_svc = FakeOTPService()

    with pytest.raises(EmailAlreadyVerifiedError):
        VerifyEmailUseCase(repo, otp_svc).execute(email=user.email, otp="ANYTHING")


def test_verify_email_raises_on_wrong_otp():
    """An incorrect OTP raises OTPInvalidError."""
    user = make_user(is_email_verified=False)
    repo = FakeUserRepository([user])
    otp_svc = FakeOTPService()
    otp_svc.generate_and_store(user.id)

    with pytest.raises(OTPInvalidError):
        VerifyEmailUseCase(repo, otp_svc).execute(email=user.email, otp="WRONGOTP")


def test_verify_email_raises_on_expired_otp():
    """Submitting an OTP when none is stored raises OTPExpiredError."""
    user = make_user(is_email_verified=False)
    repo = FakeUserRepository([user])
    otp_svc = FakeOTPService()

    with pytest.raises(OTPExpiredError):
        VerifyEmailUseCase(repo, otp_svc).execute(email=user.email, otp="ABCD1234")


def test_verify_email_raises_for_unknown_email():
    """Submitting an OTP for a non-existent email raises UserNotFoundError."""
    repo = FakeUserRepository()
    otp_svc = FakeOTPService()

    with pytest.raises(UserNotFoundError):
        VerifyEmailUseCase(repo, otp_svc).execute(email="ghost@example.com", otp="ABCD1234")
