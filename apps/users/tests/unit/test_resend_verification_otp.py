"""Unit tests for resending the email verification OTP."""

from __future__ import annotations

import pytest

from apps.users.application.use_cases.resend_verification_otp import ResendVerificationOTPUseCase
from apps.users.domain.exceptions import EmailAlreadyVerifiedError, UserNotFoundError
from apps.users.tests.unit.fakes import (
    FakeEventPublisher,
    FakeOTPService,
    FakeUserRepository,
    make_user,
)


def test_resend_generates_new_otp_and_publishes_event():
    """Resend stores a fresh OTP and fires the email_verification_requested event."""
    user = make_user(is_email_verified=False)
    repo = FakeUserRepository([user])
    otp_svc = FakeOTPService()
    publisher = FakeEventPublisher()

    ResendVerificationOTPUseCase(repo, otp_svc, publisher).execute(email=user.email)

    assert len(publisher.events) == 1
    event_name, payload = publisher.events[0]
    assert event_name == "iam.email_verification_requested"
    assert payload["email"] == user.email
    assert payload["otp"] == FakeOTPService.FIXED_OTP


def test_resend_raises_when_already_verified():
    """Requesting a resend for an already-verified account raises EmailAlreadyVerifiedError."""
    user = make_user(is_email_verified=True)
    repo = FakeUserRepository([user])

    with pytest.raises(EmailAlreadyVerifiedError):
        ResendVerificationOTPUseCase(repo, FakeOTPService(), FakeEventPublisher()).execute(
            email=user.email
        )


def test_resend_raises_for_unknown_email():
    """Requesting a resend for a non-existent email raises UserNotFoundError."""
    repo = FakeUserRepository()

    with pytest.raises(UserNotFoundError):
        ResendVerificationOTPUseCase(repo, FakeOTPService(), FakeEventPublisher()).execute(
            email="ghost@example.com"
        )


def test_resend_overwrites_existing_otp():
    """A second resend replaces the previously stored OTP."""
    user = make_user(is_email_verified=False)
    repo = FakeUserRepository([user])
    otp_svc = FakeOTPService()
    publisher = FakeEventPublisher()
    uc = ResendVerificationOTPUseCase(repo, otp_svc, publisher)

    uc.execute(email=user.email)
    uc.execute(email=user.email)

    assert len(publisher.events) == 2
