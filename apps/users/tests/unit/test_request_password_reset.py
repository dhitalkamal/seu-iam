"""Unit tests for requesting a password reset OTP."""

from __future__ import annotations

import pytest

from apps.users.application.use_cases.request_password_reset import RequestPasswordResetUseCase
from apps.users.domain.exceptions import AccountNotVerifiedError, UserNotFoundError
from apps.users.tests.unit.fakes import (
    FakeEventPublisher,
    FakeOTPService,
    FakeUserRepository,
    make_user,
)


def test_request_reset_publishes_event_with_otp():
    """A valid request generates an OTP and fires a password_reset_requested event."""
    user = make_user(is_email_verified=True)
    repo = FakeUserRepository([user])
    otp_svc = FakeOTPService()
    publisher = FakeEventPublisher()

    RequestPasswordResetUseCase(repo, otp_svc, publisher).execute(email=user.email)

    assert len(publisher.events) == 1
    event_name, payload = publisher.events[0]
    assert event_name == "iam.password_reset_requested"
    assert payload["email"] == user.email
    assert payload["otp"] == FakeOTPService.FIXED_OTP


def test_request_reset_stores_otp():
    """The OTP is persisted in the OTP service for the user."""
    user = make_user(is_email_verified=True)
    repo = FakeUserRepository([user])
    otp_svc = FakeOTPService()

    RequestPasswordResetUseCase(repo, otp_svc, FakeEventPublisher()).execute(email=user.email)

    assert user.id in otp_svc._store  # type: ignore[attr-defined]


def test_request_reset_raises_for_unknown_email():
    """Requesting a reset for a non-existent email raises UserNotFoundError."""
    repo = FakeUserRepository()

    with pytest.raises(UserNotFoundError):
        RequestPasswordResetUseCase(repo, FakeOTPService(), FakeEventPublisher()).execute(
            email="ghost@example.com"
        )


def test_request_reset_raises_when_email_not_verified():
    """Requesting a reset for an unverified account raises AccountNotVerifiedError."""
    user = make_user(is_email_verified=False)
    repo = FakeUserRepository([user])

    with pytest.raises(AccountNotVerifiedError):
        RequestPasswordResetUseCase(repo, FakeOTPService(), FakeEventPublisher()).execute(
            email=user.email
        )
