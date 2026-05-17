"""Unit tests for LoginUseCase. no database, hand-rolled fakes."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from django.contrib.auth.hashers import make_password

from apps.users.application.use_cases.login import LoginUseCase
from apps.users.domain.exceptions import (
    AccountInactiveError,
    AccountLockedError,
    AccountNotVerifiedError,
    InvalidCredentialsError,
)
from apps.users.tests.unit.fakes import FakeTokenService, FakeUserRepository, make_user


def test_valid_credentials_return_tokens():
    """Correct credentials for a verified, active account return access and refresh tokens."""
    user = make_user(email="ok@example.com", password_hash=make_password("StrongPass1!"))
    result = LoginUseCase(FakeUserRepository([user]), FakeTokenService()).execute(
        "ok@example.com", "StrongPass1!"
    )

    assert result.mfa_required is False
    assert result.access_token is not None
    assert result.refresh_token is not None
    assert result.user_id is not None


def test_mfa_enabled_returns_challenge():
    """When MFA is active, login returns mfa_required=True with user_id and no tokens."""
    user = make_user(
        email="mfa@example.com",
        password_hash=make_password("StrongPass1!"),
        mfa_enabled=True,
    )
    result = LoginUseCase(FakeUserRepository([user]), FakeTokenService()).execute(
        "mfa@example.com", "StrongPass1!"
    )

    assert result.mfa_required is True
    assert result.user_id == user.id
    assert result.access_token is None
    assert result.refresh_token is None


def test_wrong_password_raises():
    """Incorrect password raises InvalidCredentialsError."""
    user = make_user(email="a@b.com", password_hash=make_password("correct"))
    with pytest.raises(InvalidCredentialsError):
        LoginUseCase(FakeUserRepository([user]), FakeTokenService()).execute("a@b.com", "wrong")


def test_unknown_email_raises():
    """Email that does not exist raises InvalidCredentialsError, not UserNotFoundError."""
    with pytest.raises(InvalidCredentialsError):
        LoginUseCase(FakeUserRepository(), FakeTokenService()).execute("nobody@example.com", "Pass")


def test_inactive_account_raises():
    """Deactivated accounts are rejected before any password check."""
    user = make_user(is_active=False)
    with pytest.raises(AccountInactiveError):
        LoginUseCase(FakeUserRepository([user]), FakeTokenService()).execute(user.email, "anything")


def test_locked_account_raises():
    """Accounts locked by repeated failures raise AccountLockedError."""
    future = datetime.now(timezone.utc) + timedelta(minutes=30)
    user = make_user(locked_until=future, password_hash=make_password("p"))
    with pytest.raises(AccountLockedError):
        LoginUseCase(FakeUserRepository([user]), FakeTokenService()).execute(user.email, "p")


def test_unverified_account_raises():
    """Accounts with is_email_verified=False cannot log in."""
    user = make_user(is_email_verified=False, password_hash=make_password("StrongPass1!"))
    with pytest.raises(AccountNotVerifiedError):
        LoginUseCase(FakeUserRepository([user]), FakeTokenService()).execute(
            user.email, "StrongPass1!"
        )


def test_wrong_password_increments_failed_attempts():
    """Each wrong password increments failed_login_attempts on the stored user."""
    repo = FakeUserRepository([make_user(email="x@x.com", password_hash=make_password("c"))])
    try:
        LoginUseCase(repo, FakeTokenService()).execute("x@x.com", "wrong")
    except InvalidCredentialsError:
        pass
    stored = repo.get_by_email("x@x.com")
    assert stored.failed_login_attempts == 1


def test_successful_login_resets_failed_attempts():
    """A successful login clears any previous failed attempt count."""
    user = make_user(
        email="y@y.com",
        password_hash=make_password("StrongPass1!"),
        failed_login_attempts=3,
    )
    repo = FakeUserRepository([user])
    LoginUseCase(repo, FakeTokenService()).execute("y@y.com", "StrongPass1!")
    stored = repo.get_by_email("y@y.com")
    assert stored.failed_login_attempts == 0
