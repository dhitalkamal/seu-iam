"""Tests for mfa_type in LoginResult and OTP dispatch on sms/email login."""

from __future__ import annotations

from unittest.mock import MagicMock

from django.contrib.auth.hashers import make_password

from apps.users.application.use_cases.login import LoginUseCase
from apps.users.tests.unit.fakes import FakeTokenService, FakeUserRepository, make_user


def _uc(user, otp_service=None, events=None):
    return LoginUseCase(FakeUserRepository([user]), FakeTokenService(), otp_service, events)


def test_login_no_mfa_returns_tokens():
    user = make_user(email="u@example.com", password_hash=make_password("password123"))
    result = _uc(user).execute("u@example.com", "password123")
    assert result.mfa_required is False
    assert result.access_token is not None
    assert result.mfa_type is None


def test_login_totp_mfa_returns_mfa_type_totp():
    user = make_user(email="u@example.com", password_hash=make_password("password123"), mfa_enabled=True, mfa_type="totp")
    otp = MagicMock()
    events = MagicMock()
    result = _uc(user, otp, events).execute("u@example.com", "password123")
    assert result.mfa_required is True
    assert result.mfa_type == "totp"
    otp.generate_and_store.assert_not_called()
    events.publish.assert_not_called()


def test_login_sms_mfa_dispatches_event_and_returns_mfa_type():
    user = make_user(
        email="u@example.com",
        password_hash=make_password("password123"),
        mfa_enabled=True,
        mfa_type="sms",
        phone="+447700900000",
    )
    otp = MagicMock()
    otp.generate_and_store.return_value = "ABCD1234"
    events = MagicMock()
    result = _uc(user, otp, events).execute("u@example.com", "password123")
    assert result.mfa_required is True
    assert result.mfa_type == "sms"
    otp.generate_and_store.assert_called_once_with(user.id)
    call_args = events.publish.call_args[0]
    assert call_args[0] == "iam.mfa_sms_otp_requested"
    assert call_args[1]["phone"] == "+447700900000"
    assert call_args[1]["otp"] == "ABCD1234"


def test_login_email_mfa_dispatches_event_and_returns_mfa_type():
    user = make_user(
        email="u@example.com",
        password_hash=make_password("password123"),
        mfa_enabled=True,
        mfa_type="email",
    )
    otp = MagicMock()
    otp.generate_and_store.return_value = "ABCD1234"
    events = MagicMock()
    result = _uc(user, otp, events).execute("u@example.com", "password123")
    assert result.mfa_required is True
    assert result.mfa_type == "email"
    otp.generate_and_store.assert_called_once_with(user.id)
    call_args = events.publish.call_args[0]
    assert call_args[0] == "iam.mfa_email_otp_requested"
    assert call_args[1]["email"] == "u@example.com"
    assert call_args[1]["otp"] == "ABCD1234"
