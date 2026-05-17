"""Unit tests for LogoutUseCase. No database, hand-rolled fakes."""

from __future__ import annotations

import pytest

from apps.users.application.use_cases.logout import LogoutUseCase
from apps.users.domain.exceptions import InvalidTokenError
from apps.users.tests.unit.fakes import FakeTokenBlacklistService


def test_logout_blacklists_the_refresh_token():
    """A valid refresh token is added to the blacklist on logout."""
    svc = FakeTokenBlacklistService()
    LogoutUseCase(svc).execute("valid-refresh-token")
    assert "valid-refresh-token" in svc.blacklisted


def test_logout_invalid_token_raises():
    """A malformed or already-used token raises InvalidTokenError."""
    svc = FakeTokenBlacklistService()
    with pytest.raises(InvalidTokenError):
        LogoutUseCase(svc).execute("invalid-token")


def test_logout_does_not_raise_on_any_other_token():
    """Any token string that is not the sentinel raises no error."""
    svc = FakeTokenBlacklistService()
    LogoutUseCase(svc).execute("some.real.jwt.token")
    assert "some.real.jwt.token" in svc.blacklisted
