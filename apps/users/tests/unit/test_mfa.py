"""Unit tests for MFA setup, enable, disable, and challenge use cases."""

from __future__ import annotations

import pytest

from apps.users.application.use_cases.disable_mfa import DisableMFAUseCase
from apps.users.application.use_cases.enable_mfa import EnableMFAUseCase
from apps.users.application.use_cases.mfa_challenge import MFAChallengeUseCase
from apps.users.application.use_cases.setup_mfa import SetupMFAUseCase
from apps.users.domain.exceptions import (
    InvalidCredentialsError,
    InvalidTOTPError,
    MFAAlreadyEnabledError,
    MFANotEnabledError,
)
from apps.users.tests.unit.fakes import (
    FakeTokenService,
    FakeTOTPService,
    FakeUserRepository,
    make_user,
)

# setup


def test_setup_returns_secret_and_uri():
    """Setup stores a secret on the user and returns provisioning URI."""
    user = make_user(mfa_enabled=False)
    repo = FakeUserRepository([user])
    totp = FakeTOTPService()

    result = SetupMFAUseCase(repo, totp).execute(user_id=user.id)

    assert result["secret"] == FakeTOTPService.FIXED_SECRET
    assert "otpauth://" in result["provisioning_uri"]


def test_setup_stores_secret_on_user():
    """The secret is persisted to the user entity."""
    user = make_user(mfa_enabled=False)
    repo = FakeUserRepository([user])

    SetupMFAUseCase(repo, FakeTOTPService()).execute(user_id=user.id)

    assert repo.get_by_id(user.id).mfa_secret == FakeTOTPService.FIXED_SECRET


def test_setup_raises_when_already_enabled():
    """Setup on an already-enabled account raises MFAAlreadyEnabledError."""
    user = make_user(mfa_enabled=True)
    repo = FakeUserRepository([user])

    with pytest.raises(MFAAlreadyEnabledError):
        SetupMFAUseCase(repo, FakeTOTPService()).execute(user_id=user.id)


# enable


def test_enable_sets_mfa_enabled_true():
    """Valid TOTP code enables MFA on the account."""
    user = make_user(mfa_enabled=False, mfa_secret=FakeTOTPService.FIXED_SECRET)
    repo = FakeUserRepository([user])

    EnableMFAUseCase(repo, FakeTOTPService()).execute(user_id=user.id, code=FakeTOTPService.VALID_CODE)

    assert repo.get_by_id(user.id).mfa_enabled is True


def test_enable_raises_on_invalid_code():
    """Wrong TOTP code raises InvalidTOTPError."""
    user = make_user(mfa_enabled=False, mfa_secret=FakeTOTPService.FIXED_SECRET)
    repo = FakeUserRepository([user])

    with pytest.raises(InvalidTOTPError):
        EnableMFAUseCase(repo, FakeTOTPService()).execute(user_id=user.id, code="000000")


def test_enable_raises_when_no_secret():
    """Enabling without first calling setup (no secret) raises InvalidTOTPError."""
    user = make_user(mfa_enabled=False, mfa_secret=None)
    repo = FakeUserRepository([user])

    with pytest.raises(InvalidTOTPError):
        EnableMFAUseCase(repo, FakeTOTPService()).execute(user_id=user.id, code="123456")


def test_enable_raises_when_already_enabled():
    """Enabling on an already-enabled account raises MFAAlreadyEnabledError."""
    user = make_user(mfa_enabled=True, mfa_secret=FakeTOTPService.FIXED_SECRET)
    repo = FakeUserRepository([user])

    with pytest.raises(MFAAlreadyEnabledError):
        EnableMFAUseCase(repo, FakeTOTPService()).execute(user_id=user.id, code=FakeTOTPService.VALID_CODE)


# disable


def test_disable_clears_mfa():
    """Valid TOTP code disables MFA and clears the secret."""
    user = make_user(mfa_enabled=True, mfa_secret=FakeTOTPService.FIXED_SECRET)
    repo = FakeUserRepository([user])

    DisableMFAUseCase(repo, FakeTOTPService()).execute(user_id=user.id, code=FakeTOTPService.VALID_CODE)

    updated = repo.get_by_id(user.id)
    assert updated.mfa_enabled is False
    assert updated.mfa_secret is None


def test_disable_raises_on_invalid_code():
    """Wrong TOTP code raises InvalidTOTPError."""
    user = make_user(mfa_enabled=True, mfa_secret=FakeTOTPService.FIXED_SECRET)
    repo = FakeUserRepository([user])

    with pytest.raises(InvalidTOTPError):
        DisableMFAUseCase(repo, FakeTOTPService()).execute(user_id=user.id, code="000000")


def test_disable_raises_when_not_enabled():
    """Disabling when MFA is not enabled raises MFANotEnabledError."""
    user = make_user(mfa_enabled=False)
    repo = FakeUserRepository([user])

    with pytest.raises(MFANotEnabledError):
        DisableMFAUseCase(repo, FakeTOTPService()).execute(user_id=user.id, code=FakeTOTPService.VALID_CODE)


# challenge


def test_challenge_returns_tokens_on_valid_code():
    """Valid TOTP code during login challenge returns access and refresh tokens."""
    user = make_user(mfa_enabled=True, mfa_secret=FakeTOTPService.FIXED_SECRET)
    repo = FakeUserRepository([user])
    token_svc = FakeTokenService()

    result = MFAChallengeUseCase(repo, FakeTOTPService(), token_svc).execute(user_id=user.id, code=FakeTOTPService.VALID_CODE)

    assert result.access_token == f"access-{user.id}"
    assert result.refresh_token == f"refresh-{user.id}"


def test_challenge_raises_on_invalid_code():
    """Wrong TOTP code during challenge raises InvalidTOTPError."""
    user = make_user(mfa_enabled=True, mfa_secret=FakeTOTPService.FIXED_SECRET)
    repo = FakeUserRepository([user])

    with pytest.raises(InvalidTOTPError):
        MFAChallengeUseCase(repo, FakeTOTPService(), FakeTokenService()).execute(user_id=user.id, code="000000")


def test_challenge_raises_when_mfa_not_enabled():
    """Challenge for a user without MFA raises InvalidCredentialsError."""
    user = make_user(mfa_enabled=False)
    repo = FakeUserRepository([user])

    with pytest.raises(InvalidCredentialsError):
        MFAChallengeUseCase(repo, FakeTOTPService(), FakeTokenService()).execute(user_id=user.id, code=FakeTOTPService.VALID_CODE)
