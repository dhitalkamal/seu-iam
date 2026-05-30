"""Unit tests for MFA backup code use cases."""

from __future__ import annotations

import pytest

from apps.users.application.use_cases.enable_mfa import EnableMFAUseCase
from apps.users.application.use_cases.mfa_challenge import MFAChallengeUseCase
from apps.users.application.use_cases.regenerate_backup_codes import RegenerateBackupCodesUseCase
from apps.users.domain.exceptions import (
    InvalidBackupCodeError,
    InvalidTOTPError,
    MFANotEnabledError,
)
from apps.users.tests.unit.fakes import (
    FakeBackupCodeService,
    FakeTokenService,
    FakeTOTPService,
    FakeUserRepository,
    make_user,
)

# enable MFA returns backup codes


def test_enable_mfa_returns_backup_codes():
    """Enabling MFA produces a list of 8 backup codes."""
    user = make_user(mfa_enabled=False, mfa_secret=FakeTOTPService.FIXED_SECRET)
    repo = FakeUserRepository([user])
    backup_svc = FakeBackupCodeService()

    result = EnableMFAUseCase(repo, FakeTOTPService(), backup_svc).execute(user_id=user.id, code=FakeTOTPService.VALID_CODE)

    assert len(result.backup_codes) == FakeBackupCodeService.CODE_COUNT
    assert all(len(c) == 8 for c in result.backup_codes)


def test_enable_mfa_without_backup_service_still_works():
    """EnableMFAUseCase works without a backup service (no codes returned)."""
    user = make_user(mfa_enabled=False, mfa_secret=FakeTOTPService.FIXED_SECRET)
    repo = FakeUserRepository([user])

    result = EnableMFAUseCase(repo, FakeTOTPService()).execute(user_id=user.id, code=FakeTOTPService.VALID_CODE)

    assert result.backup_codes == []


# MFA challenge with backup code


def test_challenge_succeeds_with_valid_backup_code():
    """A valid backup code can be used instead of a TOTP code to complete login."""
    user = make_user(mfa_enabled=True, mfa_secret=FakeTOTPService.FIXED_SECRET)
    repo = FakeUserRepository([user])
    backup_svc = FakeBackupCodeService()
    backup_svc.generate(user.id)

    result = MFAChallengeUseCase(repo, FakeTOTPService(), FakeTokenService(), backup_svc).execute(
        user_id=user.id, code=FakeBackupCodeService.VALID_CODE
    )

    assert result.access_token is not None
    assert result.used_backup_code is True


def test_challenge_raises_on_invalid_backup_code():
    """An incorrect backup code raises InvalidBackupCodeError."""
    user = make_user(mfa_enabled=True, mfa_secret=FakeTOTPService.FIXED_SECRET)
    repo = FakeUserRepository([user])
    backup_svc = FakeBackupCodeService()
    backup_svc.generate(user.id)

    with pytest.raises((InvalidTOTPError, InvalidBackupCodeError)):
        MFAChallengeUseCase(repo, FakeTOTPService(), FakeTokenService(), backup_svc).execute(user_id=user.id, code="BADCODE1")


def test_challenge_totp_still_works_when_backup_service_present():
    """A valid TOTP code still works even when the backup service is wired in."""
    user = make_user(mfa_enabled=True, mfa_secret=FakeTOTPService.FIXED_SECRET)
    repo = FakeUserRepository([user])

    result = MFAChallengeUseCase(repo, FakeTOTPService(), FakeTokenService(), FakeBackupCodeService()).execute(
        user_id=user.id, code=FakeTOTPService.VALID_CODE
    )

    assert result.used_backup_code is False


# regenerate backup codes


def test_regenerate_requires_mfa_enabled():
    """Regenerating codes when MFA is disabled raises MFANotEnabledError."""
    user = make_user(mfa_enabled=False)
    repo = FakeUserRepository([user])

    with pytest.raises(MFANotEnabledError):
        RegenerateBackupCodesUseCase(repo, FakeTOTPService(), FakeBackupCodeService()).execute(
            user_id=user.id, code=FakeTOTPService.VALID_CODE
        )


def test_regenerate_requires_valid_totp():
    """Regenerating codes with an invalid TOTP raises InvalidTOTPError."""
    user = make_user(mfa_enabled=True, mfa_secret=FakeTOTPService.FIXED_SECRET)
    repo = FakeUserRepository([user])

    with pytest.raises(InvalidTOTPError):
        RegenerateBackupCodesUseCase(repo, FakeTOTPService(), FakeBackupCodeService()).execute(user_id=user.id, code="000000")


def test_regenerate_returns_new_codes():
    """Regenerating backup codes returns a fresh set."""
    user = make_user(mfa_enabled=True, mfa_secret=FakeTOTPService.FIXED_SECRET)
    repo = FakeUserRepository([user])
    backup_svc = FakeBackupCodeService()

    codes = RegenerateBackupCodesUseCase(repo, FakeTOTPService(), backup_svc).execute(user_id=user.id, code=FakeTOTPService.VALID_CODE)

    assert len(codes) == FakeBackupCodeService.CODE_COUNT
