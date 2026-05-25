"""Tests for MFAChallengeUseCase: TOTP, sms OTP, email OTP, and backup code paths."""

from __future__ import annotations

import pytest

from apps.users.application.use_cases.mfa_challenge import MFAChallengeUseCase
from apps.users.domain.exceptions import InvalidCredentialsError, InvalidTOTPError, OTPInvalidError
from apps.users.tests.unit.fakes import (
    FakeBackupCodeService,
    FakeOTPService,
    FakeTokenService,
    FakeTOTPService,
    FakeUserRepository,
    make_user,
)


def _uc(user, otp_service=None, backup=None):
    repo = FakeUserRepository([user])
    uc = MFAChallengeUseCase(repo, FakeTOTPService(), FakeTokenService(), backup_code_service=backup, otp_service=otp_service)
    return repo, uc


def test_mfa_challenge_totp_still_works():
    user = make_user(mfa_enabled=True, mfa_secret=FakeTOTPService.FIXED_SECRET, mfa_type="totp")
    _, uc = _uc(user)
    result = uc.execute(user.id, FakeTOTPService.VALID_CODE)
    assert result.access_token is not None
    assert result.used_backup_code is False


def test_mfa_challenge_sms_uses_otp_service():
    otp = FakeOTPService()
    user = make_user(mfa_enabled=True, mfa_type="sms")
    otp.generate_and_store(user.id)
    _, uc = _uc(user, otp_service=otp)
    result = uc.execute(user.id, FakeOTPService.FIXED_OTP)
    assert result.access_token is not None
    assert result.used_backup_code is False


def test_mfa_challenge_email_uses_otp_service():
    otp = FakeOTPService()
    user = make_user(mfa_enabled=True, mfa_type="email")
    otp.generate_and_store(user.id)
    _, uc = _uc(user, otp_service=otp)
    result = uc.execute(user.id, FakeOTPService.FIXED_OTP)
    assert result.access_token is not None


def test_mfa_challenge_sms_wrong_otp_raises():
    otp = FakeOTPService()
    user = make_user(mfa_enabled=True, mfa_type="sms")
    otp.generate_and_store(user.id)
    _, uc = _uc(user, otp_service=otp)
    with pytest.raises(OTPInvalidError):
        uc.execute(user.id, "WRONGOTP")


def test_mfa_challenge_no_mfa_raises():
    user = make_user(mfa_enabled=False)
    _, uc = _uc(user)
    with pytest.raises(InvalidCredentialsError):
        uc.execute(user.id, "123456")


def test_mfa_challenge_totp_wrong_code_raises():
    user = make_user(mfa_enabled=True, mfa_secret=FakeTOTPService.FIXED_SECRET, mfa_type="totp")
    _, uc = _uc(user)
    with pytest.raises(InvalidTOTPError):
        uc.execute(user.id, "000000")


def test_mfa_challenge_backup_code_works():
    backup = FakeBackupCodeService()
    user = make_user(mfa_enabled=True, mfa_secret=FakeTOTPService.FIXED_SECRET, mfa_type="totp")
    backup.generate(user.id)
    _, uc = _uc(user, backup=backup)
    result = uc.execute(user.id, FakeBackupCodeService.VALID_CODE)
    assert result.used_backup_code is True
