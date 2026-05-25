"""Tests that MFAChallengeUseCase routes sms/email MFA through the OTP service."""

from __future__ import annotations

import pytest

from apps.users.application.use_cases.mfa_challenge import MFAChallengeUseCase
from apps.users.domain.exceptions import OTPInvalidError
from apps.users.tests.unit.fakes import (
    FakeOTPService,
    FakeTokenService,
    FakeTOTPService,
    FakeUserRepository,
    make_user,
)


def _uc(user, otp_service=None):
    repo = FakeUserRepository([user])
    uc = MFAChallengeUseCase(repo, FakeTOTPService(), FakeTokenService(), otp_service=otp_service)
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
    _, uc = _uc(user, otp)
    result = uc.execute(user.id, FakeOTPService.FIXED_OTP)
    assert result.access_token is not None
    assert result.used_backup_code is False


def test_mfa_challenge_email_uses_otp_service():
    otp = FakeOTPService()
    user = make_user(mfa_enabled=True, mfa_type="email")
    otp.generate_and_store(user.id)
    _, uc = _uc(user, otp)
    result = uc.execute(user.id, FakeOTPService.FIXED_OTP)
    assert result.access_token is not None


def test_mfa_challenge_sms_wrong_otp_raises():
    otp = FakeOTPService()
    user = make_user(mfa_enabled=True, mfa_type="sms")
    otp.generate_and_store(user.id)
    _, uc = _uc(user, otp)
    with pytest.raises(OTPInvalidError):
        uc.execute(user.id, "WRONGOTP")
