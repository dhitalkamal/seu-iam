"""Unit tests for EnableSMSMFAUseCase."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from apps.users.application.use_cases.enable_sms_mfa import EnableSMSMFAUseCase
from apps.users.domain.exceptions import MFAAlreadyEnabledError, OTPInvalidError
from apps.users.tests.unit.fakes import FakeUserRepository, make_user


def _repo(user):
    return FakeUserRepository([user])


def test_enable_sms_verifies_otp_and_sets_mfa_type():
    user = make_user(phone="+447700900000")
    repo = _repo(user)
    otp = MagicMock()
    backup = MagicMock()
    backup.generate.return_value = ["AAAAAAAA", "BBBBBBBB"]

    result = EnableSMSMFAUseCase(repo, otp, backup).execute(user.id, "OTP12345")

    otp.verify_and_consume.assert_called_once_with(user.id, "OTP12345")
    saved = repo.get_by_id(user.id)
    assert saved.mfa_enabled is True
    assert saved.mfa_type == "sms"
    assert result.backup_codes == ["AAAAAAAA", "BBBBBBBB"]


def test_enable_sms_invalid_otp_raises():
    user = make_user()
    otp = MagicMock()
    otp.verify_and_consume.side_effect = OTPInvalidError("bad otp")
    with pytest.raises(OTPInvalidError):
        EnableSMSMFAUseCase(_repo(user), otp, None).execute(user.id, "WRONG123")


def test_enable_sms_mfa_already_enabled_raises():
    user = make_user(mfa_enabled=True)
    with pytest.raises(MFAAlreadyEnabledError):
        EnableSMSMFAUseCase(_repo(user), MagicMock(), None).execute(user.id, "OTP12345")


def test_enable_sms_no_backup_service_returns_empty_codes():
    user = make_user()
    result = EnableSMSMFAUseCase(_repo(user), MagicMock(), None).execute(user.id, "OTP12345")
    assert result.backup_codes == []
