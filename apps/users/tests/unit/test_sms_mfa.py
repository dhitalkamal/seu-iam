"""Unit tests for SetupSMSMFAUseCase and EnableSMSMFAUseCase."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from apps.users.application.use_cases.enable_sms_mfa import EnableSMSMFAUseCase
from apps.users.application.use_cases.setup_sms_mfa import SetupSMSMFAUseCase
from apps.users.domain.exceptions import MFAAlreadyEnabledError, MFAPhoneRequiredError, OTPInvalidError
from apps.users.tests.unit.fakes import FakeUserRepository, make_user


def _repo(user):
    return FakeUserRepository([user])


# SetupSMSMFAUseCase


def test_setup_sms_generates_otp_and_publishes_event():
    user = make_user(phone="+447700900000")
    otp = MagicMock()
    otp.generate_and_store.return_value = "OTP12345"
    events = MagicMock()

    SetupSMSMFAUseCase(_repo(user), otp, events).execute(user.id)

    otp.generate_and_store.assert_called_once_with(user.id)
    events.publish.assert_called_once()
    call_args = events.publish.call_args[0]
    assert call_args[0] == "iam.mfa_sms_otp_requested"
    assert call_args[1]["phone"] == "+447700900000"
    assert call_args[1]["otp"] == "OTP12345"


def test_setup_sms_mfa_already_enabled_raises():
    user = make_user(mfa_enabled=True, phone="+447700900000")
    with pytest.raises(MFAAlreadyEnabledError):
        SetupSMSMFAUseCase(_repo(user), MagicMock(), MagicMock()).execute(user.id)


def test_setup_sms_no_phone_raises():
    user = make_user(phone=None)
    with pytest.raises(MFAPhoneRequiredError):
        SetupSMSMFAUseCase(_repo(user), MagicMock(), MagicMock()).execute(user.id)


# EnableSMSMFAUseCase


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
