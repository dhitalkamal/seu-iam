"""Unit tests for SetupSMSMFAUseCase."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from apps.users.application.use_cases.setup_sms_mfa import SetupSMSMFAUseCase
from apps.users.domain.exceptions import MFAAlreadyEnabledError, MFAPhoneRequiredError
from apps.users.tests.unit.fakes import FakeUserRepository, make_user


def _repo(user):
    return FakeUserRepository([user])


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
