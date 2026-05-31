"""Unit tests for EnableEmailMFAUseCase."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from apps.users.application.use_cases.enable_email_mfa import EnableEmailMFAUseCase
from apps.users.domain.exceptions import MFAAlreadyEnabledError, OTPInvalidError
from apps.users.tests.unit.fakes import FakeUserRepository, make_user


def _repo(user):
    return FakeUserRepository([user])


def test_enable_email_verifies_otp_and_sets_mfa_type():
    user = make_user(email="u@example.com")
    repo = _repo(user)
    otp = MagicMock()
    backup = MagicMock()
    backup.generate.return_value = ["CCCCCCCC", "DDDDDDDD"]

    result = EnableEmailMFAUseCase(repo, otp, backup).execute(user.id, "OTP99999")

    otp.verify_and_consume.assert_called_once_with(user.id, "OTP99999")
    saved = repo.get_by_id(user.id)
    assert saved.mfa_enabled is True
    assert saved.mfa_type == "email"
    assert result.backup_codes == ["CCCCCCCC", "DDDDDDDD"]


def test_enable_email_invalid_otp_raises():
    user = make_user()
    otp = MagicMock()
    otp.verify_and_consume.side_effect = OTPInvalidError("bad otp")
    with pytest.raises(OTPInvalidError):
        EnableEmailMFAUseCase(_repo(user), otp, None).execute(user.id, "WRONG999")


def test_enable_email_mfa_already_enabled_raises():
    user = make_user(mfa_enabled=True)
    with pytest.raises(MFAAlreadyEnabledError):
        EnableEmailMFAUseCase(_repo(user), MagicMock(), None).execute(user.id, "OTP99999")


def test_enable_email_no_backup_service_returns_empty_codes():
    user = make_user()
    result = EnableEmailMFAUseCase(_repo(user), MagicMock(), None).execute(user.id, "OTP99999")
    assert result.backup_codes == []
