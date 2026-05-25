"""Tests that DisableMFAUseCase clears mfa_type on disable."""

from __future__ import annotations

from apps.users.application.use_cases.disable_mfa import DisableMFAUseCase
from apps.users.tests.unit.fakes import FakeTOTPService, FakeUserRepository, make_user


def test_disable_mfa_clears_mfa_type():
    user = make_user(mfa_enabled=True, mfa_secret=FakeTOTPService.FIXED_SECRET, mfa_type="totp")
    repo = FakeUserRepository([user])
    DisableMFAUseCase(repo, FakeTOTPService()).execute(user.id, FakeTOTPService.VALID_CODE)
    saved = repo.get_by_id(user.id)
    assert saved.mfa_type is None
    assert saved.mfa_enabled is False
    assert saved.mfa_secret is None
