"""Unit tests for the change password use case."""

from __future__ import annotations

import pytest
from django.contrib.auth.hashers import check_password, make_password

from apps.users.application.use_cases.change_password import ChangePasswordUseCase
from apps.users.domain.exceptions import InvalidCredentialsError
from apps.users.tests.unit.fakes import FakeTokenBlacklistService, FakeUserRepository, make_user


def _user_with_password(raw: str) -> object:
    return make_user(password_hash=make_password(raw))


def test_change_password_updates_hash():
    """New password is hashed and persisted."""
    user = _user_with_password("OldPass1!")
    repo = FakeUserRepository([user])

    ChangePasswordUseCase(repo, FakeTokenBlacklistService()).execute(
        user_id=user.id,
        current_password="OldPass1!",
        new_password="NewPass99!",
    )

    assert check_password("NewPass99!", repo.get_by_id(user.id).password_hash)


def test_change_password_invalidates_all_sessions():
    """All sessions are blacklisted after a successful change."""
    user = _user_with_password("OldPass1!")
    repo = FakeUserRepository([user])
    blacklist = FakeTokenBlacklistService()

    ChangePasswordUseCase(repo, blacklist).execute(
        user_id=user.id,
        current_password="OldPass1!",
        new_password="NewPass99!",
    )

    assert user.id in blacklist.invalidated_users


def test_change_password_rejects_wrong_current_password():
    """Wrong current password raises InvalidCredentialsError."""
    user = _user_with_password("OldPass1!")
    repo = FakeUserRepository([user])

    with pytest.raises(InvalidCredentialsError):
        ChangePasswordUseCase(repo, FakeTokenBlacklistService()).execute(
            user_id=user.id,
            current_password="WrongPass!",
            new_password="NewPass99!",
        )


def test_change_password_old_password_no_longer_valid():
    """After changing, the old password no longer matches."""
    user = _user_with_password("OldPass1!")
    repo = FakeUserRepository([user])

    ChangePasswordUseCase(repo, FakeTokenBlacklistService()).execute(
        user_id=user.id,
        current_password="OldPass1!",
        new_password="NewPass99!",
    )

    assert not check_password("OldPass1!", repo.get_by_id(user.id).password_hash)
