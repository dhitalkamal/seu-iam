"""Unit tests for the delete account use case."""

from __future__ import annotations

import pytest

from apps.users.application.use_cases.delete_account import DeleteAccountUseCase
from apps.users.domain.exceptions import UserNotFoundError
from apps.users.tests.unit.fakes import FakeTokenBlacklistService, FakeUserRepository, make_user


def test_delete_account_marks_user_inactive():
    """Deleted account has is_active set to False."""
    user = make_user()
    repo = FakeUserRepository([user])

    DeleteAccountUseCase(repo, FakeTokenBlacklistService()).execute(user_id=user.id)

    assert repo.get_by_id(user.id).is_active is False


def test_delete_account_sets_deleted_at():
    """Deleted account has deleted_at populated."""
    user = make_user()
    repo = FakeUserRepository([user])

    DeleteAccountUseCase(repo, FakeTokenBlacklistService()).execute(user_id=user.id)

    assert repo.get_by_id(user.id).deleted_at is not None


def test_delete_account_blacklists_all_sessions():
    """All sessions are invalidated when an account is deleted."""
    user = make_user()
    repo = FakeUserRepository([user])
    blacklist = FakeTokenBlacklistService()

    DeleteAccountUseCase(repo, blacklist).execute(user_id=user.id)

    assert user.id in blacklist.invalidated_users


def test_delete_account_raises_for_unknown_user():
    """Attempting to delete a non-existent user raises UserNotFoundError."""
    import uuid

    repo = FakeUserRepository()

    with pytest.raises(UserNotFoundError):
        DeleteAccountUseCase(repo, FakeTokenBlacklistService()).execute(user_id=uuid.uuid4())
