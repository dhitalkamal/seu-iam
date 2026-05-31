"""Unit tests for the 30-day grace period on account deletion and reactivation."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest

from apps.users.application.use_cases.delete_account import DeleteAccountUseCase
from apps.users.application.use_cases.reactivate_account import ReactivateAccountUseCase
from apps.users.domain.exceptions import UserNotFoundError
from apps.users.tests.unit.fakes import FakeTokenBlacklistService, FakeUserRepository, make_user


def _now() -> datetime:
    return datetime.now(timezone.utc)


class TestGracePeriodDeletion:
    """delete_account schedules deletion 30 days out instead of hard-deleting."""

    def test_delete_sets_scheduled_deletion_at_30_days_from_now(self):
        """scheduled_deletion_at must be approximately now + 30 days."""
        user = make_user()
        repo = FakeUserRepository([user])
        before = _now()

        DeleteAccountUseCase(repo, FakeTokenBlacklistService()).execute(user_id=user.id)

        after = _now()
        saved = repo.get_by_id(user.id)
        assert saved.scheduled_deletion_at is not None
        expected_low = before + timedelta(days=30)
        expected_high = after + timedelta(days=30)
        assert expected_low <= saved.scheduled_deletion_at <= expected_high

    def test_delete_sets_is_active_false(self):
        """Account is deactivated immediately on deletion request."""
        user = make_user()
        repo = FakeUserRepository([user])

        DeleteAccountUseCase(repo, FakeTokenBlacklistService()).execute(user_id=user.id)

        assert repo.get_by_id(user.id).is_active is False

    def test_delete_does_not_set_deleted_at(self):
        """deleted_at stays None; GDPR erasure only happens after the grace period."""
        user = make_user()
        repo = FakeUserRepository([user])

        DeleteAccountUseCase(repo, FakeTokenBlacklistService()).execute(user_id=user.id)

        assert repo.get_by_id(user.id).deleted_at is None

    def test_delete_blacklists_all_sessions(self):
        """All sessions must be invalidated on deletion request."""
        user = make_user()
        repo = FakeUserRepository([user])
        blacklist = FakeTokenBlacklistService()

        DeleteAccountUseCase(repo, blacklist).execute(user_id=user.id)

        assert user.id in blacklist.invalidated_users

    def test_delete_raises_for_unknown_user(self):
        """Deleting a non-existent user raises UserNotFoundError."""
        repo = FakeUserRepository()

        with pytest.raises(UserNotFoundError):
            DeleteAccountUseCase(repo, FakeTokenBlacklistService()).execute(user_id=uuid.uuid4())


class TestReactivateAccount:
    """reactivate_account clears the grace period and restores the account."""

    def test_reactivate_clears_scheduled_deletion_at(self):
        """After reactivation, scheduled_deletion_at is None."""
        scheduled = _now() + timedelta(days=20)
        user = make_user(is_active=False, scheduled_deletion_at=scheduled)
        repo = FakeUserRepository([user])

        ReactivateAccountUseCase(repo).execute(user_id=user.id)

        assert repo.get_by_id(user.id).scheduled_deletion_at is None

    def test_reactivate_sets_is_active_true(self):
        """Reactivated account has is_active set to True."""
        scheduled = _now() + timedelta(days=20)
        user = make_user(is_active=False, scheduled_deletion_at=scheduled)
        repo = FakeUserRepository([user])

        ReactivateAccountUseCase(repo).execute(user_id=user.id)

        assert repo.get_by_id(user.id).is_active is True

    def test_reactivate_raises_for_unknown_user(self):
        """Reactivating a non-existent user raises UserNotFoundError."""
        repo = FakeUserRepository()

        with pytest.raises(UserNotFoundError):
            ReactivateAccountUseCase(repo).execute(user_id=uuid.uuid4())
