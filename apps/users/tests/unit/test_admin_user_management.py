"""Unit tests for ListUsersUseCase, SuspendUserUseCase, ActivateUserUseCase."""

from __future__ import annotations

import uuid

import pytest

from apps.users.application.use_cases.admin_user_management import (
    ActivateUserUseCase,
    ListUsersUseCase,
    SuspendUserUseCase,
)
from apps.users.domain.exceptions import UserNotFoundError
from apps.users.tests.unit.fakes import FakeUserRepository, make_user


def test_list_users_returns_all():
    """ListUsersUseCase returns all non-deleted users."""
    users = [make_user(email=f"u{i}@test.com") for i in range(5)]
    repo = FakeUserRepository(users)
    result = ListUsersUseCase(repo).execute()
    assert len(result) == 5


def test_list_users_excludes_deleted():
    """ListUsersUseCase excludes soft-deleted users."""
    from datetime import datetime, timezone

    active = make_user(email="active@test.com")
    deleted = make_user(email="deleted@test.com", deleted_at=datetime.now(timezone.utc))
    repo = FakeUserRepository([active, deleted])
    result = ListUsersUseCase(repo).execute()
    assert len(result) == 1
    assert result[0].email == "active@test.com"


def test_suspend_user_sets_is_active_false():
    """SuspendUserUseCase sets is_active=False on the target user."""
    user = make_user(is_active=True)
    repo = FakeUserRepository([user])
    SuspendUserUseCase(repo).execute(user_id=user.id)
    assert repo.get_by_id(user.id).is_active is False


def test_suspend_missing_user_raises():
    """SuspendUserUseCase raises UserNotFoundError when user does not exist."""
    repo = FakeUserRepository()
    with pytest.raises(UserNotFoundError):
        SuspendUserUseCase(repo).execute(user_id=uuid.uuid4())


def test_activate_user_sets_is_active_true():
    """ActivateUserUseCase sets is_active=True on a suspended user."""
    user = make_user(is_active=False)
    repo = FakeUserRepository([user])
    ActivateUserUseCase(repo).execute(user_id=user.id)
    assert repo.get_by_id(user.id).is_active is True


def test_activate_missing_user_raises():
    """ActivateUserUseCase raises UserNotFoundError when user does not exist."""
    repo = FakeUserRepository()
    with pytest.raises(UserNotFoundError):
        ActivateUserUseCase(repo).execute(user_id=uuid.uuid4())
