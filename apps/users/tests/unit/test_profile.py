"""Unit tests for GetProfileUseCase and UpdateProfileUseCase. No database, hand-rolled fakes."""

from __future__ import annotations

import uuid

import pytest

from apps.users.application.use_cases.profile import GetProfileUseCase, UpdateProfileUseCase
from apps.users.domain.exceptions import UserNotFoundError
from apps.users.tests.unit.fakes import FakeUserRepository, make_user


def test_get_profile_returns_the_correct_user():
    """GetProfileUseCase returns the entity matching the given user ID."""
    user = make_user(first_name="Kamal", last_name="Dhital")
    entity = GetProfileUseCase(FakeUserRepository([user])).execute(user.id)

    assert entity.id == user.id
    assert entity.first_name == "Kamal"
    assert entity.last_name == "Dhital"


def test_get_profile_unknown_id_raises():
    """GetProfileUseCase raises UserNotFoundError when the ID does not exist."""
    with pytest.raises(UserNotFoundError):
        GetProfileUseCase(FakeUserRepository()).execute(uuid.uuid4())


def test_update_profile_changes_first_name():
    """UpdateProfileUseCase updates only the provided first_name."""
    user = make_user(first_name="Old", last_name="Name")
    repo = FakeUserRepository([user])

    updated = UpdateProfileUseCase(repo).execute(user.id, first_name="New")

    assert updated.first_name == "New"
    assert updated.last_name == "Name"


def test_update_profile_changes_last_name():
    """UpdateProfileUseCase updates only the provided last_name."""
    user = make_user(first_name="Kamal", last_name="Old")
    repo = FakeUserRepository([user])

    updated = UpdateProfileUseCase(repo).execute(user.id, last_name="Dhital")

    assert updated.first_name == "Kamal"
    assert updated.last_name == "Dhital"


def test_update_profile_changes_avatar_url():
    """UpdateProfileUseCase updates only the provided avatar_url."""
    user = make_user()
    repo = FakeUserRepository([user])

    updated = UpdateProfileUseCase(repo).execute(
        user.id, avatar_url="https://cdn.example.com/pic.png"
    )

    assert updated.avatar_url == "https://cdn.example.com/pic.png"


def test_update_profile_none_fields_are_not_changed():
    """Fields passed as None are left unchanged."""
    user = make_user(first_name="Keep", last_name="This", avatar_url="https://example.com/a.png")
    repo = FakeUserRepository([user])

    updated = UpdateProfileUseCase(repo).execute(user.id, last_name="Changed")

    assert updated.first_name == "Keep"
    assert updated.avatar_url == "https://example.com/a.png"
    assert updated.last_name == "Changed"


def test_update_profile_persists_to_repository():
    """The updated entity is stored back in the repository."""
    user = make_user()
    repo = FakeUserRepository([user])

    UpdateProfileUseCase(repo).execute(user.id, first_name="Saved")

    assert repo.get_by_email(user.email).first_name == "Saved"
