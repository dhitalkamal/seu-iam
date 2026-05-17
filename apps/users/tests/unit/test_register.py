"""Unit tests for user registration -- no database, hand-rolled fakes."""

from __future__ import annotations

import pytest

from apps.users.application.use_cases.register import RegisterUseCase
from apps.users.domain.exceptions import UserAlreadyExistsError
from apps.users.tests.unit.fakes import FakeUserRepository, make_user


def test_register_returns_user_with_correct_fields():
    """Registered user has the submitted email, names, and unverified status."""
    repo = FakeUserRepository()
    user = RegisterUseCase(repo).execute("kamal@example.com", "StrongPass1!", "Kamal", "Dhital")

    assert user.email == "kamal@example.com"
    assert user.first_name == "Kamal"
    assert user.last_name == "Dhital"
    assert user.is_email_verified is False
    assert user.is_active is True
    assert user.mfa_enabled is False


def test_register_password_is_hashed():
    """The stored password_hash must never equal the plaintext password."""
    repo = FakeUserRepository()
    user = RegisterUseCase(repo).execute("a@b.com", "StrongPass1!", "A", "B")

    assert user.password_hash != "StrongPass1!"
    assert user.password_hash.startswith("pbkdf2_")


def test_register_email_is_lowercased_and_trimmed():
    """Emails are normalised to lowercase with whitespace stripped."""
    repo = FakeUserRepository()
    user = RegisterUseCase(repo).execute("  UPPER@Example.COM  ", "StrongPass1!", "X", "Y")

    assert user.email == "upper@example.com"


def test_register_duplicate_email_raises():
    """Registering with an already-taken email raises UserAlreadyExistsError."""
    repo = FakeUserRepository([make_user(email="taken@example.com")])

    with pytest.raises(UserAlreadyExistsError):
        RegisterUseCase(repo).execute("taken@example.com", "StrongPass1!", "A", "B")


def test_register_persists_user_in_repository():
    """The returned user is actually stored and retrievable from the repo."""
    repo = FakeUserRepository()
    user = RegisterUseCase(repo).execute("stored@example.com", "StrongPass1!", "S", "T")

    found = repo.get_by_email("stored@example.com")
    assert found.id == user.id
