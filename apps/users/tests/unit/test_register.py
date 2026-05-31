"""Unit tests for user registration. no database, hand-rolled fakes."""

from __future__ import annotations

import pytest

from apps.users.application.use_cases.register import RegisterUseCase
from apps.users.domain.exceptions import UserAlreadyExistsError
from apps.users.tests.unit.fakes import (
    FakeEventPublisher,
    FakeOTPService,
    FakeUserRepository,
    make_user,
)


def _uc(repo: FakeUserRepository) -> RegisterUseCase:
    """Build a RegisterUseCase with stock fakes."""
    return RegisterUseCase(repo, FakeOTPService(), FakeEventPublisher())


def test_register_returns_user_with_correct_fields():
    """Registered user has the submitted email, names, and unverified status."""
    repo = FakeUserRepository()
    user = _uc(repo).execute("kamal@example.com", "StrongPass1!", "Kamal", "Dhital")

    assert user.email == "kamal@example.com"
    assert user.first_name == "Kamal"
    assert user.last_name == "Dhital"
    assert user.is_email_verified is False
    assert user.is_active is True
    assert user.mfa_enabled is False


def test_register_password_is_hashed():
    """The stored password_hash must never equal the plaintext password."""
    repo = FakeUserRepository()
    user = _uc(repo).execute("a@b.com", "StrongPass1!", "A", "B")

    assert user.password_hash != "StrongPass1!"
    assert user.password_hash.startswith("pbkdf2_")


def test_register_email_is_lowercased_and_trimmed():
    """Emails are normalised to lowercase with whitespace stripped."""
    repo = FakeUserRepository()
    user = _uc(repo).execute("  UPPER@Example.COM  ", "StrongPass1!", "X", "Y")

    assert user.email == "upper@example.com"


def test_register_duplicate_verified_email_raises():
    """Registering with a verified email raises UserAlreadyExistsError."""
    repo = FakeUserRepository([make_user(email="taken@example.com", is_email_verified=True)])

    with pytest.raises(UserAlreadyExistsError):
        _uc(repo).execute("taken@example.com", "StrongPass1!", "A", "B")


def test_register_unverified_email_resends_otp():
    """Re-registering with an unverified email resends the OTP and returns the existing user."""
    existing = make_user(email="stuck@example.com", is_email_verified=False)
    repo = FakeUserRepository([existing])
    publisher = FakeEventPublisher()

    result = RegisterUseCase(repo, FakeOTPService(), publisher).execute("stuck@example.com", "StrongPass1!", "A", "B")

    assert result.id == existing.id
    assert len(publisher.events) == 1
    event_name, payload = publisher.events[0]
    assert event_name == "iam.email_verification_requested"
    assert payload["email"] == existing.email


def test_register_unverified_email_does_not_create_duplicate():
    """Re-registering with an unverified email must not add a second record to the repo."""
    existing = make_user(email="stuck@example.com", is_email_verified=False)
    repo = FakeUserRepository([existing])

    _uc(repo).execute("stuck@example.com", "StrongPass1!", "A", "B")

    assert len(repo._store) == 1


def test_register_persists_user_in_repository():
    """The returned user is actually stored and retrievable from the repo."""
    repo = FakeUserRepository()
    user = _uc(repo).execute("stored@example.com", "StrongPass1!", "S", "T")

    found = repo.get_by_email("stored@example.com")
    assert found.id == user.id


def test_register_publishes_email_verification_event():
    """Registration fires an email_verification_requested event with email and OTP."""
    repo = FakeUserRepository()
    publisher = FakeEventPublisher()
    user = RegisterUseCase(repo, FakeOTPService(), publisher).execute("pub@example.com", "StrongPass1!", "P", "Q")

    assert len(publisher.events) == 1
    event_name, payload = publisher.events[0]
    assert event_name == "iam.email_verification_requested"
    assert payload["email"] == user.email
    assert payload["otp"] == FakeOTPService.FIXED_OTP


def test_register_generates_and_stores_otp():
    """An OTP is generated for the new user and stored in the OTP service."""
    repo = FakeUserRepository()
    otp_svc = FakeOTPService()
    user = RegisterUseCase(repo, otp_svc, FakeEventPublisher()).execute("otp@example.com", "StrongPass1!", "O", "P")

    assert user.id in otp_svc._store  # type: ignore[attr-defined]
