"""Unit tests for Google social authentication use case."""

from __future__ import annotations

import pytest

from apps.users.application.use_cases.google_social_auth import GoogleSocialAuthUseCase
from apps.users.domain.exceptions import AccountInactiveError, SocialAuthError
from apps.users.tests.unit.fakes import (
    FakeGoogleTokenVerifier,
    FakeTokenService,
    FakeUserRepository,
    make_user,
)


def test_google_auth_creates_new_user_for_unknown_email():
    """First-time Google sign-in creates a new verified account."""
    repo = FakeUserRepository()

    result = GoogleSocialAuthUseCase(repo, FakeGoogleTokenVerifier(), FakeTokenService()).execute(
        id_token=FakeGoogleTokenVerifier.VALID_TOKEN
    )

    user = repo.get_by_email(FakeGoogleTokenVerifier.PAYLOAD["email"])
    assert user.is_email_verified is True
    assert user.first_name == FakeGoogleTokenVerifier.PAYLOAD["given_name"]
    assert user.last_name == FakeGoogleTokenVerifier.PAYLOAD["family_name"]
    assert user.avatar_url == FakeGoogleTokenVerifier.PAYLOAD["picture"]
    assert result.is_new_user is True


def test_google_auth_returns_tokens_for_new_user():
    """JWT tokens are returned after creating a new user via Google."""
    repo = FakeUserRepository()

    result = GoogleSocialAuthUseCase(repo, FakeGoogleTokenVerifier(), FakeTokenService()).execute(
        id_token=FakeGoogleTokenVerifier.VALID_TOKEN
    )

    assert result.access_token is not None
    assert result.refresh_token is not None


def test_google_auth_links_existing_account_by_email():
    """Google sign-in with an email that already exists logs the user in."""
    existing = make_user(email=FakeGoogleTokenVerifier.PAYLOAD["email"])
    repo = FakeUserRepository([existing])

    result = GoogleSocialAuthUseCase(repo, FakeGoogleTokenVerifier(), FakeTokenService()).execute(
        id_token=FakeGoogleTokenVerifier.VALID_TOKEN
    )

    assert result.is_new_user is False
    assert result.access_token == f"access-{existing.id}"


def test_google_auth_raises_on_invalid_token():
    """An invalid or expired Google token raises SocialAuthError."""
    repo = FakeUserRepository()

    with pytest.raises(SocialAuthError):
        GoogleSocialAuthUseCase(repo, FakeGoogleTokenVerifier(), FakeTokenService()).execute(id_token="bad-token")


def test_google_auth_raises_for_inactive_account():
    """Google sign-in for a deactivated account raises AccountInactiveError."""
    inactive = make_user(email=FakeGoogleTokenVerifier.PAYLOAD["email"], is_active=False)
    repo = FakeUserRepository([inactive])

    with pytest.raises(AccountInactiveError):
        GoogleSocialAuthUseCase(repo, FakeGoogleTokenVerifier(), FakeTokenService()).execute(id_token=FakeGoogleTokenVerifier.VALID_TOKEN)


def test_google_auth_new_user_has_unusable_password():
    """New Google users have no usable password (cannot log in with email/password)."""
    repo = FakeUserRepository()

    GoogleSocialAuthUseCase(repo, FakeGoogleTokenVerifier(), FakeTokenService()).execute(id_token=FakeGoogleTokenVerifier.VALID_TOKEN)

    user = repo.get_by_email(FakeGoogleTokenVerifier.PAYLOAD["email"])
    assert user.password_hash.startswith("!")
