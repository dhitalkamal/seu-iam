"""Unit tests for GitHub social authentication use case."""

from __future__ import annotations

import pytest

from apps.users.application.use_cases.github_social_auth import GithubSocialAuthUseCase
from apps.users.domain.exceptions import AccountInactiveError, SocialAuthError
from apps.users.domain.repositories import IGithubTokenVerifier
from apps.users.tests.unit.fakes import FakeTokenService, FakeUserRepository, make_user


class FakeGithubTokenVerifier(IGithubTokenVerifier):
    """Returns a fixed payload for the sentinel token; raises SocialAuthError otherwise."""

    VALID_TOKEN = "valid-github-token"
    PAYLOAD = {
        "email": "github.user@example.com",
        "name": "Github User",
        "avatar_url": "https://avatars.githubusercontent.com/u/12345",
    }

    def verify(self, access_token: str) -> dict:
        """Return the fixed payload or raise SocialAuthError for invalid tokens."""
        if access_token != self.VALID_TOKEN:
            raise SocialAuthError("Invalid GitHub access token.")
        return self.PAYLOAD


def test_github_auth_creates_new_user_for_unknown_email() -> None:
    """First-time GitHub sign-in creates a new verified account."""
    repo = FakeUserRepository()

    result = GithubSocialAuthUseCase(repo, FakeGithubTokenVerifier(), FakeTokenService()).execute(
        access_token=FakeGithubTokenVerifier.VALID_TOKEN
    )

    user = repo.get_by_email(FakeGithubTokenVerifier.PAYLOAD["email"])
    assert user.is_email_verified is True
    assert user.first_name == "Github"
    assert user.last_name == "User"
    assert user.avatar_url == FakeGithubTokenVerifier.PAYLOAD["avatar_url"]
    assert result.is_new_user is True


def test_github_auth_returns_tokens_for_new_user() -> None:
    """JWT tokens are returned after creating a new user via GitHub."""
    repo = FakeUserRepository()

    result = GithubSocialAuthUseCase(repo, FakeGithubTokenVerifier(), FakeTokenService()).execute(
        access_token=FakeGithubTokenVerifier.VALID_TOKEN
    )

    assert result.access_token is not None
    assert result.refresh_token is not None


def test_github_auth_links_existing_account_by_email() -> None:
    """GitHub sign-in with an email that already exists logs the user in."""
    existing = make_user(email=FakeGithubTokenVerifier.PAYLOAD["email"])
    repo = FakeUserRepository([existing])

    result = GithubSocialAuthUseCase(repo, FakeGithubTokenVerifier(), FakeTokenService()).execute(
        access_token=FakeGithubTokenVerifier.VALID_TOKEN
    )

    assert result.is_new_user is False
    assert result.access_token == f"access-{existing.id}"


def test_github_auth_raises_on_invalid_token() -> None:
    """An invalid or expired GitHub token raises SocialAuthError."""
    repo = FakeUserRepository()

    with pytest.raises(SocialAuthError):
        GithubSocialAuthUseCase(repo, FakeGithubTokenVerifier(), FakeTokenService()).execute(access_token="bad-token")


def test_github_auth_raises_for_inactive_account() -> None:
    """GitHub sign-in for a deactivated account raises AccountInactiveError."""
    inactive = make_user(email=FakeGithubTokenVerifier.PAYLOAD["email"], is_active=False)
    repo = FakeUserRepository([inactive])

    with pytest.raises(AccountInactiveError):
        GithubSocialAuthUseCase(repo, FakeGithubTokenVerifier(), FakeTokenService()).execute(
            access_token=FakeGithubTokenVerifier.VALID_TOKEN
        )


def test_github_auth_new_user_has_unusable_password() -> None:
    """New GitHub users have no usable password (cannot log in with email/password)."""
    repo = FakeUserRepository()

    GithubSocialAuthUseCase(repo, FakeGithubTokenVerifier(), FakeTokenService()).execute(access_token=FakeGithubTokenVerifier.VALID_TOKEN)

    user = repo.get_by_email(FakeGithubTokenVerifier.PAYLOAD["email"])
    assert user.password_hash.startswith("!")


def test_github_auth_single_name_word_uses_empty_last_name() -> None:
    """If GitHub name has only one word, last_name defaults to empty string."""

    class SingleNameVerifier(IGithubTokenVerifier):
        def verify(self, access_token: str) -> dict:
            return {"email": "mono@example.com", "name": "Mono", "avatar_url": None}

    repo = FakeUserRepository()
    GithubSocialAuthUseCase(repo, SingleNameVerifier(), FakeTokenService()).execute(access_token="any")

    user = repo.get_by_email("mono@example.com")
    assert user.first_name == "Mono"
    assert user.last_name == ""
