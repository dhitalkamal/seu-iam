"""Unit tests for GithubTokenVerifier (mocks HTTP calls to GitHub API)."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from apps.users.domain.exceptions import SocialAuthError
from apps.users.infrastructure.github_verifier import GithubTokenVerifier


def _mock_response(json_data: object, status_code: int = 200) -> MagicMock:
    mock = MagicMock()
    mock.status_code = status_code
    mock.json.return_value = json_data
    mock.raise_for_status = MagicMock()
    if status_code >= 400:
        from requests.exceptions import HTTPError

        mock.raise_for_status.side_effect = HTTPError(response=mock)
    return mock


_USER_RESPONSE = {
    "login": "ghuser",
    "name": "Github User",
    "avatar_url": "https://avatars.githubusercontent.com/u/12345",
    "email": None,
}

_EMAILS_RESPONSE = [
    {"email": "private@users.noreply.github.com", "primary": False, "verified": True},
    {"email": "github.user@example.com", "primary": True, "verified": True},
]


@patch("apps.users.infrastructure.github_verifier.requests.get")
def test_verifier_returns_profile_dict(mock_get: MagicMock) -> None:
    """Returns a dict with email, name, and avatar_url for a valid token."""
    mock_get.side_effect = [
        _mock_response(_USER_RESPONSE),
        _mock_response(_EMAILS_RESPONSE),
    ]

    result = GithubTokenVerifier().verify("valid-token")

    assert result["email"] == "github.user@example.com"
    assert result["name"] == "Github User"
    assert result["avatar_url"] == "https://avatars.githubusercontent.com/u/12345"


@patch("apps.users.infrastructure.github_verifier.requests.get")
def test_verifier_raises_on_401(mock_get: MagicMock) -> None:
    """SocialAuthError when GitHub rejects the access token."""
    mock_get.return_value = _mock_response({}, status_code=401)

    with pytest.raises(SocialAuthError):
        GithubTokenVerifier().verify("bad-token")


@patch("apps.users.infrastructure.github_verifier.requests.get")
def test_verifier_raises_when_no_verified_email(mock_get: MagicMock) -> None:
    """SocialAuthError when the account has no verified primary email."""
    mock_get.side_effect = [
        _mock_response(_USER_RESPONSE),
        _mock_response([{"email": "x@example.com", "primary": True, "verified": False}]),
    ]

    with pytest.raises(SocialAuthError):
        GithubTokenVerifier().verify("valid-token")
