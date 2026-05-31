"""GitHub OAuth access token verification via the GitHub REST API."""

from __future__ import annotations

import requests
from requests.exceptions import HTTPError, RequestException

from apps.users.domain.exceptions import SocialAuthError
from apps.users.domain.repositories import IGithubTokenVerifier

_GITHUB_API = "https://api.github.com"


class GithubTokenVerifier(IGithubTokenVerifier):
    """Calls the GitHub REST API to exchange an access token for user profile data."""

    def verify(self, access_token: str) -> dict:
        """
        Fetch /user and /user/emails from GitHub, return the profile dict.

        Raises SocialAuthError on HTTP errors or when the account has no
        verified primary email.
        """
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/vnd.github+json",
        }
        try:
            user_resp = requests.get(f"{_GITHUB_API}/user", headers=headers)
            user_resp.raise_for_status()
            user_data = user_resp.json()

            emails_resp = requests.get(f"{_GITHUB_API}/user/emails", headers=headers)
            emails_resp.raise_for_status()
            emails = emails_resp.json()
        except (HTTPError, RequestException) as exc:
            raise SocialAuthError("GitHub token verification failed.") from exc

        primary_email = next(
            (e["email"] for e in emails if e.get("primary") and e.get("verified")),
            None,
        )
        if not primary_email:
            raise SocialAuthError("GitHub account has no verified primary email address.")

        return {
            "email": primary_email,
            "name": user_data.get("name") or "",
            "avatar_url": user_data.get("avatar_url"),
        }
