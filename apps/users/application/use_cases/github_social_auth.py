"""Use case: sign in or register via GitHub OAuth access token."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timezone

from django.contrib.auth.hashers import make_password

from apps.users.domain.entities import UserEntity
from apps.users.domain.exceptions import AccountInactiveError
from apps.users.domain.repositories import IGithubTokenVerifier, ITokenService, IUserRepository


@dataclass(frozen=True)
class GithubSocialAuthResult:
    """Tokens and registration status returned after GitHub sign-in."""

    access_token: str
    refresh_token: str
    is_new_user: bool


class GithubSocialAuthUseCase:
    """Verify a GitHub access token, then create or log in the matching user."""

    def __init__(
        self,
        user_repo: IUserRepository,
        github_verifier: IGithubTokenVerifier,
        token_service: ITokenService,
    ) -> None:
        self._users = user_repo
        self._verifier = github_verifier
        self._tokens = token_service

    def execute(self, access_token: str) -> GithubSocialAuthResult:
        """
        Fetch GitHub profile, then return JWT tokens for the corresponding account.

        Creates a new account on first sign-in. Links to an existing account
        if the email is already registered.

        @param access_token - the OAuth access token returned by GitHub
        @returns GithubSocialAuthResult with tokens and is_new_user flag
        @raises SocialAuthError if the token is invalid or the profile has no email
        @raises AccountInactiveError if the matched account has been deactivated
        """
        payload = self._verifier.verify(access_token)

        email = payload["email"].lower().strip()
        is_new_user = False

        if self._users.exists_by_email(email):
            user = self._users.get_by_email(email)
            if not user.is_active:
                raise AccountInactiveError("This account has been deactivated.")
        else:
            name_parts = (payload.get("name") or "").split(" ", 1)
            first_name = name_parts[0]
            last_name = name_parts[1] if len(name_parts) > 1 else ""

            now = datetime.now(timezone.utc)
            user = self._users.create(
                UserEntity(
                    id=uuid.uuid4(),
                    email=email,
                    first_name=first_name,
                    last_name=last_name,
                    password_hash=make_password(None),
                    is_email_verified=True,
                    is_active=True,
                    is_staff=False,
                    is_superuser=False,
                    mfa_enabled=False,
                    failed_login_attempts=0,
                    date_joined=now,
                    updated_at=now,
                    avatar_url=payload.get("avatar_url"),
                )
            )
            is_new_user = True

        access_token_str, refresh_token = self._tokens.generate_for_user(user.id)
        return GithubSocialAuthResult(
            access_token=access_token_str,
            refresh_token=refresh_token,
            is_new_user=is_new_user,
        )
