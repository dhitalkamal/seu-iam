"""Use case: sign in or register via Google ID token."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timezone

from django.contrib.auth.hashers import make_password

from apps.users.domain.entities import UserEntity
from apps.users.domain.exceptions import AccountInactiveError
from apps.users.domain.repositories import IGoogleTokenVerifier, ITokenService, IUserRepository


@dataclass(frozen=True)
class GoogleSocialAuthResult:
    """Tokens and registration status returned after Google sign-in."""

    access_token: str
    refresh_token: str
    is_new_user: bool


class GoogleSocialAuthUseCase:
    """Verify a Google ID token, then create or log in the matching user."""

    def __init__(
        self,
        user_repo: IUserRepository,
        google_verifier: IGoogleTokenVerifier,
        token_service: ITokenService,
    ) -> None:
        self._users = user_repo
        self._verifier = google_verifier
        self._tokens = token_service

    def execute(self, id_token: str) -> GoogleSocialAuthResult:
        """
        Verify the Google ID token and return JWT tokens for the corresponding account.

        Creates a new account on first sign-in. Links to an existing account
        if the email is already registered.

        @param id_token - the ID token returned by Google's client-side SDK
        @returns GoogleSocialAuthResult with tokens and is_new_user flag
        @raises SocialAuthError if the token is invalid or untrusted
        @raises AccountInactiveError if the matched account has been deactivated
        """
        payload = self._verifier.verify(id_token)

        email = payload["email"].lower().strip()
        is_new_user = False

        if self._users.exists_by_email(email):
            user = self._users.get_by_email(email)
            if not user.is_active:
                raise AccountInactiveError("This account has been deactivated.")
        else:
            now = datetime.now(timezone.utc)
            user = self._users.create(
                UserEntity(
                    id=uuid.uuid4(),
                    email=email,
                    first_name=payload.get("given_name", ""),
                    last_name=payload.get("family_name", ""),
                    password_hash=make_password(None),
                    is_email_verified=True,
                    is_active=True,
                    is_staff=False,
                    is_superuser=False,
                    mfa_enabled=False,
                    failed_login_attempts=0,
                    date_joined=now,
                    updated_at=now,
                    avatar_url=payload.get("picture"),
                )
            )
            is_new_user = True

        access_token, refresh_token = self._tokens.generate_for_user(user.id)
        return GoogleSocialAuthResult(
            access_token=access_token,
            refresh_token=refresh_token,
            is_new_user=is_new_user,
        )
