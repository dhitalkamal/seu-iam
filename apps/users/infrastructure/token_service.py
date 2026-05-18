"""JWT token generation and blacklist services for the IAM infrastructure layer."""

from __future__ import annotations

import uuid

from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.tokens import RefreshToken

from apps.users.domain.exceptions import InvalidTokenError
from apps.users.domain.repositories import ITokenBlacklistService, ITokenService


def extract_jti(refresh_token_str: str) -> uuid.UUID:
    """Parse a refresh token string and return its JTI claim as a UUID."""
    return uuid.UUID(RefreshToken(refresh_token_str)["jti"])


class JWTTokenService(ITokenService):
    """Generates simplejwt access and refresh token pairs for a given user ID."""

    def generate_for_user(self, user_id: uuid.UUID) -> tuple[str, str]:
        """Return (access_token, refresh_token) with email claim embedded.

        Email is added so downstream services can enforce domain-restricted
        events without a cross-service DB lookup.
        """
        from apps.users.infrastructure.models import User

        user = User.objects.get(pk=user_id)
        refresh = RefreshToken.for_user(user)
        refresh["email"] = user.email
        refresh.access_token["email"] = user.email
        return str(refresh.access_token), str(refresh)


class JWTTokenBlacklistService(ITokenBlacklistService):
    """Blacklists refresh tokens and revokes the matching UserSession records."""

    def blacklist(self, refresh_token: str) -> None:
        """Blacklist the token and mark its session inactive."""
        try:
            token = RefreshToken(refresh_token)
            jti = uuid.UUID(token["jti"])
            token.blacklist()
        except TokenError as exc:
            raise InvalidTokenError(str(exc)) from exc

        from apps.users.infrastructure.session_models import UserSession

        UserSession.objects.filter(jti=jti).update(is_active=False)

    def blacklist_all_for_user(self, user_id: uuid.UUID) -> None:
        """Blacklist every outstanding token and revoke all sessions for the user."""
        from rest_framework_simplejwt.token_blacklist.models import (
            BlacklistedToken,
            OutstandingToken,
        )

        tokens = OutstandingToken.objects.filter(user_id=user_id)
        for token in tokens:
            BlacklistedToken.objects.get_or_create(token=token)

        from apps.users.infrastructure.session_models import UserSession

        UserSession.objects.filter(user_id=user_id, is_active=True).update(is_active=False)
