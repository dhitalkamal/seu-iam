"""JWT token generation and blacklist services for the IAM infrastructure layer."""

from __future__ import annotations

import uuid

from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.tokens import RefreshToken

from apps.users.domain.exceptions import InvalidTokenError
from apps.users.domain.repositories import ITokenBlacklistService, ITokenService


class JWTTokenService(ITokenService):
    """Generates simplejwt access and refresh token pairs for a given user ID."""

    def generate_for_user(self, user_id: uuid.UUID) -> tuple[str, str]:
        """Return (access_token, refresh_token) strings for the user."""
        from apps.users.infrastructure.models import User

        user = User.objects.get(pk=user_id)
        refresh = RefreshToken.for_user(user)
        return str(refresh.access_token), str(refresh)


class JWTTokenBlacklistService(ITokenBlacklistService):
    """Blacklists a refresh token using simplejwt's built-in blacklist."""

    def blacklist(self, refresh_token: str) -> None:
        """Add the token to the blacklist. Raises InvalidTokenError if the token is bad."""
        try:
            RefreshToken(refresh_token).blacklist()
        except TokenError as exc:
            raise InvalidTokenError(str(exc)) from exc

    def blacklist_all_for_user(self, user_id: uuid.UUID) -> None:
        """Blacklist every outstanding refresh token for the given user."""
        from rest_framework_simplejwt.token_blacklist.models import (
            BlacklistedToken,
            OutstandingToken,
        )

        tokens = OutstandingToken.objects.filter(user_id=user_id)
        for token in tokens:
            BlacklistedToken.objects.get_or_create(token=token)
