"""JWT token generation service for the IAM infrastructure layer."""

from __future__ import annotations

import uuid

from rest_framework_simplejwt.tokens import RefreshToken

from apps.users.domain.repositories import ITokenService


class JWTTokenService(ITokenService):
    """Generates simplejwt access and refresh token pairs for a given user ID."""

    def generate_for_user(self, user_id: uuid.UUID) -> tuple[str, str]:
        """Return (access_token, refresh_token) strings for the user."""
        from apps.users.infrastructure.models import User

        user = User.objects.get(pk=user_id)
        refresh = RefreshToken.for_user(user)
        return str(refresh.access_token), str(refresh)
