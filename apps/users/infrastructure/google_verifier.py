"""Google ID token verification using google-auth."""

from __future__ import annotations

from django.conf import settings
from google.auth.exceptions import GoogleAuthError
from google.auth.transport import requests as google_requests
from google.oauth2 import id_token

from apps.users.domain.exceptions import SocialAuthError
from apps.users.domain.repositories import IGoogleTokenVerifier


class GoogleTokenVerifier(IGoogleTokenVerifier):
    """Verifies Google ID tokens against Google's public keys."""

    def verify(self, token: str) -> dict:
        """
        Validate the token audience and signature using Google's discovery document.

        Raises SocialAuthError if verification fails for any reason.
        """
        try:
            payload = id_token.verify_oauth2_token(
                token,
                google_requests.Request(),
                settings.GOOGLE_CLIENT_ID,
            )
        except (GoogleAuthError, ValueError) as exc:
            raise SocialAuthError("Google ID token verification failed.") from exc

        if not payload.get("email_verified"):
            raise SocialAuthError("Google account email is not verified.")

        return payload
