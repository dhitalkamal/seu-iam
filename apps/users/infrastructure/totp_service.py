"""PyOTP-backed TOTP service for MFA secret generation and code verification."""

from __future__ import annotations

import pyotp

from apps.users.domain.repositories import ITOTPService

_ISSUER = "Sansaar: The Event Universe"


class PyOTPService(ITOTPService):
    """Generates TOTP secrets and verifies codes using the pyotp library."""

    def generate_secret(self) -> str:
        """Return a new cryptographically random base32 TOTP secret."""
        return pyotp.random_base32()

    def get_provisioning_uri(self, secret: str, email: str) -> str:
        """Return the otpauth:// URI for display in an authenticator app."""
        return pyotp.TOTP(secret).provisioning_uri(name=email, issuer_name=_ISSUER)

    def verify_code(self, secret: str, code: str) -> bool:
        """Return True if the 6-digit code is valid for the current 30-second window."""
        return pyotp.TOTP(secret).verify(code)
