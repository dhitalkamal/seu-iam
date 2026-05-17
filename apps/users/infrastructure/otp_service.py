"""Redis-backed OTP storage for short-lived verification codes."""

from __future__ import annotations

import secrets
import string
import uuid

from django.conf import settings
from redis import Redis

from apps.users.domain.exceptions import OTPExpiredError, OTPInvalidError
from apps.users.domain.repositories import IOTPService

_ALPHABET = string.ascii_uppercase + string.digits


def _client() -> Redis:
    return Redis.from_url(settings.REDIS_URL, decode_responses=True)


class RedisOTPService(IOTPService):
    """Stores 8-char alphanumeric OTPs in Redis with a configurable TTL and namespace."""

    def __init__(self, namespace: str = "email_verify") -> None:
        self._namespace = namespace

    def _key(self, user_id: uuid.UUID) -> str:
        return f"otp:{self._namespace}:{user_id}"

    def generate_and_store(self, user_id: uuid.UUID) -> str:
        """Generate a cryptographically random OTP and persist it with a 10-minute TTL."""
        otp = "".join(secrets.choice(_ALPHABET) for _ in range(8))
        _client().setex(self._key(user_id), settings.OTP_TTL_SECONDS, otp)
        return otp

    def verify_and_consume(self, user_id: uuid.UUID, otp: str) -> None:
        """Validate the OTP and delete it. Raises on expiry or mismatch."""
        client = _client()
        key = self._key(user_id)
        stored = client.get(key)
        if stored is None:
            raise OTPExpiredError("OTP has expired or was never issued.")
        if stored != otp:
            raise OTPInvalidError("OTP does not match.")
        client.delete(key)
