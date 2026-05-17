"""Hand-rolled in-memory fakes for all repository and service interfaces."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from apps.users.domain.entities import UserEntity
from apps.users.domain.exceptions import (
    InvalidTokenError,
    OTPExpiredError,
    OTPInvalidError,
    UserNotFoundError,
)
from apps.users.domain.repositories import (
    IEventPublisher,
    IOTPService,
    ITokenBlacklistService,
    ITokenService,
    IUserRepository,
)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def make_user(**kwargs: object) -> UserEntity:
    """Build a UserEntity with sensible defaults for testing."""
    now = _now()
    defaults: dict = {
        "id": uuid.uuid4(),
        "email": "test@example.com",
        "first_name": "Test",
        "last_name": "User",
        "password_hash": "pbkdf2_sha256$hashed",
        "is_email_verified": True,
        "is_active": True,
        "is_staff": False,
        "is_superuser": False,
        "mfa_enabled": False,
        "failed_login_attempts": 0,
        "date_joined": now,
        "updated_at": now,
    }
    defaults.update(kwargs)
    return UserEntity(**defaults)  # type: ignore[arg-type]


class FakeUserRepository(IUserRepository):
    """In-memory user store backed by a dict keyed on user.id."""

    def __init__(self, users: list[UserEntity] | None = None) -> None:
        self._store: dict[uuid.UUID, UserEntity] = {u.id: u for u in (users or [])}

    def get_by_id(self, user_id: uuid.UUID) -> UserEntity:
        """Return the user with this ID or raise UserNotFoundError."""
        try:
            return self._store[user_id]
        except KeyError:
            raise UserNotFoundError("User not found.")

    def get_by_email(self, email: str) -> UserEntity:
        """Return the user with this email or raise UserNotFoundError."""
        for u in self._store.values():
            if u.email == email:
                return u
        raise UserNotFoundError("User not found.")

    def exists_by_email(self, email: str) -> bool:
        """Return True if any user with this email exists."""
        return any(u.email == email for u in self._store.values())

    def create(self, entity: UserEntity) -> UserEntity:
        """Persist the entity and return it."""
        self._store[entity.id] = entity
        return entity

    def update(self, entity: UserEntity) -> UserEntity:
        """Persist updated fields and return the entity."""
        self._store[entity.id] = entity
        return entity


class FakeTokenService(ITokenService):
    """Returns predictable fake token strings for unit tests."""

    def generate_for_user(self, user_id: uuid.UUID) -> tuple[str, str]:
        """Return deterministic fake tokens keyed on the user ID."""
        return f"access-{user_id}", f"refresh-{user_id}"


class FakeTokenBlacklistService(ITokenBlacklistService):
    """Records blacklisted tokens. Raises InvalidTokenError on the sentinel 'invalid-token'."""

    def __init__(self) -> None:
        self.blacklisted: set[str] = set()

    def blacklist(self, refresh_token: str) -> None:
        """Add the token to the set, or raise if it equals the sentinel value."""
        if refresh_token == "invalid-token":
            raise InvalidTokenError("Token is invalid or already blacklisted.")
        self.blacklisted.add(refresh_token)

    def blacklist_all_for_user(self, user_id: uuid.UUID) -> None:
        """Record that all tokens for this user were invalidated."""
        self.invalidated_users: set[uuid.UUID] = getattr(self, "invalidated_users", set())
        self.invalidated_users.add(user_id)


class FakeOTPService(IOTPService):
    """Stores OTPs in memory. Returns a fixed OTP for deterministic tests."""

    FIXED_OTP = "ABCD1234"

    def __init__(self) -> None:
        self._store: dict[uuid.UUID, str] = {}

    def generate_and_store(self, user_id: uuid.UUID) -> str:
        """Store the fixed OTP for the user and return it."""
        self._store[user_id] = self.FIXED_OTP
        return self.FIXED_OTP

    def verify_and_consume(self, user_id: uuid.UUID, otp: str) -> None:
        """Raise OTPExpiredError if no OTP exists, OTPInvalidError if it does not match."""
        stored = self._store.get(user_id)
        if stored is None:
            raise OTPExpiredError("OTP has expired or was never issued.")
        if stored != otp:
            raise OTPInvalidError("OTP does not match.")
        del self._store[user_id]


class FakeEventPublisher(IEventPublisher):
    """Records published events for assertion in tests."""

    def __init__(self) -> None:
        self.events: list[tuple[str, dict]] = []

    def publish(self, event_name: str, payload: dict) -> None:
        """Append the event and payload to the recorded list."""
        self.events.append((event_name, payload))
