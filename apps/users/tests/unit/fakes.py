"""Hand-rolled in-memory fakes for all repository interfaces."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from apps.users.domain.entities import UserEntity
from apps.users.domain.exceptions import UserNotFoundError
from apps.users.domain.repositories import IUserRepository


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
