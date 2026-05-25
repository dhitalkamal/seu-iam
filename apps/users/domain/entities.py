"""Pure Python domain entities for the IAM service with no framework dependencies."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime


@dataclass(slots=True)
class UserEntity:
    """Represents a platform user as a pure domain object."""

    id: uuid.UUID
    email: str
    first_name: str
    last_name: str
    password_hash: str
    is_email_verified: bool
    is_active: bool
    is_staff: bool
    is_superuser: bool
    mfa_enabled: bool
    failed_login_attempts: int
    date_joined: datetime
    updated_at: datetime
    avatar_url: str | None = None
    phone: str | None = None
    bio: str | None = None
    mfa_secret: str | None = None
    mfa_type: str | None = None
    locked_until: datetime | None = None
    deleted_at: datetime | None = None

    @property
    def full_name(self) -> str:
        """First and last name joined with a space."""
        return f"{self.first_name} {self.last_name}".strip()


@dataclass(slots=True)
class FeatureFlagEntity:
    """A named platform capability switch, togglable per plan or per org."""

    key: str
    name: str
    is_enabled: bool
    enabled_plans: list[str]
    enabled_org_ids: list[str]
    created_at: datetime
    updated_at: datetime
    description: str = ""


@dataclass(slots=True)
class AnnouncementEntity:
    """A platform-wide message broadcast to users, with optional scheduling."""

    id: uuid.UUID
    title: str
    body: str
    target_plans: list[str]
    is_active: bool
    created_at: datetime
    scheduled_at: datetime | None = None
    published_at: datetime | None = None
