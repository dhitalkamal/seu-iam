"""Re-export ORM models so Django's app registry finds them under the users label."""

from __future__ import annotations

from apps.users.infrastructure.models import User

__all__ = ["User"]
