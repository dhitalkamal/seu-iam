"""Service for checking and recording password history."""

from __future__ import annotations

import uuid

from django.conf import settings
from django.contrib.auth.hashers import check_password

from apps.users.domain.exceptions import WeakPasswordError
from apps.users.domain.repositories import IPasswordHistoryService
from apps.users.infrastructure.password_history_models import PasswordHistory

_DEFAULT_MAX_HISTORY = 5


def _max() -> int:
    return getattr(settings, "PASSWORD_HISTORY_LIMIT", _DEFAULT_MAX_HISTORY)


class PasswordHistoryService(IPasswordHistoryService):
    """Checks new passwords against history and records them after a successful change."""

    def check(self, user_id: uuid.UUID, new_password: str) -> None:
        """Raise WeakPasswordError if new_password matches any of the last N stored hashes."""
        recent = PasswordHistory.objects.filter(user_id=user_id).order_by("-created_at")[: _max()]
        for entry in recent:
            if check_password(new_password, entry.password_hash):
                raise WeakPasswordError(f"You cannot reuse any of your last {_max()} passwords.")

    def record(self, user_id: uuid.UUID, password_hash: str) -> None:
        """Store the new hash and prune entries beyond the limit."""
        PasswordHistory.objects.create(user_id=user_id, password_hash=password_hash)
        ids_to_keep = list(
            PasswordHistory.objects.filter(user_id=user_id)
            .order_by("-created_at")
            .values_list("id", flat=True)[: _max()]
        )
        PasswordHistory.objects.filter(user_id=user_id).exclude(id__in=ids_to_keep).delete()
