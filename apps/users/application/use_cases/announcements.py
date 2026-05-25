"""Use cases for superadmin announcement management."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from apps.users.domain.entities import AnnouncementEntity
from apps.users.domain.repositories import IAnnouncementRepository


def _now() -> datetime:
    return datetime.now(timezone.utc)


class ListAnnouncementsUseCase:
    """Return all platform announcements."""

    def __init__(self, repo: IAnnouncementRepository) -> None:
        self._repo = repo

    def execute(self) -> list[AnnouncementEntity]:
        """Return every announcement, ordered by created_at descending."""
        return sorted(self._repo.list_all(), key=lambda a: a.created_at, reverse=True)


class CreateAnnouncementUseCase:
    """Create a new platform announcement."""

    def __init__(self, repo: IAnnouncementRepository) -> None:
        self._repo = repo

    def execute(
        self,
        *,
        title: str,
        body: str,
        target_plans: list[str],
        is_active: bool,
        scheduled_at: datetime | None,
    ) -> AnnouncementEntity:
        """
        Persist and return the announcement.

        Sets published_at to now when is_active=True; leaves it None for drafts.
        """
        now = _now()
        entity = AnnouncementEntity(
            id=uuid.uuid4(),
            title=title,
            body=body,
            target_plans=target_plans,
            is_active=is_active,
            created_at=now,
            scheduled_at=scheduled_at,
            published_at=now if is_active else None,
        )
        return self._repo.create(entity)
