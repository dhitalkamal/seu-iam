"""Django ORM implementation of IAnnouncementRepository."""

from __future__ import annotations

import uuid

from apps.users.domain.entities import AnnouncementEntity
from apps.users.domain.exceptions import AnnouncementNotFoundError
from apps.users.domain.repositories import IAnnouncementRepository
from apps.users.infrastructure.announcement_models import AnnouncementModel


def _to_entity(m: AnnouncementModel) -> AnnouncementEntity:
    """Convert an ORM model instance to a domain entity."""
    return AnnouncementEntity(
        id=m.id,
        title=m.title,
        body=m.body,
        target_plans=list(m.target_plans),
        is_active=m.is_active,
        created_at=m.created_at,
        scheduled_at=m.scheduled_at,
        published_at=m.published_at,
    )


class DjangoAnnouncementRepository(IAnnouncementRepository):
    """Reads and writes Announcement rows via the Django ORM."""

    def list_all(self) -> list[AnnouncementEntity]:
        """Return all announcements ordered by created_at descending."""
        return [_to_entity(m) for m in AnnouncementModel.objects.all()]

    def get_by_id(self, announcement_id: uuid.UUID) -> AnnouncementEntity:
        """Return the announcement with this ID or raise AnnouncementNotFoundError."""
        try:
            return _to_entity(AnnouncementModel.objects.get(id=announcement_id))
        except AnnouncementModel.DoesNotExist:
            raise AnnouncementNotFoundError(f"Announcement '{announcement_id}' not found.")

    def create(self, entity: AnnouncementEntity) -> AnnouncementEntity:
        """Persist the announcement and return it with DB-populated created_at."""
        m = AnnouncementModel.objects.create(
            id=entity.id,
            title=entity.title,
            body=entity.body,
            target_plans=entity.target_plans,
            is_active=entity.is_active,
            scheduled_at=entity.scheduled_at,
            published_at=entity.published_at,
        )
        return _to_entity(m)
