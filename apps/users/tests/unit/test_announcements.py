"""Unit tests for announcement use cases."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from apps.users.application.use_cases.announcements import (
    CreateAnnouncementUseCase,
    ListAnnouncementsUseCase,
)
from apps.users.domain.entities import AnnouncementEntity
from apps.users.domain.exceptions import AnnouncementNotFoundError
from apps.users.domain.repositories import IAnnouncementRepository


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _make_ann(**kwargs: object) -> AnnouncementEntity:
    """Build an AnnouncementEntity with sensible defaults."""
    defaults: dict = {
        "id": uuid.uuid4(),
        "title": "Test Announcement",
        "body": "This is the body.",
        "target_plans": [],
        "is_active": True,
        "created_at": _now(),
    }
    defaults.update(kwargs)
    return AnnouncementEntity(**defaults)  # type: ignore[arg-type]


class FakeAnnouncementRepository(IAnnouncementRepository):
    """In-memory announcement store for unit tests."""

    def __init__(self, items: list[AnnouncementEntity] | None = None) -> None:
        self._store: dict[uuid.UUID, AnnouncementEntity] = {a.id: a for a in (items or [])}

    def list_all(self) -> list[AnnouncementEntity]:
        return list(self._store.values())

    def get_by_id(self, announcement_id: uuid.UUID) -> AnnouncementEntity:
        try:
            return self._store[announcement_id]
        except KeyError:
            raise AnnouncementNotFoundError("Announcement not found.")

    def create(self, entity: AnnouncementEntity) -> AnnouncementEntity:
        self._store[entity.id] = entity
        return entity


def test_list_announcements_returns_all() -> None:
    """ListAnnouncementsUseCase returns every announcement."""
    repo = FakeAnnouncementRepository([_make_ann(), _make_ann()])
    result = ListAnnouncementsUseCase(repo).execute()
    assert len(result) == 2


def test_list_announcements_returns_empty_when_none() -> None:
    """ListAnnouncementsUseCase returns an empty list when no announcements exist."""
    result = ListAnnouncementsUseCase(FakeAnnouncementRepository()).execute()
    assert result == []


def test_create_announcement_persists_and_returns() -> None:
    """CreateAnnouncementUseCase stores the announcement and returns it."""
    repo = FakeAnnouncementRepository()
    result = CreateAnnouncementUseCase(repo).execute(
        title="Scheduled maintenance",
        body="The platform will be down for maintenance.",
        target_plans=["pro", "enterprise"],
        is_active=False,
        scheduled_at=_now() + timedelta(days=1),
    )
    assert result.title == "Scheduled maintenance"
    assert result.target_plans == ["pro", "enterprise"]
    assert result.is_active is False
    assert result.scheduled_at is not None
    assert repo.get_by_id(result.id).title == "Scheduled maintenance"


def test_create_announcement_no_schedule() -> None:
    """CreateAnnouncementUseCase works without a scheduled_at date."""
    repo = FakeAnnouncementRepository()
    result = CreateAnnouncementUseCase(repo).execute(
        title="Immediate notice",
        body="Something happened.",
        target_plans=[],
        is_active=True,
        scheduled_at=None,
    )
    assert result.scheduled_at is None
    assert result.is_active is True


def test_create_announcement_sets_published_at_when_active() -> None:
    """CreateAnnouncementUseCase sets published_at only when is_active=True."""
    repo = FakeAnnouncementRepository()
    active = CreateAnnouncementUseCase(repo).execute(title="Active", body="body", target_plans=[], is_active=True, scheduled_at=None)
    inactive = CreateAnnouncementUseCase(repo).execute(title="Draft", body="body", target_plans=[], is_active=False, scheduled_at=None)
    assert active.published_at is not None
    assert inactive.published_at is None
