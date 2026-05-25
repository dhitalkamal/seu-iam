"""Integration tests for the Django announcement repository."""

from __future__ import annotations

import uuid

import pytest

from apps.users.domain.entities import AnnouncementEntity
from apps.users.domain.exceptions import AnnouncementNotFoundError


@pytest.mark.django_db
def test_create_and_retrieve_announcement() -> None:
    """DjangoAnnouncementRepository persists and retrieves an announcement by ID."""
    from datetime import datetime, timezone

    from apps.users.infrastructure.announcement_repository import DjangoAnnouncementRepository

    now = datetime.now(timezone.utc)
    repo = DjangoAnnouncementRepository()
    ann_id = uuid.uuid4()
    entity = AnnouncementEntity(
        id=ann_id,
        title="Welcome",
        body="Hello platform!",
        target_plans=["pro"],
        is_active=True,
        created_at=now,
        published_at=now,
    )
    created = repo.create(entity)
    assert created.title == "Welcome"
    assert created.is_active is True

    fetched = repo.get_by_id(ann_id)
    assert fetched.title == "Welcome"
    assert fetched.target_plans == ["pro"]


@pytest.mark.django_db
def test_get_by_id_raises_when_missing() -> None:
    """DjangoAnnouncementRepository raises AnnouncementNotFoundError for unknown id."""
    from apps.users.infrastructure.announcement_repository import DjangoAnnouncementRepository

    with pytest.raises(AnnouncementNotFoundError):
        DjangoAnnouncementRepository().get_by_id(uuid.uuid4())


@pytest.mark.django_db
def test_list_all_announcements() -> None:
    """DjangoAnnouncementRepository.list_all returns all rows."""
    from datetime import datetime, timezone

    from apps.users.infrastructure.announcement_repository import DjangoAnnouncementRepository

    now = datetime.now(timezone.utc)
    repo = DjangoAnnouncementRepository()
    for title in ("A", "B", "C"):
        repo.create(
            AnnouncementEntity(
                id=uuid.uuid4(),
                title=title,
                body="body",
                target_plans=[],
                is_active=False,
                created_at=now,
            )
        )
    assert len(repo.list_all()) == 3
