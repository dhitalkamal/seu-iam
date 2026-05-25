"""Tests for the AnnouncementModel ORM model."""

from __future__ import annotations

import pytest


@pytest.mark.django_db
def test_announcement_model_db_table() -> None:
    """AnnouncementModel maps to the announcements table."""
    from apps.users.infrastructure.announcement_models import AnnouncementModel

    assert AnnouncementModel._meta.db_table == "announcements"


@pytest.mark.django_db
def test_announcement_model_create() -> None:
    """AnnouncementModel can persist a row with default values."""
    from apps.users.infrastructure.announcement_models import AnnouncementModel

    m = AnnouncementModel.objects.create(title="Test", body="Body text.")
    assert m.pk is not None
    assert m.is_active is False
    assert m.target_plans == []
    assert m.scheduled_at is None
