"""Integration tests for the Django feature flag repository."""

from __future__ import annotations

import pytest

from apps.users.domain.entities import FeatureFlagEntity
from apps.users.domain.exceptions import FeatureFlagNotFoundError


@pytest.mark.django_db
def test_create_and_retrieve_flag() -> None:
    """DjangoFeatureFlagRepository persists and retrieves a flag by key."""
    from datetime import datetime, timezone

    from apps.users.infrastructure.feature_flag_models import FeatureFlagModel  # noqa: F401
    from apps.users.infrastructure.feature_flag_repository import DjangoFeatureFlagRepository

    now = datetime.now(timezone.utc)
    repo = DjangoFeatureFlagRepository()
    entity = FeatureFlagEntity(
        key="test_flag",
        name="Test Flag",
        description="",
        is_enabled=True,
        enabled_plans=["pro"],
        enabled_org_ids=[],
        created_at=now,
        updated_at=now,
    )
    created = repo.create(entity)
    assert created.key == "test_flag"
    assert created.is_enabled is True

    fetched = repo.get_by_key("test_flag")
    assert fetched.key == "test_flag"
    assert fetched.enabled_plans == ["pro"]


@pytest.mark.django_db
def test_get_by_key_raises_when_missing() -> None:
    """DjangoFeatureFlagRepository raises FeatureFlagNotFoundError for unknown key."""
    from apps.users.infrastructure.feature_flag_repository import DjangoFeatureFlagRepository

    with pytest.raises(FeatureFlagNotFoundError):
        DjangoFeatureFlagRepository().get_by_key("nonexistent")


@pytest.mark.django_db
def test_exists_by_key() -> None:
    """DjangoFeatureFlagRepository.exists_by_key returns True only when the flag is present."""
    from datetime import datetime, timezone

    from apps.users.infrastructure.feature_flag_models import FeatureFlagModel  # noqa: F401
    from apps.users.infrastructure.feature_flag_repository import DjangoFeatureFlagRepository

    now = datetime.now(timezone.utc)
    repo = DjangoFeatureFlagRepository()
    assert not repo.exists_by_key("flag_x")

    entity = FeatureFlagEntity(
        key="flag_x",
        name="Flag X",
        description="",
        is_enabled=False,
        enabled_plans=[],
        enabled_org_ids=[],
        created_at=now,
        updated_at=now,
    )
    repo.create(entity)
    assert repo.exists_by_key("flag_x")


@pytest.mark.django_db
def test_update_flag() -> None:
    """DjangoFeatureFlagRepository.update overwrites mutable columns."""
    from datetime import datetime, timezone

    from apps.users.infrastructure.feature_flag_repository import DjangoFeatureFlagRepository

    now = datetime.now(timezone.utc)
    repo = DjangoFeatureFlagRepository()
    entity = FeatureFlagEntity(
        key="upd_flag",
        name="Original",
        description="",
        is_enabled=False,
        enabled_plans=[],
        enabled_org_ids=[],
        created_at=now,
        updated_at=now,
    )
    repo.create(entity)

    entity.name = "Updated"
    entity.is_enabled = True
    entity.enabled_plans = ["enterprise"]
    result = repo.update(entity)
    assert result.name == "Updated"
    assert result.is_enabled is True
    assert result.enabled_plans == ["enterprise"]


@pytest.mark.django_db
def test_delete_flag() -> None:
    """DjangoFeatureFlagRepository.delete removes the row."""
    from datetime import datetime, timezone

    from apps.users.infrastructure.feature_flag_repository import DjangoFeatureFlagRepository

    now = datetime.now(timezone.utc)
    repo = DjangoFeatureFlagRepository()
    entity = FeatureFlagEntity(
        key="del_flag",
        name="To Delete",
        description="",
        is_enabled=False,
        enabled_plans=[],
        enabled_org_ids=[],
        created_at=now,
        updated_at=now,
    )
    repo.create(entity)
    repo.delete("del_flag")
    assert not repo.exists_by_key("del_flag")


@pytest.mark.django_db
def test_list_all_flags() -> None:
    """DjangoFeatureFlagRepository.list_all returns all rows."""
    from datetime import datetime, timezone

    from apps.users.infrastructure.feature_flag_repository import DjangoFeatureFlagRepository

    now = datetime.now(timezone.utc)
    repo = DjangoFeatureFlagRepository()
    for key in ("aa", "bb", "cc"):
        repo.create(
            FeatureFlagEntity(
                key=key,
                name=key,
                description="",
                is_enabled=False,
                enabled_plans=[],
                enabled_org_ids=[],
                created_at=now,
                updated_at=now,
            )
        )
    assert len(repo.list_all()) == 3
