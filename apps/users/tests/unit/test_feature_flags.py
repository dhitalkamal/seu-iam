"""Unit tests for feature flag use cases."""

from __future__ import annotations

from datetime import datetime, timezone

from apps.users.application.use_cases.feature_flags import (
    CreateFeatureFlagUseCase,
    DeleteFeatureFlagUseCase,
    ListFeatureFlagsUseCase,
    UpdateFeatureFlagUseCase,
)
from apps.users.domain.entities import FeatureFlagEntity
from apps.users.domain.exceptions import (
    FeatureFlagAlreadyExistsError,
    FeatureFlagNotFoundError,
)
from apps.users.domain.repositories import IFeatureFlagRepository


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _make_flag(**kwargs: object) -> FeatureFlagEntity:
    """Build a FeatureFlagEntity with sensible defaults."""
    now = _now()
    defaults: dict = {
        "key": "test_flag",
        "name": "Test Flag",
        "description": "",
        "is_enabled": False,
        "enabled_plans": [],
        "enabled_org_ids": [],
        "created_at": now,
        "updated_at": now,
    }
    defaults.update(kwargs)
    return FeatureFlagEntity(**defaults)  # type: ignore[arg-type]


class FakeFeatureFlagRepository(IFeatureFlagRepository):
    """In-memory feature flag store for unit tests."""

    def __init__(self, flags: list[FeatureFlagEntity] | None = None) -> None:
        self._store: dict[str, FeatureFlagEntity] = {f.key: f for f in (flags or [])}

    def list_all(self) -> list[FeatureFlagEntity]:
        return list(self._store.values())

    def get_by_key(self, key: str) -> FeatureFlagEntity:
        try:
            return self._store[key]
        except KeyError:
            raise FeatureFlagNotFoundError("Feature flag not found.")

    def exists_by_key(self, key: str) -> bool:
        return key in self._store

    def create(self, entity: FeatureFlagEntity) -> FeatureFlagEntity:
        self._store[entity.key] = entity
        return entity

    def update(self, entity: FeatureFlagEntity) -> FeatureFlagEntity:
        self._store[entity.key] = entity
        return entity

    def delete(self, key: str) -> None:
        self._store.pop(key, None)


def test_list_flags_returns_all() -> None:
    """ListFeatureFlagsUseCase returns every flag in the repository."""
    repo = FakeFeatureFlagRepository([_make_flag(key="a"), _make_flag(key="b")])
    result = ListFeatureFlagsUseCase(repo).execute()
    assert len(result) == 2


def test_list_flags_returns_empty_when_none() -> None:
    """ListFeatureFlagsUseCase returns an empty list when no flags exist."""
    result = ListFeatureFlagsUseCase(FakeFeatureFlagRepository()).execute()
    assert result == []


def test_create_flag_persists_and_returns_entity() -> None:
    """CreateFeatureFlagUseCase stores a new flag and returns it."""
    repo = FakeFeatureFlagRepository()
    result = CreateFeatureFlagUseCase(repo).execute(
        key="early_access_ai",
        name="Early Access AI",
        description="Enables AI features for opted-in orgs.",
        is_enabled=True,
        enabled_plans=["pro", "enterprise"],
        enabled_org_ids=[],
    )
    assert result.key == "early_access_ai"
    assert result.is_enabled is True
    assert result.enabled_plans == ["pro", "enterprise"]
    assert repo.exists_by_key("early_access_ai")


def test_create_flag_raises_if_key_already_exists() -> None:
    """CreateFeatureFlagUseCase raises FeatureFlagAlreadyExistsError on duplicate key."""
    repo = FakeFeatureFlagRepository([_make_flag(key="dup")])
    try:
        CreateFeatureFlagUseCase(repo).execute(
            key="dup",
            name="Duplicate",
            description="",
            is_enabled=False,
            enabled_plans=[],
            enabled_org_ids=[],
        )
        assert False, "expected FeatureFlagAlreadyExistsError"
    except FeatureFlagAlreadyExistsError:
        pass


def test_update_flag_changes_fields() -> None:
    """UpdateFeatureFlagUseCase overwrites name, description, is_enabled, and plan lists."""
    repo = FakeFeatureFlagRepository([_make_flag(key="flag1", is_enabled=False)])
    result = UpdateFeatureFlagUseCase(repo).execute(
        key="flag1",
        name="Updated Name",
        description="new desc",
        is_enabled=True,
        enabled_plans=["pro"],
        enabled_org_ids=["org-123"],
    )
    assert result.is_enabled is True
    assert result.name == "Updated Name"
    assert result.enabled_plans == ["pro"]
    assert result.enabled_org_ids == ["org-123"]


def test_update_flag_raises_if_not_found() -> None:
    """UpdateFeatureFlagUseCase raises FeatureFlagNotFoundError when key is absent."""
    try:
        UpdateFeatureFlagUseCase(FakeFeatureFlagRepository()).execute(
            key="missing",
            name="x",
            description="",
            is_enabled=False,
            enabled_plans=[],
            enabled_org_ids=[],
        )
        assert False, "expected FeatureFlagNotFoundError"
    except FeatureFlagNotFoundError:
        pass


def test_delete_flag_removes_it() -> None:
    """DeleteFeatureFlagUseCase removes the flag from the repository."""
    repo = FakeFeatureFlagRepository([_make_flag(key="to_delete")])
    DeleteFeatureFlagUseCase(repo).execute(key="to_delete")
    assert not repo.exists_by_key("to_delete")


def test_delete_flag_raises_if_not_found() -> None:
    """DeleteFeatureFlagUseCase raises FeatureFlagNotFoundError when the key is absent."""
    try:
        DeleteFeatureFlagUseCase(FakeFeatureFlagRepository()).execute(key="missing")
        assert False, "expected FeatureFlagNotFoundError"
    except FeatureFlagNotFoundError:
        pass
