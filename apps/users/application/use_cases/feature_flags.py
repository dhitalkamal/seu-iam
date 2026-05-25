"""Use cases for superadmin feature flag management."""

from __future__ import annotations

from datetime import datetime, timezone

from apps.users.domain.entities import FeatureFlagEntity
from apps.users.domain.exceptions import (
    FeatureFlagAlreadyExistsError,
    FeatureFlagNotFoundError,
)
from apps.users.domain.repositories import IFeatureFlagRepository


def _now() -> datetime:
    return datetime.now(timezone.utc)


class ListFeatureFlagsUseCase:
    """Return all platform feature flags."""

    def __init__(self, repo: IFeatureFlagRepository) -> None:
        self._repo = repo

    def execute(self) -> list[FeatureFlagEntity]:
        """Return every flag, ordered by key ascending."""
        return sorted(self._repo.list_all(), key=lambda f: f.key)


class CreateFeatureFlagUseCase:
    """Create a new platform feature flag. Key must be unique."""

    def __init__(self, repo: IFeatureFlagRepository) -> None:
        self._repo = repo

    def execute(
        self,
        *,
        key: str,
        name: str,
        description: str,
        is_enabled: bool,
        enabled_plans: list[str],
        enabled_org_ids: list[str],
    ) -> FeatureFlagEntity:
        """
        Persist and return the new flag.

        Raises FeatureFlagAlreadyExistsError if the key is already taken.
        """
        if self._repo.exists_by_key(key):
            raise FeatureFlagAlreadyExistsError(f"Feature flag '{key}' already exists.")
        now = _now()
        entity = FeatureFlagEntity(
            key=key,
            name=name,
            description=description,
            is_enabled=is_enabled,
            enabled_plans=enabled_plans,
            enabled_org_ids=enabled_org_ids,
            created_at=now,
            updated_at=now,
        )
        return self._repo.create(entity)


class UpdateFeatureFlagUseCase:
    """Update an existing feature flag's metadata and toggle state."""

    def __init__(self, repo: IFeatureFlagRepository) -> None:
        self._repo = repo

    def execute(
        self,
        *,
        key: str,
        name: str,
        description: str,
        is_enabled: bool,
        enabled_plans: list[str],
        enabled_org_ids: list[str],
    ) -> FeatureFlagEntity:
        """
        Overwrite all mutable fields on the flag.

        Raises FeatureFlagNotFoundError if the key does not exist.
        """
        flag = self._repo.get_by_key(key)
        flag.name = name
        flag.description = description
        flag.is_enabled = is_enabled
        flag.enabled_plans = enabled_plans
        flag.enabled_org_ids = enabled_org_ids
        flag.updated_at = _now()
        return self._repo.update(flag)


class DeleteFeatureFlagUseCase:
    """Remove a feature flag permanently."""

    def __init__(self, repo: IFeatureFlagRepository) -> None:
        self._repo = repo

    def execute(self, *, key: str) -> None:
        """
        Delete the flag.

        Raises FeatureFlagNotFoundError if it does not exist.
        """
        if not self._repo.exists_by_key(key):
            raise FeatureFlagNotFoundError(f"Feature flag '{key}' not found.")
        self._repo.delete(key)
