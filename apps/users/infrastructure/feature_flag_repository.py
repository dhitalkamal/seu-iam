"""Django ORM implementation of IFeatureFlagRepository."""

from __future__ import annotations

from apps.users.domain.entities import FeatureFlagEntity
from apps.users.domain.exceptions import FeatureFlagNotFoundError
from apps.users.domain.repositories import IFeatureFlagRepository
from apps.users.infrastructure.feature_flag_models import FeatureFlagModel


def _to_entity(m: FeatureFlagModel) -> FeatureFlagEntity:
    """Convert an ORM model instance to a domain entity."""
    return FeatureFlagEntity(
        key=m.key,
        name=m.name,
        description=m.description,
        is_enabled=m.is_enabled,
        enabled_plans=list(m.enabled_plans),
        enabled_org_ids=list(m.enabled_org_ids),
        created_at=m.created_at,
        updated_at=m.updated_at,
    )


class DjangoFeatureFlagRepository(IFeatureFlagRepository):
    """Reads and writes FeatureFlag rows via the Django ORM."""

    def list_all(self) -> list[FeatureFlagEntity]:
        """Return all flags ordered by key."""
        return [_to_entity(m) for m in FeatureFlagModel.objects.all()]

    def get_by_key(self, key: str) -> FeatureFlagEntity:
        """Return the flag with this key or raise FeatureFlagNotFoundError."""
        try:
            return _to_entity(FeatureFlagModel.objects.get(key=key))
        except FeatureFlagModel.DoesNotExist:
            raise FeatureFlagNotFoundError(f"Feature flag '{key}' not found.")

    def exists_by_key(self, key: str) -> bool:
        """Return True if a flag with this key exists."""
        return FeatureFlagModel.objects.filter(key=key).exists()

    def create(self, entity: FeatureFlagEntity) -> FeatureFlagEntity:
        """Persist a new flag and return the entity with DB-populated timestamps."""
        m = FeatureFlagModel.objects.create(
            key=entity.key,
            name=entity.name,
            description=entity.description,
            is_enabled=entity.is_enabled,
            enabled_plans=entity.enabled_plans,
            enabled_org_ids=entity.enabled_org_ids,
        )
        return _to_entity(m)

    def update(self, entity: FeatureFlagEntity) -> FeatureFlagEntity:
        """Overwrite all mutable columns on the existing row."""
        updated = FeatureFlagModel.objects.filter(key=entity.key).update(
            name=entity.name,
            description=entity.description,
            is_enabled=entity.is_enabled,
            enabled_plans=entity.enabled_plans,
            enabled_org_ids=entity.enabled_org_ids,
        )
        if not updated:
            raise FeatureFlagNotFoundError(f"Feature flag '{entity.key}' not found.")
        return self.get_by_key(entity.key)

    def delete(self, key: str) -> None:
        """Delete the flag row. No-op if it does not exist."""
        FeatureFlagModel.objects.filter(key=key).delete()
