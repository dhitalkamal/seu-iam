"""Concrete repository implementations backed by the Django ORM."""

from __future__ import annotations

from apps.users.domain.entities import UserEntity
from apps.users.domain.exceptions import UserNotFoundError
from apps.users.domain.repositories import IUserRepository
from apps.users.infrastructure.models import User


class DjangoUserRepository(IUserRepository):
    """Persists User entities using the Django ORM."""

    def get_by_email(self, email: str) -> UserEntity:
        """Fetch by email. Raises UserNotFoundError if absent."""
        try:
            return User.objects.get(email=email).to_entity()
        except User.DoesNotExist:
            raise UserNotFoundError("User not found.")

    def exists_by_email(self, email: str) -> bool:
        """Return True if any user with this email exists."""
        return User.objects.filter(email=email).exists()

    def create(self, entity: UserEntity) -> UserEntity:
        """Persist a new user and return the saved entity."""
        obj = User.from_entity(entity)
        obj.save(using="default")
        return obj.to_entity()
