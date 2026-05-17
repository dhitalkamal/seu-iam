"""Concrete repository implementations backed by the Django ORM."""

from __future__ import annotations

from apps.users.domain.entities import UserEntity
from apps.users.domain.exceptions import UserNotFoundError
from apps.users.domain.repositories import IUserRepository
from apps.users.infrastructure.models import User


class DjangoUserRepository(IUserRepository):
    """Persists User entities using the Django ORM."""

    def get_by_id(self, user_id: object) -> UserEntity:
        """Fetch by primary key. Raises UserNotFoundError if absent."""
        try:
            return User.objects.get(pk=user_id).to_entity()
        except User.DoesNotExist:
            raise UserNotFoundError("User not found.")

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

    def update(self, entity: UserEntity) -> UserEntity:
        """Update mutable fields on an existing user."""
        User.objects.filter(pk=entity.id).update(
            first_name=entity.first_name,
            last_name=entity.last_name,
            avatar_url=entity.avatar_url,
            phone=entity.phone,
            bio=entity.bio,
            is_email_verified=entity.is_email_verified,
            is_active=entity.is_active,
            mfa_enabled=entity.mfa_enabled,
            mfa_secret=entity.mfa_secret,
            failed_login_attempts=entity.failed_login_attempts,
            locked_until=entity.locked_until,
            deleted_at=entity.deleted_at,
            password=entity.password_hash,
        )
        return entity
