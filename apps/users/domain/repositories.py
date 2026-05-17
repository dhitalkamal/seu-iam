"""Abstract repository interfaces for the users domain. Implemented in the infrastructure layer."""

from __future__ import annotations

import uuid
from abc import ABC, abstractmethod

from apps.users.domain.entities import UserEntity


class IUserRepository(ABC):
    """Persistence contract for User aggregates."""

    @abstractmethod
    def get_by_email(self, email: str) -> UserEntity: ...

    @abstractmethod
    def exists_by_email(self, email: str) -> bool: ...

    @abstractmethod
    def create(self, entity: UserEntity) -> UserEntity: ...

    @abstractmethod
    def update(self, entity: UserEntity) -> UserEntity: ...


class ITokenService(ABC):
    """Issues JWT access + refresh token pairs for a given user."""

    @abstractmethod
    def generate_for_user(self, user_id: uuid.UUID) -> tuple[str, str]: ...


class ITokenBlacklistService(ABC):
    """Invalidates a refresh token so it cannot be used again."""

    @abstractmethod
    def blacklist(self, refresh_token: str) -> None: ...
