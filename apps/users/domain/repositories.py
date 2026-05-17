"""Abstract repository interfaces for the users domain. Implemented in the infrastructure layer."""

from __future__ import annotations

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
