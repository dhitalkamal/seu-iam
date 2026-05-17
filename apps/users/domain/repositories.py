"""Abstract repository interfaces for the users domain. Implemented in the infrastructure layer."""

from __future__ import annotations

import uuid
from abc import ABC, abstractmethod

from apps.users.domain.entities import UserEntity


class IUserRepository(ABC):
    """Persistence contract for User aggregates."""

    @abstractmethod
    def get_by_id(self, user_id: uuid.UUID) -> UserEntity: ...

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


class IOTPService(ABC):
    """Generates, stores, and verifies short-lived one-time passwords."""

    @abstractmethod
    def generate_and_store(self, user_id: uuid.UUID) -> str:
        """Generate an 8-char alphanumeric OTP, persist it with a TTL, and return it."""
        ...

    @abstractmethod
    def verify_and_consume(self, user_id: uuid.UUID, otp: str) -> None:
        """
        Validate the OTP for the given user.

        Deletes it on success so it cannot be reused.
        Raises OTPExpiredError if no OTP exists, OTPInvalidError if it does not match.
        """
        ...


class IEventPublisher(ABC):
    """Publishes domain events to a message broker."""

    @abstractmethod
    def publish(self, event_name: str, payload: dict) -> None:
        """Publish a named event with an arbitrary JSON-serialisable payload."""
        ...
