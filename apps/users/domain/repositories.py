"""Abstract repository interfaces for the users domain. Implemented in the infrastructure layer."""

from __future__ import annotations

import uuid
from abc import ABC, abstractmethod

from apps.users.domain.entities import AnnouncementEntity, FeatureFlagEntity, UserEntity


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

    @abstractmethod
    def list_all(self) -> list[UserEntity]: ...


class ITokenService(ABC):
    """Issues JWT access + refresh token pairs for a given user."""

    @abstractmethod
    def generate_for_user(self, user_id: uuid.UUID) -> tuple[str, str]: ...


class ITokenBlacklistService(ABC):
    """Invalidates a refresh token so it cannot be used again."""

    @abstractmethod
    def blacklist(self, refresh_token: str) -> None: ...

    @abstractmethod
    def blacklist_all_for_user(self, user_id: uuid.UUID) -> None:
        """Blacklist every outstanding refresh token for the given user."""
        ...


class IOTPService(ABC):
    """Generates, stores, and verifies short-lived one-time passwords."""

    @abstractmethod
    def generate_and_store(self, user_id: uuid.UUID) -> str:
        """Generate an 8-char alphanumeric OTP, persist it with a TTL, and return it."""
        ...

    @abstractmethod
    def verify(self, user_id: uuid.UUID, otp: str) -> None:
        """
        Validate the OTP without consuming it.

        Raises OTPExpiredError if no OTP exists, OTPInvalidError if it does not match.
        Does NOT delete the OTP — use this to verify before presenting the password form.
        """
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


class IPasswordHistoryService(ABC):
    """Checks and records password history to prevent reuse."""

    @abstractmethod
    def check(self, user_id: uuid.UUID, new_password: str) -> None:
        """Raise WeakPasswordError if new_password was recently used."""
        ...

    @abstractmethod
    def record(self, user_id: uuid.UUID, password_hash: str) -> None:
        """Store the new hash, pruning old entries beyond the limit."""
        ...


class IGoogleTokenVerifier(ABC):
    """Verifies a Google ID token and returns the decoded payload."""

    @abstractmethod
    def verify(self, id_token: str) -> dict:
        """
        Verify the token against Google's public keys and return the payload.

        Raises SocialAuthError if the token is invalid, expired, or the
        audience does not match.
        """
        ...


class IGithubTokenVerifier(ABC):
    """Verifies a GitHub OAuth access token and returns the user profile payload."""

    @abstractmethod
    def verify(self, access_token: str) -> dict:
        """
        Exchange the access token for a user profile via the GitHub REST API.

        Returns a dict with email, name, and avatar_url keys.
        Raises SocialAuthError if the token is invalid or the account has no
        verified primary email address.
        """
        ...


class ITOTPService(ABC):
    """Generates and verifies TOTP secrets and codes."""

    @abstractmethod
    def generate_secret(self) -> str:
        """Return a new base32-encoded TOTP secret."""
        ...

    @abstractmethod
    def get_provisioning_uri(self, secret: str, email: str) -> str:
        """Return the otpauth:// URI for QR code display in an authenticator app."""
        ...

    @abstractmethod
    def verify_code(self, secret: str, code: str) -> bool:
        """Return True if code is valid for the given secret at the current time."""
        ...


class IFeatureFlagRepository(ABC):
    """Persistence contract for FeatureFlag aggregates."""

    @abstractmethod
    def list_all(self) -> list[FeatureFlagEntity]: ...

    @abstractmethod
    def get_by_key(self, key: str) -> FeatureFlagEntity: ...

    @abstractmethod
    def exists_by_key(self, key: str) -> bool: ...

    @abstractmethod
    def create(self, entity: FeatureFlagEntity) -> FeatureFlagEntity: ...

    @abstractmethod
    def update(self, entity: FeatureFlagEntity) -> FeatureFlagEntity: ...

    @abstractmethod
    def delete(self, key: str) -> None: ...


class IAnnouncementRepository(ABC):
    """Persistence contract for Announcement aggregates."""

    @abstractmethod
    def list_all(self) -> list[AnnouncementEntity]: ...

    @abstractmethod
    def get_by_id(self, announcement_id: uuid.UUID) -> AnnouncementEntity: ...

    @abstractmethod
    def create(self, entity: AnnouncementEntity) -> AnnouncementEntity: ...
