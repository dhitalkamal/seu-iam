"""Django ORM models for the users domain. Maps domain entities to the iam schema."""

from __future__ import annotations

import uuid

from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.db import models

from apps.users.domain.entities import UserEntity


class UserManager(BaseUserManager["User"]):
    """Custom manager that uses email as the unique identifier."""

    def create_user(self, email: str, password: str | None = None, **extra: object) -> "User":
        """Create and save a regular user account."""
        if not email:
            raise ValueError("Email is required.")
        user: User = self.model(email=self.normalize_email(email), **extra)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email: str, password: str | None = None, **extra: object) -> "User":
        """Create a staff superuser with full permissions."""
        extra.setdefault("is_staff", True)
        extra.setdefault("is_superuser", True)
        extra.setdefault("is_active", True)
        extra.setdefault("is_email_verified", True)
        return self.create_user(email, password, **extra)


class User(AbstractBaseUser, PermissionsMixin):
    """Platform user. Email is the login credential."""

    class Meta:
        db_table = '"iam"."user"'

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.EmailField(unique=True, max_length=255)
    first_name = models.CharField(max_length=150)
    last_name = models.CharField(max_length=150)
    avatar_url = models.URLField(blank=True, null=True)
    is_email_verified = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    mfa_enabled = models.BooleanField(default=False)
    failed_login_attempts = models.PositiveSmallIntegerField(default=0)
    locked_until = models.DateTimeField(null=True, blank=True)
    deleted_at = models.DateTimeField(null=True, blank=True)
    date_joined = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["first_name", "last_name"]
    objects: UserManager = UserManager()  # type: ignore[assignment]

    def to_entity(self) -> UserEntity:
        """Map this ORM row to a pure-Python UserEntity."""
        return UserEntity(
            id=self.id,
            email=self.email,
            first_name=self.first_name,
            last_name=self.last_name,
            password_hash=self.password,
            is_email_verified=self.is_email_verified,
            is_active=self.is_active,
            is_staff=self.is_staff,
            is_superuser=self.is_superuser,
            mfa_enabled=self.mfa_enabled,
            failed_login_attempts=self.failed_login_attempts,
            date_joined=self.date_joined,
            updated_at=self.updated_at,
            avatar_url=self.avatar_url,
            locked_until=self.locked_until,
            deleted_at=self.deleted_at,
        )

    @classmethod
    def from_entity(cls, entity: UserEntity) -> "User":
        """Build an unsaved ORM instance from a UserEntity (password already hashed)."""
        obj = cls(
            id=entity.id,
            email=entity.email,
            first_name=entity.first_name,
            last_name=entity.last_name,
            avatar_url=entity.avatar_url,
            is_email_verified=entity.is_email_verified,
            is_active=entity.is_active,
            is_staff=entity.is_staff,
            is_superuser=entity.is_superuser,
            mfa_enabled=entity.mfa_enabled,
            failed_login_attempts=entity.failed_login_attempts,
            locked_until=entity.locked_until,
            deleted_at=entity.deleted_at,
        )
        # password is pre-hashed — set directly to skip double-hashing
        obj.password = entity.password_hash
        return obj
