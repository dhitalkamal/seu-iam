"""Use case: register a new user account."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from django.contrib.auth.hashers import make_password
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError as DjangoValidationError

from apps.users.domain.entities import UserEntity
from apps.users.domain.exceptions import UserAlreadyExistsError
from apps.users.domain.repositories import IUserRepository


class RegisterUseCase:
    """Create a new unverified user account."""

    def __init__(self, user_repo: IUserRepository) -> None:
        self._users = user_repo

    def execute(self, email: str, password: str, first_name: str, last_name: str) -> UserEntity:
        """
        Validate uniqueness, hash the password, and persist the account.

        @param email - login email address
        @param password - plaintext password validated against Django validators
        @param first_name - user's given name
        @param last_name - user's family name
        @returns the newly created UserEntity
        @raises UserAlreadyExistsError if email is already taken
        """
        email = email.lower().strip()

        if self._users.exists_by_email(email):
            raise UserAlreadyExistsError("An account with this email already exists.")

        try:
            validate_password(password)
        except DjangoValidationError as exc:
            raise UserAlreadyExistsError(exc.messages[0]) from exc

        now = datetime.now(timezone.utc)
        entity = UserEntity(
            id=uuid.uuid4(),
            email=email,
            first_name=first_name.strip(),
            last_name=last_name.strip(),
            password_hash=make_password(password),
            is_email_verified=False,
            is_active=True,
            is_staff=False,
            is_superuser=False,
            mfa_enabled=False,
            failed_login_attempts=0,
            date_joined=now,
            updated_at=now,
        )
        return self._users.create(entity)
