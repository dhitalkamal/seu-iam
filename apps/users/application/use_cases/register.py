"""Use case: register a new user account."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from django.contrib.auth.hashers import make_password
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError as DjangoValidationError

from apps.users.domain.entities import UserEntity
from apps.users.domain.exceptions import UserAlreadyExistsError, WeakPasswordError
from apps.users.domain.repositories import IEventPublisher, IOTPService, IUserRepository


class RegisterUseCase:
    """Create a new unverified user account and dispatch an email verification OTP."""

    def __init__(
        self,
        user_repo: IUserRepository,
        otp_service: IOTPService,
        event_publisher: IEventPublisher,
    ) -> None:
        self._users = user_repo
        self._otp = otp_service
        self._publisher = event_publisher

    def execute(self, email: str, password: str, first_name: str, last_name: str) -> UserEntity:
        """
        Validate uniqueness, hash the password, persist the account, then send a verification OTP.

        @param email - login email address
        @param password - plaintext password validated against Django validators
        @param first_name - user's given name
        @param last_name - user's family name
        @returns the newly created UserEntity
        @raises UserAlreadyExistsError if email is already taken
        @raises WeakPasswordError if the password fails Django validators
        """
        email = email.lower().strip()

        # ! If the account exists but is unverified, treat this as a resend rather
        # than a duplicate — the user simply missed or let their previous OTP expire.
        if self._users.exists_by_email(email):
            existing = self._users.get_by_email(email)
            if not existing.is_email_verified:
                otp = self._otp.generate_and_store(existing.id)
                self._publisher.publish(
                    "iam.email_verification_requested",
                    {
                        "user_id": str(existing.id),
                        "email": existing.email,
                        "first_name": existing.first_name,
                        "otp": otp,
                    },
                )
                return existing
            raise UserAlreadyExistsError("An account with this email already exists.")

        try:
            validate_password(password)
        except DjangoValidationError as exc:
            raise WeakPasswordError(exc.messages[0]) from exc

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
        user = self._users.create(entity)

        otp = self._otp.generate_and_store(user.id)
        self._publisher.publish(
            "iam.email_verification_requested",
            {
                "user_id": str(user.id),
                "email": user.email,
                "first_name": user.first_name,
                "otp": otp,
            },
        )

        return user
