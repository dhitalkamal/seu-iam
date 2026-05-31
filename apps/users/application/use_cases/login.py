"""Use case: authenticate with email and password."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from django.conf import settings
from django.contrib.auth.hashers import check_password

from apps.users.domain.exceptions import (
    AccountInactiveError,
    AccountLockedError,
    AccountNotVerifiedError,
    InvalidCredentialsError,
)
from apps.users.domain.repositories import (
    IEventPublisher,
    IOTPService,
    ITokenService,
    IUserRepository,
)


@dataclass(slots=True)
class LoginResult:
    """Output of a successful login attempt."""

    mfa_required: bool
    user_id: uuid.UUID | None = None
    mfa_type: str | None = None
    access_token: str | None = None
    refresh_token: str | None = None


class LoginUseCase:
    """Validate credentials and issue tokens or signal an MFA challenge."""

    def __init__(
        self,
        user_repo: IUserRepository,
        token_service: ITokenService,
        otp_service: IOTPService | None = None,
        event_publisher: IEventPublisher | None = None,
    ) -> None:
        self._users = user_repo
        self._tokens = token_service
        self._otp = otp_service
        self._events = event_publisher

    def execute(self, email: str, password: str) -> LoginResult:
        """
        Authenticate the user and return tokens or an MFA signal.

        @param email - the user's registered email
        @param password - the plaintext password to verify
        @returns LoginResult with tokens or mfa_required flag
        @raises InvalidCredentialsError, AccountInactiveError, AccountLockedError, AccountNotVerifiedError
        """
        try:
            user = self._users.get_by_email(email.lower().strip())
        except Exception:
            raise InvalidCredentialsError("Invalid email or password.")

        if not user.is_active:
            raise AccountInactiveError("This account has been deactivated.")

        now = datetime.now(timezone.utc)
        if user.locked_until and user.locked_until > now:
            raise AccountLockedError(
                "Account is temporarily locked due to failed login attempts.",
                details={"locked_until": user.locked_until.isoformat()},
            )

        if not check_password(password, user.password_hash):
            user.failed_login_attempts += 1
            max_attempts: int = getattr(settings, "MAX_FAILED_LOGIN_ATTEMPTS", 5)
            lockout_minutes: int = getattr(settings, "ACCOUNT_LOCKOUT_MINUTES", 30)
            if user.failed_login_attempts >= max_attempts:
                user.locked_until = now + timedelta(minutes=lockout_minutes)
            self._users.update(user)
            raise InvalidCredentialsError("Invalid email or password.")

        if not user.is_email_verified:
            raise AccountNotVerifiedError("Please verify your email before signing in.")

        user.failed_login_attempts = 0
        user.locked_until = None
        self._users.update(user)

        if user.mfa_enabled:
            mfa_type = user.mfa_type or "totp"
            self._dispatch_otp_if_needed(user, mfa_type)
            return LoginResult(mfa_required=True, user_id=user.id, mfa_type=mfa_type)

        access, refresh = self._tokens.generate_for_user(user.id)
        return LoginResult(mfa_required=False, user_id=user.id, access_token=access, refresh_token=refresh)

    def _dispatch_otp_if_needed(self, user: object, mfa_type: str) -> None:
        """Send an OTP via the appropriate channel for sms and email MFA methods."""
        if mfa_type not in ("sms", "email") or self._otp is None or self._events is None:
            return
        otp = self._otp.generate_and_store(user.id)  # type: ignore[attr-defined]
        if mfa_type == "sms":
            self._events.publish(
                "iam.mfa_sms_otp_requested",
                {"user_id": str(user.id), "phone": user.phone, "otp": otp},  # type: ignore[attr-defined]
            )
        else:
            self._events.publish(
                "iam.mfa_email_otp_requested",
                {
                    "user_id": str(user.id),  # type: ignore[attr-defined]
                    "email": user.email,  # type: ignore[attr-defined]
                    "first_name": user.first_name,  # type: ignore[attr-defined]
                    "otp": otp,
                },
            )
