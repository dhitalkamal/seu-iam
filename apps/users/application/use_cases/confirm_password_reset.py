"""Use case: confirm a password reset with OTP and set a new password."""

from __future__ import annotations

from django.contrib.auth.hashers import make_password
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError as DjangoValidationError

from apps.users.domain.exceptions import WeakPasswordError
from apps.users.domain.repositories import (
    IOTPService,
    IPasswordHistoryService,
    ITokenBlacklistService,
    IUserRepository,
)


class ConfirmPasswordResetUseCase:
    """Validate OTP, check password history, update the password, and invalidate all sessions."""

    def __init__(
        self,
        user_repo: IUserRepository,
        otp_service: IOTPService,
        token_blacklist_service: ITokenBlacklistService,
        password_history_service: IPasswordHistoryService,
    ) -> None:
        self._users = user_repo
        self._otp = otp_service
        self._blacklist = token_blacklist_service
        self._history = password_history_service

    def execute(self, email: str, otp: str, new_password: str) -> None:
        """
        Verify OTP, check history, hash and save the new password, then invalidate all sessions.

        @param email - the account email address
        @param otp - the 8-char reset code from the email
        @param new_password - validated against Django validators and password history
        @raises UserNotFoundError if the email does not exist
        @raises OTPExpiredError if no reset OTP exists for this user
        @raises OTPInvalidError if the OTP does not match
        @raises WeakPasswordError if the new password fails validators or was recently used
        """
        user = self._users.get_by_email(email.lower().strip())
        self._otp.verify_and_consume(user.id, otp)

        try:
            validate_password(new_password)
        except DjangoValidationError as exc:
            raise WeakPasswordError(exc.messages[0]) from exc

        self._history.check(user.id, new_password)

        old_hash = user.password_hash
        new_hash = make_password(new_password)
        user.password_hash = new_hash
        self._users.update(user)
        self._history.record(user.id, old_hash)
        self._blacklist.blacklist_all_for_user(user.id)
