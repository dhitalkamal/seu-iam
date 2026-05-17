"""Use case: confirm a password reset with OTP and set a new password."""

from __future__ import annotations

from django.contrib.auth.hashers import make_password
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError as DjangoValidationError

from apps.users.domain.exceptions import UserAlreadyExistsError
from apps.users.domain.repositories import IOTPService, ITokenBlacklistService, IUserRepository


class ConfirmPasswordResetUseCase:
    """Validate the OTP, update the password, and invalidate all existing sessions."""

    def __init__(
        self,
        user_repo: IUserRepository,
        otp_service: IOTPService,
        token_blacklist_service: ITokenBlacklistService,
    ) -> None:
        self._users = user_repo
        self._otp = otp_service
        self._blacklist = token_blacklist_service

    def execute(self, email: str, otp: str, new_password: str) -> None:
        """
        Verify OTP, hash and save the new password, then invalidate all sessions.

        @param email - the account email address
        @param otp - the 8-char reset code from the email
        @param new_password - the new plaintext password
        @raises UserNotFoundError if the email does not exist
        @raises OTPExpiredError if no reset OTP exists for this user
        @raises OTPInvalidError if the OTP does not match
        @raises UserAlreadyExistsError if the new password fails Django validators
        """
        user = self._users.get_by_email(email.lower().strip())
        self._otp.verify_and_consume(user.id, otp)

        try:
            validate_password(new_password)
        except DjangoValidationError as exc:
            raise UserAlreadyExistsError(exc.messages[0]) from exc

        user.password_hash = make_password(new_password)
        self._users.update(user)
        self._blacklist.blacklist_all_for_user(user.id)
