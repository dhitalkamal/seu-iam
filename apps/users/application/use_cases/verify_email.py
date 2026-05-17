"""Use case: verify a user's email address using an OTP."""

from __future__ import annotations

from apps.users.domain.exceptions import EmailAlreadyVerifiedError
from apps.users.domain.repositories import IOTPService, IUserRepository


class VerifyEmailUseCase:
    """Validate the submitted OTP and mark the user's email as verified."""

    def __init__(self, user_repo: IUserRepository, otp_service: IOTPService) -> None:
        self._users = user_repo
        self._otp = otp_service

    def execute(self, email: str, otp: str) -> None:
        """
        Look up the user by email, check verification status, then validate the OTP.

        @param email - the account's email address
        @param otp - the 8-char alphanumeric code submitted by the user
        @raises UserNotFoundError if the email does not exist
        @raises EmailAlreadyVerifiedError if the account is already verified
        @raises OTPExpiredError if no OTP is stored for this user
        @raises OTPInvalidError if the OTP does not match
        """
        user = self._users.get_by_email(email.lower().strip())

        if user.is_email_verified:
            raise EmailAlreadyVerifiedError("This email address is already verified.")

        self._otp.verify_and_consume(user.id, otp)

        user.is_email_verified = True
        self._users.update(user)
