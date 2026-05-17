"""Use case: verify a password-reset OTP without consuming it."""

from __future__ import annotations

from apps.users.domain.repositories import IOTPService, IUserRepository


class VerifyPasswordResetOTPUseCase:
    """Check the OTP is valid for this email without deleting it.

    Allows the frontend to confirm the OTP on page 2 of the reset flow
    before presenting the new-password form on page 3.
    """

    def __init__(self, user_repo: IUserRepository, otp_service: IOTPService) -> None:
        self._users = user_repo
        self._otp = otp_service

    def execute(self, email: str, otp: str) -> None:
        """
        Look up the user and validate the OTP without consuming it.

        @param email - the account email address
        @param otp - the 8-char reset code to verify
        @raises UserNotFoundError if the email does not exist
        @raises OTPExpiredError if no reset OTP is stored for this user
        @raises OTPInvalidError if the OTP does not match
        """
        user = self._users.get_by_email(email.lower().strip())
        self._otp.verify(user.id, otp)
