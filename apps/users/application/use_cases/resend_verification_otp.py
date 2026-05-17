"""Use case: resend the email verification OTP."""

from __future__ import annotations

from apps.users.domain.exceptions import EmailAlreadyVerifiedError
from apps.users.domain.repositories import IEventPublisher, IOTPService, IUserRepository


class ResendVerificationOTPUseCase:
    """Generate a fresh OTP and re-publish the verification event."""

    def __init__(
        self,
        user_repo: IUserRepository,
        otp_service: IOTPService,
        event_publisher: IEventPublisher,
    ) -> None:
        self._users = user_repo
        self._otp = otp_service
        self._publisher = event_publisher

    def execute(self, email: str) -> None:
        """
        Look up the user, guard against already-verified accounts, then issue a new OTP.

        @param email - the account's email address
        @raises UserNotFoundError if the email does not exist
        @raises EmailAlreadyVerifiedError if the account is already verified
        """
        user = self._users.get_by_email(email.lower().strip())

        if user.is_email_verified:
            raise EmailAlreadyVerifiedError("This email address is already verified.")

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
