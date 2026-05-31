"""Use case: request a password reset OTP."""

from __future__ import annotations

from apps.users.domain.exceptions import AccountNotVerifiedError
from apps.users.domain.repositories import IEventPublisher, IOTPService, IUserRepository


class RequestPasswordResetUseCase:
    """Generate a password-reset OTP and publish it to the notification service."""

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
        Look up the user, require a verified email, then issue a reset OTP.

        @param email - the account email address
        @raises UserNotFoundError if the email does not exist
        @raises AccountNotVerifiedError if the email has not been verified
        """
        user = self._users.get_by_email(email.lower().strip())

        if not user.is_email_verified:
            raise AccountNotVerifiedError("Email must be verified before resetting a password.")

        otp = self._otp.generate_and_store(user.id)
        self._publisher.publish(
            "iam.password_reset_requested",
            {
                "user_id": str(user.id),
                "email": user.email,
                "first_name": user.first_name,
                "otp": otp,
            },
        )
