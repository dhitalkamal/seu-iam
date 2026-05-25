"""Use case: initiate email MFA setup by sending an OTP to the user's email."""

from __future__ import annotations

import uuid

from apps.users.domain.exceptions import MFAAlreadyEnabledError
from apps.users.domain.repositories import IEventPublisher, IOTPService, IUserRepository


class SetupEmailMFAUseCase:
    """Generate an OTP and dispatch it via email to prepare for email MFA activation."""

    def __init__(
        self,
        user_repo: IUserRepository,
        otp_service: IOTPService,
        event_publisher: IEventPublisher,
    ) -> None:
        self._users = user_repo
        self._otp = otp_service
        self._events = event_publisher

    def execute(self, user_id: uuid.UUID) -> None:
        """
        Generate an OTP and publish an email dispatch event.

        The user must call EnableEmailMFAUseCase with the received OTP to activate.

        @param user_id - the authenticated user's ID
        @raises MFAAlreadyEnabledError if MFA is already active
        """
        user = self._users.get_by_id(user_id)

        if user.mfa_enabled:
            raise MFAAlreadyEnabledError("MFA is already enabled on this account.")

        otp = self._otp.generate_and_store(user_id)
        self._events.publish(
            "iam.mfa_email_otp_requested",
            {
                "user_id": str(user_id),
                "email": user.email,
                "first_name": user.first_name,
                "otp": otp,
            },
        )
