"""Use case: initiate SMS MFA setup by sending an OTP to the user's phone."""

from __future__ import annotations

import uuid

from apps.users.domain.exceptions import MFAAlreadyEnabledError, MFAPhoneRequiredError
from apps.users.domain.repositories import IEventPublisher, IOTPService, IUserRepository


class SetupSMSMFAUseCase:
    """Generate an OTP and dispatch it via SMS to prepare for SMS MFA activation."""

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
        Generate an OTP and publish an SMS dispatch event.

        The user must call EnableSMSMFAUseCase with the received OTP to activate.

        @param user_id - the authenticated user's ID
        @raises MFAAlreadyEnabledError if MFA is already active
        @raises MFAPhoneRequiredError if no phone number is on the user's profile
        """
        user = self._users.get_by_id(user_id)

        if user.mfa_enabled:
            raise MFAAlreadyEnabledError("MFA is already enabled on this account.")

        if not user.phone:
            raise MFAPhoneRequiredError("A phone number is required to set up SMS MFA.")

        otp = self._otp.generate_and_store(user_id)
        self._events.publish(
            "iam.mfa_sms_otp_requested",
            {"user_id": str(user_id), "phone": user.phone, "otp": otp},
        )
