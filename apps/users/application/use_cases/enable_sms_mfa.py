"""Use case: confirm SMS MFA by verifying the OTP and activating MFA."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field

from apps.users.domain.exceptions import MFAAlreadyEnabledError
from apps.users.domain.repositories import IOTPService, IUserRepository


@dataclass(frozen=True)
class EnableSMSMFAResult:
    """Result of enabling SMS MFA, including one-time backup codes."""

    backup_codes: list[str] = field(default_factory=list)


class EnableSMSMFAUseCase:
    """Verify the SMS OTP, activate MFA with type 'sms', and generate backup codes."""

    def __init__(
        self,
        user_repo: IUserRepository,
        otp_service: IOTPService,
        backup_code_service: object = None,
    ) -> None:
        self._users = user_repo
        self._otp = otp_service
        self._backup = backup_code_service

    def execute(self, user_id: uuid.UUID, otp: str) -> EnableSMSMFAResult:
        """
        Verify the OTP received via SMS and activate MFA.

        @param user_id - the authenticated user's ID
        @param otp - the 8-char OTP received via SMS
        @returns EnableSMSMFAResult with backup codes
        @raises MFAAlreadyEnabledError if MFA is already active
        @raises OTPInvalidError / OTPExpiredError if the OTP is wrong or expired
        """
        user = self._users.get_by_id(user_id)

        if user.mfa_enabled:
            raise MFAAlreadyEnabledError("MFA is already enabled on this account.")

        # raises OTPInvalidError or OTPExpiredError on failure
        self._otp.verify_and_consume(user_id, otp)

        user.mfa_enabled = True
        user.mfa_type = "sms"
        self._users.update(user)

        if self._backup is not None:
            codes = self._backup.generate(user_id)  # type: ignore[attr-defined]
            return EnableSMSMFAResult(backup_codes=codes)

        return EnableSMSMFAResult()
