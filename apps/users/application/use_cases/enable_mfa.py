"""Use case: confirm MFA setup by verifying a TOTP code."""

from __future__ import annotations

import uuid

from apps.users.domain.exceptions import InvalidTOTPError, MFAAlreadyEnabledError
from apps.users.domain.repositories import ITOTPService, IUserRepository


class EnableMFAUseCase:
    """Verify the TOTP code against the stored secret and activate MFA."""

    def __init__(self, user_repo: IUserRepository, totp_service: ITOTPService) -> None:
        self._users = user_repo
        self._totp = totp_service

    def execute(self, user_id: uuid.UUID, code: str) -> None:
        """
        Activate MFA after confirming the user can generate valid codes.

        @param user_id - the authenticated user's ID
        @param code - 6-digit TOTP code from the authenticator app
        @raises MFAAlreadyEnabledError if MFA is already active
        @raises InvalidTOTPError if no secret exists or the code is wrong
        """
        user = self._users.get_by_id(user_id)

        if user.mfa_enabled:
            raise MFAAlreadyEnabledError("MFA is already enabled on this account.")

        if not user.mfa_secret or not self._totp.verify_code(user.mfa_secret, code):
            raise InvalidTOTPError("Invalid or expired TOTP code.")

        user.mfa_enabled = True
        self._users.update(user)
