"""Use case: disable MFA after verifying a TOTP code."""

from __future__ import annotations

import uuid

from apps.users.domain.exceptions import InvalidTOTPError, MFANotEnabledError
from apps.users.domain.repositories import ITOTPService, IUserRepository


class DisableMFAUseCase:
    """Verify the TOTP code and deactivate MFA, clearing the stored secret."""

    def __init__(self, user_repo: IUserRepository, totp_service: ITOTPService) -> None:
        self._users = user_repo
        self._totp = totp_service

    def execute(self, user_id: uuid.UUID, code: str) -> None:
        """
        Disable MFA after confirming ownership via a valid TOTP code.

        @param user_id - the authenticated user's ID
        @param code - 6-digit TOTP code from the authenticator app
        @raises MFANotEnabledError if MFA is not active
        @raises InvalidTOTPError if the code is wrong
        """
        user = self._users.get_by_id(user_id)

        if not user.mfa_enabled:
            raise MFANotEnabledError("MFA is not enabled on this account.")

        if not self._totp.verify_code(user.mfa_secret or "", code):
            raise InvalidTOTPError("Invalid or expired TOTP code.")

        user.mfa_enabled = False
        user.mfa_secret = None
        self._users.update(user)
