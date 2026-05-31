"""Use case: confirm MFA setup by verifying a TOTP code."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field

from apps.users.domain.exceptions import InvalidTOTPError, MFAAlreadyEnabledError
from apps.users.domain.repositories import ITOTPService, IUserRepository


@dataclass(frozen=True)
class EnableMFAResult:
    """Result of enabling MFA, including generated backup codes."""

    backup_codes: list[str] = field(default_factory=list)


class EnableMFAUseCase:
    """Verify the TOTP code and activate MFA, optionally generating backup codes."""

    def __init__(
        self,
        user_repo: IUserRepository,
        totp_service: ITOTPService,
        backup_code_service: object = None,
    ) -> None:
        self._users = user_repo
        self._totp = totp_service
        self._backup = backup_code_service

    def execute(self, user_id: uuid.UUID, code: str) -> EnableMFAResult:
        """
        Activate MFA after confirming the user can generate valid codes.

        @param user_id - the authenticated user's ID
        @param code - 6-digit TOTP code from the authenticator app
        @returns EnableMFAResult with plaintext backup codes (empty if no backup service)
        @raises MFAAlreadyEnabledError if MFA is already active
        @raises InvalidTOTPError if no secret exists or the code is wrong
        """
        user = self._users.get_by_id(user_id)

        if user.mfa_enabled:
            raise MFAAlreadyEnabledError("MFA is already enabled on this account.")

        if not user.mfa_secret or not self._totp.verify_code(user.mfa_secret, code):
            raise InvalidTOTPError("Invalid or expired TOTP code.")

        user.mfa_enabled = True
        user.mfa_type = "totp"
        self._users.update(user)

        if self._backup is not None:
            codes = self._backup.generate(user_id)
            return EnableMFAResult(backup_codes=codes)

        return EnableMFAResult()
