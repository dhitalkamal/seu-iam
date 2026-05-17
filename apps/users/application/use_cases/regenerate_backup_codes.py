"""Use case: regenerate MFA backup codes after confirming a TOTP code."""

from __future__ import annotations

import uuid

from apps.users.domain.exceptions import InvalidTOTPError, MFANotEnabledError
from apps.users.domain.repositories import ITOTPService, IUserRepository


class RegenerateBackupCodesUseCase:
    """Invalidate all existing backup codes and generate a fresh set."""

    def __init__(
        self,
        user_repo: IUserRepository,
        totp_service: ITOTPService,
        backup_code_service: object,
    ) -> None:
        self._users = user_repo
        self._totp = totp_service
        self._backup = backup_code_service

    def execute(self, user_id: uuid.UUID, code: str) -> list[str]:
        """
        Verify the TOTP code and generate a new set of backup codes.

        @param user_id - the authenticated user's ID
        @param code - 6-digit TOTP code confirming ownership
        @returns list of new plaintext backup codes
        @raises MFANotEnabledError if MFA is not active
        @raises InvalidTOTPError if the TOTP code is wrong
        """
        user = self._users.get_by_id(user_id)

        if not user.mfa_enabled:
            raise MFANotEnabledError("MFA must be enabled before generating backup codes.")

        if not user.mfa_secret or not self._totp.verify_code(user.mfa_secret, code):
            raise InvalidTOTPError("Invalid or expired TOTP code.")

        return self._backup.generate(user_id)  # type: ignore[union-attr]
