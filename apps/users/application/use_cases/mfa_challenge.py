"""Use case: complete login by verifying a TOTP code or backup code and issuing JWT tokens."""

from __future__ import annotations

import uuid
from dataclasses import dataclass

from apps.users.domain.exceptions import InvalidCredentialsError, InvalidTOTPError
from apps.users.domain.repositories import ITokenService, ITOTPService, IUserRepository


@dataclass(frozen=True)
class MFAChallengeResult:
    """JWT tokens returned after a successful MFA challenge."""

    access_token: str
    refresh_token: str
    used_backup_code: bool = False


class MFAChallengeUseCase:
    """Verify a TOTP code or backup code for a pending MFA login and issue JWT tokens."""

    def __init__(
        self,
        user_repo: IUserRepository,
        totp_service: ITOTPService,
        token_service: ITokenService,
        backup_code_service: object = None,
    ) -> None:
        self._users = user_repo
        self._totp = totp_service
        self._tokens = token_service
        self._backup = backup_code_service

    def execute(self, user_id: uuid.UUID, code: str) -> MFAChallengeResult:
        """
        Verify the code (TOTP first, then backup) and return tokens on success.

        @param user_id - the user ID returned by the login endpoint
        @param code - 6-digit TOTP code or 8-char backup code
        @returns MFAChallengeResult with tokens and used_backup_code flag
        @raises InvalidCredentialsError if MFA is not enabled for this user
        @raises InvalidTOTPError if neither TOTP nor backup code matches
        """
        user = self._users.get_by_id(user_id)

        if not user.mfa_enabled or not user.mfa_secret:
            raise InvalidCredentialsError("MFA is not enabled for this account.")

        if self._totp.verify_code(user.mfa_secret, code):
            access_token, refresh_token = self._tokens.generate_for_user(user.id)
            return MFAChallengeResult(
                access_token=access_token,
                refresh_token=refresh_token,
                used_backup_code=False,
            )

        if self._backup is not None:
            from apps.users.domain.exceptions import InvalidBackupCodeError, NoBackupCodesError

            try:
                self._backup.verify_and_consume(user_id, code)
                access_token, refresh_token = self._tokens.generate_for_user(user.id)
                return MFAChallengeResult(
                    access_token=access_token,
                    refresh_token=refresh_token,
                    used_backup_code=True,
                )
            except (InvalidBackupCodeError, NoBackupCodesError):
                pass

        raise InvalidTOTPError("Invalid or expired TOTP or backup code.")
