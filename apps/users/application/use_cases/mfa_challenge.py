"""Use case: complete login by verifying a TOTP code and issuing JWT tokens."""

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


class MFAChallengeUseCase:
    """Verify the TOTP code for a pending MFA login and issue JWT tokens."""

    def __init__(
        self,
        user_repo: IUserRepository,
        totp_service: ITOTPService,
        token_service: ITokenService,
    ) -> None:
        self._users = user_repo
        self._totp = totp_service
        self._tokens = token_service

    def execute(self, user_id: uuid.UUID, code: str) -> MFAChallengeResult:
        """
        Verify the TOTP code and return tokens on success.

        @param user_id - the user ID returned by the login endpoint
        @param code - 6-digit TOTP code from the authenticator app
        @returns MFAChallengeResult with access and refresh tokens
        @raises InvalidCredentialsError if MFA is not enabled for this user
        @raises InvalidTOTPError if the code is wrong or expired
        """
        user = self._users.get_by_id(user_id)

        if not user.mfa_enabled or not user.mfa_secret:
            raise InvalidCredentialsError("MFA is not enabled for this account.")

        if not self._totp.verify_code(user.mfa_secret, code):
            raise InvalidTOTPError("Invalid or expired TOTP code.")

        access_token, refresh_token = self._tokens.generate_for_user(user.id)
        return MFAChallengeResult(access_token=access_token, refresh_token=refresh_token)
