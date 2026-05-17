"""Use case: initiate MFA setup by generating a TOTP secret."""

from __future__ import annotations

import uuid

from apps.users.domain.exceptions import MFAAlreadyEnabledError
from apps.users.domain.repositories import ITOTPService, IUserRepository


class SetupMFAUseCase:
    """Generate a TOTP secret, persist it, and return the provisioning URI."""

    def __init__(self, user_repo: IUserRepository, totp_service: ITOTPService) -> None:
        self._users = user_repo
        self._totp = totp_service

    def execute(self, user_id: uuid.UUID) -> dict:
        """
        Generate and store a TOTP secret for the user.

        MFA is not yet active until EnableMFAUseCase confirms the code.

        @param user_id - the authenticated user's ID
        @returns dict with 'secret' and 'provisioning_uri'
        @raises MFAAlreadyEnabledError if MFA is already active
        """
        user = self._users.get_by_id(user_id)

        if user.mfa_enabled:
            raise MFAAlreadyEnabledError("MFA is already enabled on this account.")

        secret = self._totp.generate_secret()
        user.mfa_secret = secret
        self._users.update(user)

        return {
            "secret": secret,
            "provisioning_uri": self._totp.get_provisioning_uri(secret, user.email),
        }
