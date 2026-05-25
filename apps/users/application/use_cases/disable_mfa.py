"""Use case: disable MFA after confirming identity via TOTP code or current password."""

from __future__ import annotations

import uuid

from django.contrib.auth.hashers import check_password

from apps.users.domain.exceptions import InvalidCredentialsError, InvalidTOTPError, MFANotEnabledError
from apps.users.domain.repositories import ITOTPService, IUserRepository


class DisableMFAUseCase:
    """Deactivate MFA, confirming via TOTP code (totp) or current password (sms/email)."""

    def __init__(self, user_repo: IUserRepository, totp_service: ITOTPService) -> None:
        self._users = user_repo
        self._totp = totp_service

    def execute(
        self,
        user_id: uuid.UUID,
        code: str | None = None,
        current_password: str | None = None,
    ) -> None:
        """
        Disable MFA after confirming the user's identity.

        For totp users, pass code (6-digit TOTP). For sms/email users, pass current_password.

        @param user_id - the authenticated user's ID
        @param code - 6-digit TOTP code (required for totp MFA type)
        @param current_password - account password (required for sms/email MFA types)
        @raises MFANotEnabledError if MFA is not active
        @raises InvalidTOTPError if code is wrong (totp)
        @raises InvalidCredentialsError if password is wrong (sms/email)
        """
        user = self._users.get_by_id(user_id)

        if not user.mfa_enabled:
            raise MFANotEnabledError("MFA is not enabled on this account.")

        mfa_type = user.mfa_type or "totp"

        if mfa_type in ("sms", "email"):
            if not current_password or not check_password(current_password, user.password_hash):
                raise InvalidCredentialsError("Incorrect password.")
        else:
            if not code or not self._totp.verify_code(user.mfa_secret or "", code):
                raise InvalidTOTPError("Invalid or expired TOTP code.")

        user.mfa_enabled = False
        user.mfa_secret = None
        user.mfa_type = None
        self._users.update(user)
