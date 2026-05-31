"""Use case: anonymize all PII for a user (GDPR Article 17 — Right to Erasure)."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from django.contrib.auth.hashers import check_password

from apps.users.domain.exceptions import InvalidCredentialsError
from apps.users.domain.repositories import ITokenBlacklistService, IUserRepository


class GDPRErasureUseCase:
    """Pseudonymize user PII in-place, invalidate all sessions."""

    def __init__(
        self,
        user_repo: IUserRepository,
        token_blacklist_service: ITokenBlacklistService,
    ) -> None:
        self._users = user_repo
        self._blacklist = token_blacklist_service

    def execute(self, user_id: uuid.UUID, current_password: str | None) -> None:
        """
        Replace all PII with anonymised values and deactivate the account.

        Password confirmation is required for users who have a usable password.
        Social auth users (unusable password hash starting with !) are exempt.

        @param user_id - the authenticated user's ID
        @param current_password - required for password users, None for social auth users
        @raises InvalidCredentialsError if password confirmation fails
        """
        user = self._users.get_by_id(user_id)

        if not user.password_hash.startswith("!"):
            if not current_password or not check_password(current_password, user.password_hash):
                raise InvalidCredentialsError("Password confirmation is required for erasure.")

        user.email = f"deleted_{user.id}@redacted.sansaar.com"
        user.first_name = "Deleted"
        user.last_name = "User"
        user.avatar_url = None
        user.mfa_secret = None
        user.is_active = False
        user.deleted_at = datetime.now(timezone.utc)
        self._users.update(user)
        self._blacklist.blacklist_all_for_user(user.id)
