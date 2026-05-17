"""Use case: soft-delete the authenticated user's account."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from apps.users.domain.repositories import ITokenBlacklistService, IUserRepository


class DeleteAccountUseCase:
    """Deactivate the account, record deletion timestamp, and invalidate all sessions."""

    def __init__(
        self,
        user_repo: IUserRepository,
        token_blacklist_service: ITokenBlacklistService,
    ) -> None:
        self._users = user_repo
        self._blacklist = token_blacklist_service

    def execute(self, user_id: uuid.UUID) -> None:
        """
        Soft-delete the user account.

        @param user_id - the authenticated user's ID
        @raises UserNotFoundError if the user does not exist
        """
        user = self._users.get_by_id(user_id)
        user.is_active = False
        user.deleted_at = datetime.now(timezone.utc)
        self._users.update(user)
        self._blacklist.blacklist_all_for_user(user.id)
