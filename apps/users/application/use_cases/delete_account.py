"""Use case: initiate a 30-day grace-period soft-delete on the authenticated user's account."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from apps.users.domain.repositories import ITokenBlacklistService, IUserRepository

# ! accounts are not erased immediately; GDPR anonymization runs after this window
_GRACE_PERIOD_DAYS = 30


class DeleteAccountUseCase:
    """Deactivate the account, schedule it for erasure in 30 days, and invalidate all sessions."""

    def __init__(
        self,
        user_repo: IUserRepository,
        token_blacklist_service: ITokenBlacklistService,
    ) -> None:
        self._users = user_repo
        self._blacklist = token_blacklist_service

    def execute(self, user_id: uuid.UUID) -> None:
        """
        Begin the deletion grace period for the account.

        Sets is_active=False and scheduled_deletion_at=now+30d. Does NOT
        anonymize PII immediately; a daily Celery beat task handles that.

        @param user_id - the authenticated user's ID
        @raises UserNotFoundError if the user does not exist
        """
        user = self._users.get_by_id(user_id)
        user.is_active = False
        user.scheduled_deletion_at = datetime.now(timezone.utc) + timedelta(days=_GRACE_PERIOD_DAYS)
        self._users.update(user)
        self._blacklist.blacklist_all_for_user(user.id)
