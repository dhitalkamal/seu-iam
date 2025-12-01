"""Use case: reactivate an account that is within its 30-day deletion grace period."""

from __future__ import annotations

import uuid

from apps.users.domain.repositories import IUserRepository


class ReactivateAccountUseCase:
    """Cancel a pending deletion by clearing the schedule and restoring active status."""

    def __init__(self, user_repo: IUserRepository) -> None:
        self._users = user_repo

    def execute(self, user_id: uuid.UUID) -> None:
        """
        Restore a deactivated account that has not yet been erased.

        Clears scheduled_deletion_at and sets is_active=True so the user
        can log in again. No-op if already active (idempotent field writes).

        @param user_id - the user requesting reactivation
        @raises UserNotFoundError if the user does not exist
        """
        user = self._users.get_by_id(user_id)
        user.is_active = True
        user.scheduled_deletion_at = None
        self._users.update(user)
