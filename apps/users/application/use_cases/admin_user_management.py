"""Use cases for superadmin user management: list, suspend, activate."""

from __future__ import annotations

import uuid

from apps.users.domain.entities import UserEntity
from apps.users.domain.repositories import IUserRepository


class ListUsersUseCase:
    """Return all non-deleted platform users. Superadmin only."""

    def __init__(self, user_repo: IUserRepository) -> None:
        self._users = user_repo

    def execute(self) -> list[UserEntity]:
        """Return every non-deleted user, ordered by date_joined descending."""
        return sorted(self._users.list_all(), key=lambda u: u.date_joined, reverse=True)


class SuspendUserUseCase:
    """Set is_active=False on a specific user. Superadmin only."""

    def __init__(self, user_repo: IUserRepository) -> None:
        self._users = user_repo

    def execute(self, *, user_id: uuid.UUID) -> UserEntity:
        """
        Deactivate the user account.

        @param user_id - the user to suspend
        @raises UserNotFoundError if the user does not exist
        """
        user = self._users.get_by_id(user_id)
        user.is_active = False
        return self._users.update(user)


class ActivateUserUseCase:
    """Set is_active=True on a suspended user. Superadmin only."""

    def __init__(self, user_repo: IUserRepository) -> None:
        self._users = user_repo

    def execute(self, *, user_id: uuid.UUID) -> UserEntity:
        """
        Reactivate a suspended user account.

        @param user_id - the user to activate
        @raises UserNotFoundError if the user does not exist
        """
        user = self._users.get_by_id(user_id)
        user.is_active = True
        return self._users.update(user)
