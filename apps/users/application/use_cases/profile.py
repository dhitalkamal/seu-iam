"""Use cases: get and update the authenticated user's profile."""

from __future__ import annotations

import uuid

from apps.users.domain.entities import UserEntity
from apps.users.domain.repositories import IUserRepository


class GetProfileUseCase:
    """Fetch the current user's full profile."""

    def __init__(self, user_repo: IUserRepository) -> None:
        self._users = user_repo

    def execute(self, user_id: uuid.UUID) -> UserEntity:
        """
        Return the UserEntity for the given user ID.

        @param user_id - the authenticated user's ID from the JWT claim
        @returns UserEntity
        @raises UserNotFoundError if the account does not exist
        """
        return self._users.get_by_id(user_id)


class UpdateProfileUseCase:
    """Apply partial updates to the authenticated user's profile."""

    def __init__(self, user_repo: IUserRepository) -> None:
        self._users = user_repo

    def execute(
        self,
        user_id: uuid.UUID,
        first_name: str | None = None,
        last_name: str | None = None,
        avatar_url: str | None = None,
    ) -> UserEntity:
        """
        Update only the fields that are explicitly provided.

        @param user_id - the authenticated user's ID
        @param first_name - new given name, if changing
        @param last_name - new family name, if changing
        @param avatar_url - new avatar URL, if changing
        @returns the updated UserEntity
        """
        user = self._users.get_by_id(user_id)
        if first_name is not None:
            user.first_name = first_name.strip()
        if last_name is not None:
            user.last_name = last_name.strip()
        if avatar_url is not None:
            user.avatar_url = avatar_url
        return self._users.update(user)
