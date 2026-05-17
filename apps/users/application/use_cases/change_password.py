"""Use case: change the authenticated user's own password."""

from __future__ import annotations

import uuid

from django.contrib.auth.hashers import check_password, make_password
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError as DjangoValidationError

from apps.users.domain.exceptions import InvalidCredentialsError, UserAlreadyExistsError
from apps.users.domain.repositories import ITokenBlacklistService, IUserRepository


class ChangePasswordUseCase:
    """Verify the current password, set a new one, and invalidate all sessions."""

    def __init__(
        self,
        user_repo: IUserRepository,
        token_blacklist_service: ITokenBlacklistService,
    ) -> None:
        self._users = user_repo
        self._blacklist = token_blacklist_service

    def execute(self, user_id: uuid.UUID, current_password: str, new_password: str) -> None:
        """
        Authenticate the current password, then update to the new one.

        @param user_id - the authenticated user's ID
        @param current_password - must match the stored hash
        @param new_password - new plaintext password, validated against Django validators
        @raises InvalidCredentialsError if current_password does not match
        @raises UserAlreadyExistsError if new_password fails Django validators
        """
        user = self._users.get_by_id(user_id)

        if not check_password(current_password, user.password_hash):
            raise InvalidCredentialsError("Current password is incorrect.")

        try:
            validate_password(new_password)
        except DjangoValidationError as exc:
            raise UserAlreadyExistsError(exc.messages[0]) from exc

        user.password_hash = make_password(new_password)
        self._users.update(user)
        self._blacklist.blacklist_all_for_user(user.id)
