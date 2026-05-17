"""Use case: change the authenticated user's own password."""

from __future__ import annotations

import uuid

from django.contrib.auth.hashers import check_password, make_password
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError as DjangoValidationError

from apps.users.domain.exceptions import InvalidCredentialsError, WeakPasswordError
from apps.users.domain.repositories import (
    IPasswordHistoryService,
    ITokenBlacklistService,
    IUserRepository,
)


class ChangePasswordUseCase:
    """Verify the current password, check history, set the new one, and invalidate sessions."""

    def __init__(
        self,
        user_repo: IUserRepository,
        token_blacklist_service: ITokenBlacklistService,
        password_history_service: IPasswordHistoryService,
    ) -> None:
        self._users = user_repo
        self._blacklist = token_blacklist_service
        self._history = password_history_service

    def execute(self, user_id: uuid.UUID, current_password: str, new_password: str) -> None:
        """
        Authenticate the current password, validate the new one, check history, then update.

        @param user_id - the authenticated user's ID
        @param current_password - must match the stored hash
        @param new_password - validated against Django validators and password history
        @raises InvalidCredentialsError if current_password does not match
        @raises WeakPasswordError if new_password fails validators or was recently used
        """
        user = self._users.get_by_id(user_id)

        if not check_password(current_password, user.password_hash):
            raise InvalidCredentialsError("Current password is incorrect.")

        try:
            validate_password(new_password)
        except DjangoValidationError as exc:
            raise WeakPasswordError(exc.messages[0]) from exc

        self._history.check(user_id, new_password)

        old_hash = user.password_hash
        new_hash = make_password(new_password)
        user.password_hash = new_hash
        self._users.update(user)
        self._history.record(user_id, old_hash)
        self._blacklist.blacklist_all_for_user(user.id)
