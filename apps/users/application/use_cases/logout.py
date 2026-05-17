"""Use case: invalidate a refresh token on logout."""

from __future__ import annotations

from apps.users.domain.repositories import ITokenBlacklistService


class LogoutUseCase:
    """Blacklist the user's refresh token to terminate their session."""

    def __init__(self, blacklist_service: ITokenBlacklistService) -> None:
        self._blacklist = blacklist_service

    def execute(self, refresh_token: str) -> None:
        """
        Add the refresh token to the blacklist.

        @param refresh_token - the token string to invalidate
        @raises InvalidTokenError if the token is malformed or already blacklisted
        """
        self._blacklist.blacklist(refresh_token)
