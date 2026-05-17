"""Domain errors raised by IAM use cases and never swallowed silently."""

from __future__ import annotations

from apps.common.api.exceptions import DomainError


class UserAlreadyExistsError(DomainError):
    """A user with that email address already exists."""

    http_status = 409
    code = "ERR_AUTH_USER_ALREADY_EXISTS"


class UserNotFoundError(DomainError):
    """No user matches the given identifier."""

    http_status = 404
    code = "ERR_AUTH_USER_NOT_FOUND"
