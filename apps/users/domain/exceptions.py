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


class InvalidCredentialsError(DomainError):
    """Email and password combination is incorrect."""

    http_status = 401
    code = "ERR_AUTH_INVALID_CREDENTIALS"


class AccountNotVerifiedError(DomainError):
    """The account email has not been verified yet."""

    http_status = 401
    code = "ERR_AUTH_ACCOUNT_NOT_VERIFIED"


class AccountInactiveError(DomainError):
    """The account has been deactivated."""

    http_status = 403
    code = "ERR_AUTH_ACCOUNT_INACTIVE"


class AccountLockedError(DomainError):
    """Too many failed login attempts. Account is temporarily locked."""

    http_status = 423
    code = "ERR_AUTH_ACCOUNT_LOCKED"


class InvalidTokenError(DomainError):
    """The token is missing, already used, or expired."""

    http_status = 400
    code = "ERR_AUTH_INVALID_TOKEN"
