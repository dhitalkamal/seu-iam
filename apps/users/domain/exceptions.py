"""Domain errors raised by IAM use cases and never swallowed silently."""

from __future__ import annotations

from apps.common.api.exceptions import DomainError


class UserAlreadyExistsError(DomainError):
    """A user with that email address already exists."""

    http_status = 409
    code = "ERR_AUTH_USER_ALREADY_EXISTS"


class WeakPasswordError(DomainError):
    """The password does not meet the minimum security requirements."""

    http_status = 422
    code = "ERR_AUTH_WEAK_PASSWORD"


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


class EmailAlreadyVerifiedError(DomainError):
    """The user's email address is already verified."""

    http_status = 409
    code = "ERR_AUTH_EMAIL_ALREADY_VERIFIED"


class OTPExpiredError(DomainError):
    """The OTP has expired or was never issued."""

    http_status = 400
    code = "ERR_AUTH_OTP_EXPIRED"


class OTPInvalidError(DomainError):
    """The OTP does not match."""

    http_status = 400
    code = "ERR_AUTH_OTP_INVALID"


class SocialAuthError(DomainError):
    """The social identity token is invalid, expired, or untrusted."""

    http_status = 401
    code = "ERR_AUTH_SOCIAL_INVALID_TOKEN"


class MFAAlreadyEnabledError(DomainError):
    """MFA is already enabled on this account."""

    http_status = 409
    code = "ERR_AUTH_MFA_ALREADY_ENABLED"


class MFANotEnabledError(DomainError):
    """MFA is not enabled on this account."""

    http_status = 409
    code = "ERR_AUTH_MFA_NOT_ENABLED"


class InvalidTOTPError(DomainError):
    """The TOTP code is incorrect or has expired."""

    http_status = 400
    code = "ERR_AUTH_INVALID_TOTP"


class InvalidBackupCodeError(DomainError):
    """The backup code is incorrect or has already been used."""

    http_status = 400
    code = "ERR_AUTH_INVALID_BACKUP_CODE"


class NoBackupCodesError(DomainError):
    """All backup codes have been used. Regenerate to get new ones."""

    http_status = 400
    code = "ERR_AUTH_NO_BACKUP_CODES"
