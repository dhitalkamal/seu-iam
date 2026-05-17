"""Audit log domain entity and repository interface."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class AuditLogEntry:
    """Immutable record of a security-relevant user action."""

    id: uuid.UUID
    user_id: uuid.UUID
    event_type: str
    ip_address: str | None
    user_agent: str | None
    metadata: dict
    created_at: datetime


class IAuditLogRepository:
    """Persists audit log entries."""

    def create(self, entry: AuditLogEntry) -> AuditLogEntry:
        """Persist a new audit log entry and return it."""
        raise NotImplementedError

    def list_for_user(self, user_id: uuid.UUID) -> list[AuditLogEntry]:
        """Return all audit entries for the given user, ordered by most recent first."""
        raise NotImplementedError


class AuditEventType:
    """Centralised registry of audit event type strings."""

    USER_REGISTERED = "user.registered"
    LOGIN_SUCCESS = "user.login_success"
    LOGIN_FAILED = "user.login_failed"
    LOGIN_MFA_CHALLENGED = "user.login_mfa_challenged"
    LOGIN_MFA_SUCCESS = "user.login_mfa_success"
    LOGOUT = "user.logout"
    SOCIAL_AUTH_GOOGLE = "user.social_auth_google"
    PASSWORD_CHANGED = "user.password_changed"
    PASSWORD_RESET_REQUESTED = "user.password_reset_requested"
    PASSWORD_RESET_COMPLETED = "user.password_reset_completed"
    MFA_ENABLED = "user.mfa_enabled"
    MFA_DISABLED = "user.mfa_disabled"
    ACCOUNT_LOCKED = "user.account_locked"
    EMAIL_VERIFIED = "user.email_verified"
    SESSION_REVOKED = "user.session_revoked"
    ALL_SESSIONS_REVOKED = "user.all_sessions_revoked"
    PROFILE_UPDATED = "user.profile_updated"
    GDPR_EXPORT_REQUESTED = "user.gdpr_export_requested"
    GDPR_ERASURE_COMPLETED = "user.gdpr_erasure_completed"
    ACCOUNT_DELETED = "user.account_deleted"
