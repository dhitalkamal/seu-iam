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
    """Centralized registry of audit event type strings."""

    # * user / auth
    USER_REGISTERED = "user.registered"
    LOGIN_SUCCESS = "user.login_success"
    LOGIN_FAILED = "user.login_failed"
    LOGIN_MFA_CHALLENGED = "user.login_mfa_challenged"
    LOGIN_MFA_SUCCESS = "user.login_mfa_success"
    LOGOUT = "user.logout"
    SOCIAL_AUTH_GOOGLE = "user.social_auth_google"
    SOCIAL_AUTH_GITHUB = "user.social_auth_github"
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
    USER_SUSPENDED = "user.suspended"
    USER_ACTIVATED = "user.activated"

    # * events
    EVENT_CREATED = "event.created"
    EVENT_UPDATED = "event.updated"
    EVENT_PUBLISHED = "event.published"
    EVENT_COMPLETED = "event.completed"
    EVENT_DELETED = "event.deleted"
    CATEGORY_CREATED = "category.created"
    TAG_CREATED = "tag.created"

    # * organizations
    ORG_CREATED = "org.created"
    ORG_UPDATED = "org.updated"
    ORG_APPROVED = "org.approved"
    ORG_REJECTED = "org.rejected"
    ORG_SUSPENDED = "org.suspended"
    ORG_REINSTATED = "org.reinstated"
    ORG_DELETED = "org.deleted"
    ORG_MEMBER_ADDED = "org.member.added"
    ORG_MEMBER_REMOVED = "org.member.removed"
    ORG_INVITE_SENT = "org.invite.sent"
    ORG_INVITE_ACCEPTED = "org.invite.accepted"

    # * venues
    VENUE_CREATED = "venue.created"
    VENUE_UPDATED = "venue.updated"
    VENUE_DELETED = "venue.deleted"
    VENUE_BOOKING_CREATED = "venue.booking.created"
    VENUE_BOOKING_CANCELLED = "venue.booking.cancelled"

    # * community
    COMMUNITY_CREATED = "community.created"
    POST_CREATED = "post.created"
    POST_DELETED = "post.deleted"

    # * volunteers
    VOLUNTEER_ROLE_CREATED = "volunteer.role.created"
    VOLUNTEER_APPLICATION_SUBMITTED = "volunteer.application.submitted"
    VOLUNTEER_APPLICATION_APPROVED = "volunteer.application.approved"
    VOLUNTEER_APPLICATION_REJECTED = "volunteer.application.rejected"
    VOLUNTEER_SHIFT_CREATED = "volunteer.shift.created"

    # * marketing
    CAMPAIGN_CREATED = "campaign.created"
    CAMPAIGN_SENT = "campaign.sent"

    # * moderation
    MODERATION_CASE_CREATED = "moderation.case.created"
    MODERATION_CASE_UPDATED = "moderation.case.updated"

    # * compliance
    COMPLIANCE_CONTROL_CREATED = "compliance.control.created"
    COMPLIANCE_CONTROL_UPDATED = "compliance.control.updated"

    # * participation
    REGISTRATION_CREATED = "registration.created"
    REGISTRATION_CANCELLED = "registration.cancelled"
    CHECKIN_COMPLETED = "checkin.completed"
    TRANSFER_INITIATED = "transfer.initiated"
    TRANSFER_ACCEPTED = "transfer.accepted"

    # * payments
    ORDER_CREATED = "order.created"
    ORDER_COMPLETED = "order.completed"
    REFUND_REQUESTED = "refund.requested"
    SUBSCRIPTION_CREATED = "subscription.created"
    SUBSCRIPTION_CANCELLED = "subscription.cancelled"
    PROMO_CREATED = "promo.created"
    DISPUTE_CREATED = "dispute.created"
    DISPUTE_UPDATED = "dispute.updated"

    # * notifications
    PREFERENCE_UPDATED = "notification.preference.updated"
    DIGEST_CREATED = "notification.digest.created"
