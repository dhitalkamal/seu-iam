"""Session management service backed by UserSession and simplejwt OutstandingToken."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime

from django.utils import timezone as dj_timezone
from rest_framework.request import Request

from apps.users.infrastructure.session_models import UserSession


@dataclass
class SessionInfo:
    """Public representation of an active session for the list endpoint."""

    jti: uuid.UUID
    ip_address: str | None
    user_agent: str | None
    created_at: datetime
    last_seen_at: datetime


def _get_ip(request: Request) -> str | None:
    forwarded = request.META.get("HTTP_X_FORWARDED_FOR")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR")


def _get_ua(request: Request) -> str | None:
    return request.META.get("HTTP_USER_AGENT")


class SessionService:
    """Creates, updates, and revokes UserSession records."""

    def create_session(self, request: Request, user_id: uuid.UUID, jti: uuid.UUID) -> None:
        """Persist a new session record when a refresh token is issued."""
        UserSession.objects.create(
            jti=jti,
            user_id=user_id,
            ip_address=_get_ip(request),
            user_agent=_get_ua(request),
        )

    def touch_session(self, jti: uuid.UUID) -> None:
        """Update last_seen_at when a token refresh occurs."""
        UserSession.objects.filter(jti=jti, is_active=True).update(last_seen_at=dj_timezone.now())

    def revoke_session(self, jti: uuid.UUID, user_id: uuid.UUID) -> bool:
        """Mark a specific session inactive. Returns True if it existed and was active."""
        updated = UserSession.objects.filter(jti=jti, user_id=user_id, is_active=True).update(
            is_active=False
        )
        return updated > 0

    def revoke_all_for_user(self, user_id: uuid.UUID) -> None:
        """Mark all sessions for the user as inactive."""
        UserSession.objects.filter(user_id=user_id, is_active=True).update(is_active=False)

    def list_active_sessions(self, user_id: uuid.UUID) -> list[SessionInfo]:
        """Return all active sessions for the user, most recent first."""
        rows = UserSession.objects.filter(user_id=user_id, is_active=True)
        return [
            SessionInfo(
                jti=row.jti,
                ip_address=row.ip_address,
                user_agent=row.user_agent,
                created_at=row.created_at,
                last_seen_at=row.last_seen_at,
            )
            for row in rows
        ]
