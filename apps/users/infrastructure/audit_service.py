"""Thin service for creating audit log entries from views."""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone

from rest_framework.request import Request

from apps.users.domain.audit import AuditLogEntry, IAuditLogRepository

logger = logging.getLogger(__name__)


def _get_ip(request: Request) -> str | None:
    """Extract the real client IP, respecting X-Forwarded-For from the gateway."""
    forwarded = request.META.get("HTTP_X_FORWARDED_FOR")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR")


def _get_ua(request: Request) -> str | None:
    """Extract the User-Agent header."""
    return request.META.get("HTTP_USER_AGENT")


class AuditService:
    """Creates and persists audit log entries, swallowing errors to never block responses."""

    def __init__(self, repo: IAuditLogRepository) -> None:
        self._repo = repo

    def log(
        self,
        request: Request,
        user_id: uuid.UUID,
        event_type: str,
        metadata: dict | None = None,
    ) -> None:
        """Persist an audit entry. Logs a warning and continues if persistence fails."""
        try:
            self._repo.create(
                AuditLogEntry(
                    id=uuid.uuid4(),
                    user_id=user_id,
                    event_type=event_type,
                    ip_address=_get_ip(request),
                    user_agent=_get_ua(request),
                    metadata=metadata or {},
                    created_at=datetime.now(timezone.utc),
                )
            )
        except Exception:
            logger.warning("Failed to write audit log entry for %s.", event_type, exc_info=True)
