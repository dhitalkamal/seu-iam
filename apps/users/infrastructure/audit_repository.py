"""Concrete audit log repository backed by the Django ORM."""

from __future__ import annotations

import uuid

from apps.users.domain.audit import AuditLogEntry, IAuditLogRepository
from apps.users.infrastructure.audit_models import AuditLog


class DjangoAuditLogRepository(IAuditLogRepository):
    """Persists AuditLogEntry records using the Django ORM."""

    def create(self, entry: AuditLogEntry) -> AuditLogEntry:
        """Write a new audit log row and return the entry."""
        AuditLog.objects.create(
            id=entry.id,
            user_id=entry.user_id,
            event_type=entry.event_type,
            ip_address=entry.ip_address,
            user_agent=entry.user_agent,
            metadata=entry.metadata,
        )
        return entry

    def list_for_user(self, user_id: uuid.UUID) -> list[AuditLogEntry]:
        """Return all entries for the user, most recent first."""
        return [row.to_entry() for row in AuditLog.objects.filter(user_id=user_id)]
