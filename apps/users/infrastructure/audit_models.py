"""Django ORM model for persisting audit log entries."""

from __future__ import annotations

import uuid

from django.db import models

from apps.users.domain.audit import AuditLogEntry


class AuditLog(models.Model):
    """Security audit trail entry stored in the iam schema."""

    class Meta:
        db_table = '"iam"."audit_log"'
        ordering = ["-created_at"]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user_id = models.UUIDField(db_index=True)
    event_type = models.CharField(max_length=64, db_index=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True, null=True)
    metadata = models.JSONField(default=dict)
    created_at = models.DateTimeField(auto_now_add=True)

    def to_entry(self) -> AuditLogEntry:
        """Convert this ORM row to a pure domain AuditLogEntry."""
        return AuditLogEntry(
            id=self.id,
            user_id=self.user_id,
            event_type=self.event_type,
            ip_address=self.ip_address,
            user_agent=self.user_agent,
            metadata=self.metadata,
            created_at=self.created_at,
        )
