"""Django ORM model for MFA backup codes."""

from __future__ import annotations

import uuid

from django.db import models


class MFABackupCode(models.Model):
    """A single-use hashed backup code for MFA recovery."""

    class Meta:
        db_table = "iam_mfa_backup_code"
        ordering = ["created_at"]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user_id = models.UUIDField(db_index=True)
    code_hash = models.CharField(max_length=128)
    created_at = models.DateTimeField(auto_now_add=True)
    used_at = models.DateTimeField(null=True, blank=True)

    @property
    def is_used(self) -> bool:
        """True when this code has already been consumed."""
        return self.used_at is not None
