"""Django ORM model for tracking previous password hashes."""

from __future__ import annotations

from django.db import models


class PasswordHistory(models.Model):
    """Stores the last N hashed passwords per user to prevent reuse."""

    class Meta:
        db_table = '"iam"."password_history"'
        ordering = ["-created_at"]

    user_id = models.UUIDField(db_index=True)
    password_hash = models.CharField(max_length=128)
    created_at = models.DateTimeField(auto_now_add=True)
