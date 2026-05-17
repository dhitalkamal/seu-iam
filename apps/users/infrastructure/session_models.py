"""Django ORM model for tracking user sessions with device metadata."""

from __future__ import annotations

from django.db import models


class UserSession(models.Model):
    """Tracks an issued refresh token with device context for session management."""

    class Meta:
        db_table = '"iam"."user_session"'
        ordering = ["-created_at"]

    jti = models.UUIDField(primary_key=True)
    user_id = models.UUIDField(db_index=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    last_seen_at = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=True, db_index=True)
