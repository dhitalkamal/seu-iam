"""Django ORM model for platform announcements."""

from __future__ import annotations

import uuid

from django.db import models


class AnnouncementModel(models.Model):
    """Stores a platform-wide broadcast message with optional scheduling."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    title = models.CharField(max_length=300)
    body = models.TextField()
    # json array of plan slugs; empty = target all plans
    target_plans = models.JSONField(default=list)
    is_active = models.BooleanField(default=False, db_index=True)
    scheduled_at = models.DateTimeField(null=True, blank=True)
    published_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "announcements"
        ordering = ["-created_at"]
