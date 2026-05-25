"""Django ORM model for platform feature flags."""

from __future__ import annotations

from django.db import models


class FeatureFlagModel(models.Model):
    """Stores a named capability switch with per-plan and per-org scope."""

    key = models.SlugField(max_length=100, unique=True, db_index=True)
    name = models.CharField(max_length=200)
    description = models.TextField(blank=True, default="")
    is_enabled = models.BooleanField(default=False)
    # json arrays of plan slugs, e.g. ["pro", "enterprise"]
    enabled_plans = models.JSONField(default=list)
    # json arrays of org uuid strings
    enabled_org_ids = models.JSONField(default=list)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "feature_flags"
        ordering = ["key"]
