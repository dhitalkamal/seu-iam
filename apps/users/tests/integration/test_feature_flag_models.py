"""Tests for the FeatureFlagModel ORM model."""

from __future__ import annotations

import pytest


@pytest.mark.django_db
def test_feature_flag_model_db_table() -> None:
    """FeatureFlagModel maps to the feature_flags table."""
    from apps.users.infrastructure.feature_flag_models import FeatureFlagModel

    assert FeatureFlagModel._meta.db_table == "feature_flags"


@pytest.mark.django_db
def test_feature_flag_model_create() -> None:
    """FeatureFlagModel can persist a row with default values."""
    from apps.users.infrastructure.feature_flag_models import FeatureFlagModel

    m = FeatureFlagModel.objects.create(key="smoke_test", name="Smoke Test")
    assert m.pk is not None
    assert m.is_enabled is False
    assert m.enabled_plans == []
    assert m.enabled_org_ids == []
