"""Integration tests confirming mfa_type persists through the ORM."""

from __future__ import annotations

import pytest

from apps.users.infrastructure.models import User


@pytest.mark.django_db
def test_user_mfa_type_column_defaults_to_null():
    user = User.objects.create_user(
        email="mtype@example.com",
        password="testpass1",
        first_name="M",
        last_name="T",
    )
    user.refresh_from_db()
    assert user.mfa_type is None


@pytest.mark.django_db
def test_user_mfa_type_persists_totp():
    user = User.objects.create_user(
        email="mtype2@example.com",
        password="testpass1",
        first_name="M",
        last_name="T",
    )
    user.mfa_type = "totp"
    user.save()
    user.refresh_from_db()
    assert user.mfa_type == "totp"


@pytest.mark.django_db
def test_to_entity_maps_mfa_type():
    user = User.objects.create_user(
        email="mtype3@example.com",
        password="testpass1",
        first_name="M",
        last_name="T",
    )
    user.mfa_type = "sms"
    user.save()
    entity = user.to_entity()
    assert entity.mfa_type == "sms"
