"""Django app config for the users module."""

from __future__ import annotations

from django.apps import AppConfig


class UsersConfig(AppConfig):
    """Registers the users app with Django."""

    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.users"
    label = "users"
