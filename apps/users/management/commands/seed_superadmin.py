"""Management command: create the default superadmin on first boot if absent."""

from __future__ import annotations

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand

User = get_user_model()

# credentials seeded via this command; override via env vars for non-default envs
DEFAULT_EMAIL = "kamaldhitalofficial@gmail.com"
DEFAULT_PASSWORD = "Kamal123@@@@"
DEFAULT_FIRST = "Kamal"
DEFAULT_LAST = "Dhital"


class Command(BaseCommand):
    """Create the platform superadmin account if one does not already exist."""

    help = "Seed a default superadmin user on first boot"

    def handle(self, *args: object, **options: object) -> None:
        if User.objects.filter(is_superuser=True).exists():
            self.stdout.write("superadmin already exists, skipping seed")
            return

        User.objects.create_superuser(
            email=DEFAULT_EMAIL,
            password=DEFAULT_PASSWORD,
            first_name=DEFAULT_FIRST,
            last_name=DEFAULT_LAST,
        )
        self.stdout.write(self.style.SUCCESS(f"created superadmin: {DEFAULT_EMAIL}"))

        self._seed_feature_flags()

    def _seed_feature_flags(self) -> None:
        """Create the maintenance_mode flag if it doesn't exist."""
        from apps.users.infrastructure.feature_flag_models import FeatureFlagModel as FeatureFlag

        _, created = FeatureFlag.objects.get_or_create(
            key="maintenance_mode",
            defaults={
                "key": "maintenance_mode",
                "name": "Maintenance mode",
                "description": "Show maintenance page to all users",
                "is_enabled": False,
            },
        )
        if created:
            self.stdout.write("  seeded flag: maintenance_mode")
