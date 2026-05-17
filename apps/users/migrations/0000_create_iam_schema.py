"""Create the iam PostgreSQL schema before any table migrations run."""

from __future__ import annotations

from django.db import migrations


class Migration(migrations.Migration):
    """Must run before all table migrations in this app."""

    initial = True
    dependencies: list = []

    operations = [
        migrations.RunSQL(
            sql="CREATE SCHEMA IF NOT EXISTS iam;",
            reverse_sql="DROP SCHEMA IF EXISTS iam CASCADE;",
        ),
    ]
