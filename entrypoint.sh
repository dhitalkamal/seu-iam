#!/bin/sh
set -e
uv run python manage.py migrate --noinput
uv run python manage.py seed_superadmin
exec uv run gunicorn config.wsgi:application --bind 0.0.0.0:8001 --workers 2
