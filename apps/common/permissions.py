"""Custom DRF permission classes for role-based access control."""

from __future__ import annotations

from django.conf import settings
from rest_framework.permissions import BasePermission
from rest_framework.request import Request


class IsSuperAdminFromAllowedIP(BasePermission):
    """Allow access only to staff users whose IP is in SUPERADMIN_ALLOWED_IPS.

    When SUPERADMIN_ALLOWED_IPS is empty, all staff IPs are accepted.
    The real client IP is taken from X-Forwarded-For when present (first entry),
    falling back to REMOTE_ADDR.
    """

    def has_permission(self, request: Request, view: object) -> bool:
        """Return True if the request comes from a staff user on an allowed IP."""
        if not getattr(request.user, "is_staff", False):
            return False

        allowed: list[str] = getattr(settings, "SUPERADMIN_ALLOWED_IPS", [])
        if not allowed:
            return True

        forwarded = request.META.get("HTTP_X_FORWARDED_FOR")
        if forwarded:
            client_ip = forwarded.split(",")[0].strip()
        else:
            client_ip = request.META.get("REMOTE_ADDR", "")

        return client_ip in allowed
