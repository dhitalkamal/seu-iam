"""Custom DRF permission classes for role-based access control."""

from __future__ import annotations

from django.conf import settings
from rest_framework.permissions import BasePermission
from rest_framework.request import Request


def _get_client_ip(request: Request) -> str:
    """Extract the real client IP, preferring X-Forwarded-For over REMOTE_ADDR."""
    forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR", "")


class IsSuperAdminFromAllowedIP(BasePermission):
    """Allow access only to staff users whose IP is in SUPERADMIN_ALLOWED_IPS.

    If SUPERADMIN_ALLOWED_IPS is empty, no IP restriction is applied (dev-friendly
    default). In production the setting should list specific trusted IPs.
    """

    message = "Access denied: insufficient privileges or IP not whitelisted."

    def has_permission(self, request: Request, view: object) -> bool:
        """Return True only if the user is staff and their IP is allowed."""
        if not getattr(request.user, "is_staff", False):
            return False
        allowed: list[str] = getattr(settings, "SUPERADMIN_ALLOWED_IPS", [])
        if not allowed:
            return True
        return _get_client_ip(request) in allowed
