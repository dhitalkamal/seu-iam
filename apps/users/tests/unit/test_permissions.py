"""Tests for IsSuperAdminFromAllowedIP permission class."""

from __future__ import annotations

from typing import Any

from django.http import HttpRequest
from django.test import RequestFactory

from apps.common.permissions import IsSuperAdminFromAllowedIP


class _FakeUser:
    """Minimal stand-in for the Django user object."""

    def __init__(self, is_staff: bool = True) -> None:
        self.is_staff = is_staff
        self.is_authenticated = True


def _make_request(ip: str, forwarded: str | None = None) -> HttpRequest:
    """Build a request with the given IP and a default staff user."""
    factory = RequestFactory()
    request = factory.get("/")
    request.META["REMOTE_ADDR"] = ip
    if forwarded:
        request.META["HTTP_X_FORWARDED_FOR"] = forwarded
    request.user = _FakeUser()  # type: ignore[assignment]
    return request


class TestIsSuperAdminFromAllowedIP:
    """Unit tests for the superadmin IP whitelist permission."""

    def test_allows_staff_from_whitelisted_ip(self, settings: Any) -> None:
        """Staff user from a whitelisted IP should be permitted."""
        settings.SUPERADMIN_ALLOWED_IPS = ["10.0.0.1"]
        perm = IsSuperAdminFromAllowedIP()
        request = _make_request("10.0.0.1")
        assert perm.has_permission(request, None) is True  # type: ignore[arg-type]

    def test_denies_staff_from_non_whitelisted_ip(self, settings: Any) -> None:
        """Staff user from an unlisted IP should be denied."""
        settings.SUPERADMIN_ALLOWED_IPS = ["10.0.0.1"]
        perm = IsSuperAdminFromAllowedIP()
        request = _make_request("192.168.1.100")
        assert perm.has_permission(request, None) is False  # type: ignore[arg-type]

    def test_denies_non_staff_even_from_whitelisted_ip(self, settings: Any) -> None:
        """Non-staff user is denied regardless of IP."""
        settings.SUPERADMIN_ALLOWED_IPS = ["10.0.0.1"]
        perm = IsSuperAdminFromAllowedIP()
        request = _make_request("10.0.0.1")
        request.user = _FakeUser(is_staff=False)  # type: ignore[assignment]
        assert perm.has_permission(request, None) is False  # type: ignore[arg-type]

    def test_allows_all_when_whitelist_is_empty(self, settings: Any) -> None:
        """Empty whitelist means no restriction; all staff IPs are accepted."""
        settings.SUPERADMIN_ALLOWED_IPS = []
        perm = IsSuperAdminFromAllowedIP()
        request = _make_request("1.2.3.4")
        assert perm.has_permission(request, None) is True  # type: ignore[arg-type]

    def test_uses_x_forwarded_for_when_present(self, settings: Any) -> None:
        """When X-Forwarded-For is set the first IP is used, not REMOTE_ADDR."""
        settings.SUPERADMIN_ALLOWED_IPS = ["203.0.113.5"]
        perm = IsSuperAdminFromAllowedIP()
        request = _make_request("10.0.0.99", forwarded="203.0.113.5, 10.0.0.99")
        assert perm.has_permission(request, None) is True  # type: ignore[arg-type]

    def test_forwarded_for_non_whitelisted(self, settings: Any) -> None:
        """X-Forwarded-For IP not in whitelist is denied."""
        settings.SUPERADMIN_ALLOWED_IPS = ["203.0.113.5"]
        perm = IsSuperAdminFromAllowedIP()
        request = _make_request("10.0.0.99", forwarded="1.1.1.1, 10.0.0.99")
        assert perm.has_permission(request, None) is False  # type: ignore[arg-type]
