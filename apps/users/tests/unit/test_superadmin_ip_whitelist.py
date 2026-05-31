"""Tests for IsSuperAdminFromAllowedIP permission class."""

from __future__ import annotations

from django.test import RequestFactory

from apps.common.permissions import IsSuperAdminFromAllowedIP


def _staff_user(is_staff: bool = True) -> object:
    """Return a minimal user-like object."""

    class _User:
        pass

    u = _User()
    u.is_staff = is_staff
    u.is_authenticated = True
    return u


def _make_request(ip: str, forwarded: str | None = None) -> object:
    """Build a request with the given IP."""
    factory = RequestFactory()
    request = factory.get("/")
    request.META["REMOTE_ADDR"] = ip
    if forwarded:
        request.META["HTTP_X_FORWARDED_FOR"] = forwarded
    request.user = _staff_user()
    return request


class TestIsSuperAdminFromAllowedIP:
    """Unit tests for the superadmin IP whitelist permission."""

    def test_allows_staff_from_whitelisted_ip(self, settings: object) -> None:
        """Staff user from a whitelisted IP should be permitted."""
        settings.SUPERADMIN_ALLOWED_IPS = ["10.0.0.1"]
        perm = IsSuperAdminFromAllowedIP()
        request = _make_request("10.0.0.1")
        assert perm.has_permission(request, None) is True

    def test_denies_staff_from_non_whitelisted_ip(self, settings: object) -> None:
        """Staff user from an unlisted IP should be denied."""
        settings.SUPERADMIN_ALLOWED_IPS = ["10.0.0.1"]
        perm = IsSuperAdminFromAllowedIP()
        request = _make_request("192.168.1.100")
        assert perm.has_permission(request, None) is False

    def test_denies_non_staff_even_from_whitelisted_ip(self, settings: object) -> None:
        """Non-staff user is denied regardless of IP."""
        settings.SUPERADMIN_ALLOWED_IPS = ["10.0.0.1"]
        perm = IsSuperAdminFromAllowedIP()
        request = _make_request("10.0.0.1")
        request.user = _staff_user(is_staff=False)
        assert perm.has_permission(request, None) is False

    def test_allows_all_when_whitelist_is_empty(self, settings: object) -> None:
        """Empty whitelist means no restriction; all staff IPs are accepted."""
        settings.SUPERADMIN_ALLOWED_IPS = []
        perm = IsSuperAdminFromAllowedIP()
        request = _make_request("1.2.3.4")
        assert perm.has_permission(request, None) is True

    def test_uses_x_forwarded_for_when_present(self, settings: object) -> None:
        """When X-Forwarded-For is set the first IP is used, not REMOTE_ADDR."""
        settings.SUPERADMIN_ALLOWED_IPS = ["203.0.113.5"]
        perm = IsSuperAdminFromAllowedIP()
        # REMOTE_ADDR is a proxy; real client IP is in X-Forwarded-For
        request = _make_request("10.0.0.99", forwarded="203.0.113.5, 10.0.0.99")
        assert perm.has_permission(request, None) is True

    def test_forwarded_for_non_whitelisted(self, settings: object) -> None:
        """X-Forwarded-For IP not in whitelist is denied."""
        settings.SUPERADMIN_ALLOWED_IPS = ["203.0.113.5"]
        perm = IsSuperAdminFromAllowedIP()
        request = _make_request("10.0.0.99", forwarded="1.1.1.1, 10.0.0.99")
        assert perm.has_permission(request, None) is False
