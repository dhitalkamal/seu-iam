"""Unit tests confirming JWTTokenService embeds org_roles claim in generated tokens."""

from __future__ import annotations

import uuid
from unittest.mock import MagicMock, patch


def _make_refresh_mock() -> MagicMock:
    """Build a simplejwt RefreshToken-like mock that tracks setitem calls.

    Dunder method assignment on MagicMock must go through the class, not the
    instance, which is why we configure them here via type: ignore comments.
    """
    claims: dict = {}
    access_claims: dict = {}

    def refresh_setitem(key: str, value: object) -> None:
        claims[key] = value

    def refresh_getitem(key: str) -> object:
        return claims[key]

    def access_setitem(key: str, value: object) -> None:
        access_claims[key] = value

    def access_getitem(key: str) -> object:
        return access_claims[key]

    # access_token mock
    access_token_mock = MagicMock()
    type(access_token_mock).__setitem__ = MagicMock(side_effect=access_setitem)  # type: ignore[assignment]
    type(access_token_mock).__getitem__ = MagicMock(side_effect=access_getitem)  # type: ignore[assignment]
    type(access_token_mock).__str__ = MagicMock(return_value="fake-access-str")  # type: ignore[assignment]

    # refresh token mock
    refresh_mock = MagicMock()
    type(refresh_mock).__setitem__ = MagicMock(side_effect=refresh_setitem)  # type: ignore[assignment]
    type(refresh_mock).__getitem__ = MagicMock(side_effect=refresh_getitem)  # type: ignore[assignment]
    type(refresh_mock).__str__ = MagicMock(return_value="fake-refresh-str")  # type: ignore[assignment]
    refresh_mock.access_token = access_token_mock

    refresh_mock._claims = claims
    refresh_mock._access_claims = access_claims
    return refresh_mock


def _make_user_mock(user_id: uuid.UUID) -> MagicMock:
    """Build a minimal User-like mock for the token service."""
    user = MagicMock()
    user.pk = user_id
    user.id = user_id
    user.email = "rbac@example.com"
    user.is_staff = False
    user.is_superuser = False
    return user


def test_access_token_contains_org_roles() -> None:
    """The access token must carry an org_roles claim populated from OrgRoleClient."""
    from apps.users.infrastructure.token_service import JWTTokenService

    user_id = uuid.uuid4()
    user_mock = _make_user_mock(user_id)
    refresh_mock = _make_refresh_mock()
    org_roles = {"org-abc": "owner", "org-xyz": "member"}

    with (
        patch(
            "apps.users.infrastructure.models.User.objects.get",
            return_value=user_mock,
        ),
        patch(
            "apps.users.infrastructure.token_service.RefreshToken.for_user",
            return_value=refresh_mock,
        ),
        patch("apps.users.infrastructure.token_service.OrgRoleClient") as mock_client,
    ):
        instance = MagicMock()
        instance.get_org_roles.return_value = org_roles
        mock_client.return_value = instance

        JWTTokenService().generate_for_user(user_id)

    # verify org_roles was captured in both claim dicts via the side_effect closures
    assert refresh_mock._claims.get("org_roles") == org_roles
    assert refresh_mock._access_claims.get("org_roles") == org_roles


def test_empty_org_roles_when_no_memberships() -> None:
    """When the user has no org memberships, org_roles claim must be an empty dict."""
    from apps.users.infrastructure.token_service import JWTTokenService

    user_id = uuid.uuid4()
    user_mock = _make_user_mock(user_id)
    refresh_mock = _make_refresh_mock()

    with (
        patch(
            "apps.users.infrastructure.models.User.objects.get",
            return_value=user_mock,
        ),
        patch(
            "apps.users.infrastructure.token_service.RefreshToken.for_user",
            return_value=refresh_mock,
        ),
        patch("apps.users.infrastructure.token_service.OrgRoleClient") as mock_client,
    ):
        instance = MagicMock()
        instance.get_org_roles.return_value = {}
        mock_client.return_value = instance

        JWTTokenService().generate_for_user(user_id)

    assert refresh_mock._claims.get("org_roles") == {}
    assert refresh_mock._access_claims.get("org_roles") == {}
