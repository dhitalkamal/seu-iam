"""Unit tests for OrgRoleClient - Redis caching and management-service integration."""

from __future__ import annotations

import json
import uuid
from typing import TYPE_CHECKING
from unittest.mock import MagicMock, patch

if TYPE_CHECKING:
    from apps.users.infrastructure.org_role_client import OrgRoleClient


def _make_client(redis_mock: object) -> "OrgRoleClient":
    """Build an OrgRoleClient with an injected Redis mock."""
    from apps.users.infrastructure.org_role_client import OrgRoleClient

    return OrgRoleClient(redis_client=redis_mock)


def test_returns_cached_roles_on_hit() -> None:
    """When Redis has a cached entry, return it without hitting the management API."""
    user_id = uuid.uuid4()
    cached_roles = {"org-abc": "owner", "org-xyz": "member"}
    redis_mock = MagicMock()
    redis_mock.get.return_value = json.dumps(cached_roles).encode()

    client = _make_client(redis_mock)

    with patch("requests.get") as mock_get:
        result = client.get_org_roles(user_id)

    assert result == cached_roles
    mock_get.assert_not_called()
    redis_mock.get.assert_called_once_with(f"user_org_roles:{user_id}")


def test_fetches_from_api_on_cache_miss() -> None:
    """When Redis misses, fetch from the API and cache the result with TTL 300."""
    user_id = uuid.uuid4()
    api_roles = {"org-abc": "admin"}
    redis_mock = MagicMock()
    redis_mock.get.return_value = None

    response_mock = MagicMock()
    response_mock.status_code = 200
    response_mock.json.return_value = {"org_roles": api_roles}

    client = _make_client(redis_mock)

    with patch("requests.get", return_value=response_mock) as mock_get:
        result = client.get_org_roles(user_id)

    assert result == api_roles
    mock_get.assert_called_once()
    redis_mock.setex.assert_called_once_with(
        f"user_org_roles:{user_id}",
        300,
        json.dumps(api_roles),
    )


def test_returns_empty_dict_when_api_fails() -> None:
    """When the management-service call raises, return an empty dict without crashing."""
    user_id = uuid.uuid4()
    redis_mock = MagicMock()
    redis_mock.get.return_value = None

    client = _make_client(redis_mock)

    with patch("requests.get", side_effect=Exception("connection refused")):
        result = client.get_org_roles(user_id)

    assert result == {}


def test_invalidate_deletes_cache_key() -> None:
    """invalidate() must call redis.delete with the correct cache key."""
    user_id = uuid.uuid4()
    redis_mock = MagicMock()

    client = _make_client(redis_mock)
    client.invalidate(user_id)

    redis_mock.delete.assert_called_once_with(f"user_org_roles:{user_id}")
