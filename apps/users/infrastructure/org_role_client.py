"""Client for fetching org roles from management-service with Redis caching."""

from __future__ import annotations

import json
import logging
import uuid

import requests
from django.conf import settings

logger = logging.getLogger(__name__)

_CACHE_TTL = 300  # 5 minutes
_CACHE_PREFIX = "user_org_roles"
_REQUEST_TIMEOUT = 5


class OrgRoleClient:
    """Fetches a user's org roles, backed by Redis cache."""

    def __init__(self, redis_client: object | None = None) -> None:
        """Accept an optional Redis client for injection (tests pass a mock here)."""
        self._redis = redis_client

    def _get_redis(self) -> object:
        """Lazy-load Redis client from Django cache backend."""
        if self._redis is not None:
            return self._redis
        from django.core.cache import cache

        self._redis = cache.client.get_client()
        return self._redis

    def get_org_roles(self, user_id: uuid.UUID) -> dict[str, str]:
        """Return {org_id: role} for the user, using cache when available."""
        cache_key = f"{_CACHE_PREFIX}:{user_id}"
        redis = self._get_redis()
        cached = redis.get(cache_key)
        if cached:
            return json.loads(cached)
        org_roles = self._fetch_from_api(user_id)
        redis.setex(cache_key, _CACHE_TTL, json.dumps(org_roles))
        return org_roles

    def invalidate(self, user_id: uuid.UUID) -> None:
        """Delete cached org roles for a user."""
        cache_key = f"{_CACHE_PREFIX}:{user_id}"
        redis = self._get_redis()
        redis.delete(cache_key)

    def _fetch_from_api(self, user_id: uuid.UUID) -> dict[str, str]:
        """Call management-service internal endpoint."""
        url = f"{settings.MANAGEMENT_SERVICE_URL}/org/api/v1/internal/users/{user_id}/org-roles/"
        try:
            resp = requests.get(url, timeout=_REQUEST_TIMEOUT)
            if resp.status_code == 200:
                return resp.json().get("org_roles", {})
            logger.warning(
                "Management-service returned %s for org roles of %s",
                resp.status_code,
                user_id,
            )
            return {}
        except Exception:
            logger.warning(
                "Failed to fetch org roles from management-service for %s",
                user_id,
                exc_info=True,
            )
            return {}
