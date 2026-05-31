"""Unit tests for org.member.* event handlers that invalidate the Redis role cache."""

from __future__ import annotations

import uuid
from unittest.mock import MagicMock, patch


def test_member_added_invalidates_cache() -> None:
    """Receiving an org.member.added event must call OrgRoleClient.invalidate with the user_id."""
    from apps.users.management.commands.consume_events import _handle_member_event

    user_id = uuid.uuid4()
    payload = {"user_id": str(user_id), "org_id": "org-abc", "role": "member"}

    with patch("apps.users.management.commands.consume_events.OrgRoleClient") as mock_client:
        instance = MagicMock()
        mock_client.return_value = instance

        _handle_member_event(payload)

    instance.invalidate.assert_called_once_with(uuid.UUID(str(user_id)))


def test_ignores_payload_without_user_id() -> None:
    """A payload missing user_id must not call OrgRoleClient.invalidate at all."""
    from apps.users.management.commands.consume_events import _handle_member_event

    payload = {"org_id": "org-abc", "role": "member"}

    with patch("apps.users.management.commands.consume_events.OrgRoleClient") as mock_client:
        instance = MagicMock()
        mock_client.return_value = instance

        _handle_member_event(payload)

    instance.invalidate.assert_not_called()
