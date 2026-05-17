"""Use case: export all personal data for a user (GDPR Article 15)."""

from __future__ import annotations

import uuid

from apps.users.domain.audit import IAuditLogRepository
from apps.users.domain.repositories import IUserRepository


class GDPRExportUseCase:
    """Compile all personal data held for the user into a structured dict."""

    def __init__(
        self,
        user_repo: IUserRepository,
        audit_repo: IAuditLogRepository,
    ) -> None:
        self._users = user_repo
        self._audit = audit_repo

    def execute(self, user_id: uuid.UUID) -> dict:
        """
        Return all personal data for the user.

        @param user_id - the authenticated user's ID
        @returns dict with profile and audit_logs sections
        """
        user = self._users.get_by_id(user_id)
        audit_entries = self._audit.list_for_user(user_id)

        return {
            "profile": {
                "id": str(user.id),
                "email": user.email,
                "first_name": user.first_name,
                "last_name": user.last_name,
                "avatar_url": user.avatar_url,
                "is_email_verified": user.is_email_verified,
                "mfa_enabled": user.mfa_enabled,
                "date_joined": user.date_joined.isoformat(),
                "updated_at": user.updated_at.isoformat(),
            },
            "audit_logs": [
                {
                    "event_type": e.event_type,
                    "ip_address": e.ip_address,
                    "user_agent": e.user_agent,
                    "metadata": e.metadata,
                    "created_at": e.created_at.isoformat(),
                }
                for e in audit_entries
            ],
        }
