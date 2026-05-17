"""Unit tests for password history, GDPR export, and GDPR erasure use cases."""

from __future__ import annotations

import pytest
from django.contrib.auth.hashers import make_password

from apps.users.application.use_cases.gdpr_erasure import GDPRErasureUseCase
from apps.users.application.use_cases.gdpr_export import GDPRExportUseCase
from apps.users.domain.audit import AuditEventType, AuditLogEntry, IAuditLogRepository
from apps.users.domain.exceptions import InvalidCredentialsError
from apps.users.tests.unit.fakes import FakeTokenBlacklistService, FakeUserRepository, make_user


# minimal in-memory audit repo for tests
class FakeAuditRepo(IAuditLogRepository):
    """In-memory audit log repository."""

    def __init__(self) -> None:
        self.entries: list[AuditLogEntry] = []

    def create(self, entry: AuditLogEntry) -> AuditLogEntry:
        self.entries.append(entry)
        return entry

    def list_for_user(self, user_id: object) -> list[AuditLogEntry]:
        return [e for e in self.entries if e.user_id == user_id]


# GDPR export


def test_gdpr_export_returns_profile_and_empty_audit():
    """Export returns user profile fields and an empty audit list when none exist."""
    user = make_user()
    repo = FakeUserRepository([user])
    audit = FakeAuditRepo()

    result = GDPRExportUseCase(repo, audit).execute(user_id=user.id)

    assert result["profile"]["email"] == user.email
    assert result["profile"]["first_name"] == user.first_name
    assert result["audit_logs"] == []


def test_gdpr_export_includes_audit_entries():
    """Export includes all audit log entries for the user."""
    import uuid
    from datetime import datetime, timezone

    user = make_user()
    repo = FakeUserRepository([user])
    audit = FakeAuditRepo()
    entry = AuditLogEntry(
        id=uuid.uuid4(),
        user_id=user.id,
        event_type=AuditEventType.LOGIN_SUCCESS,
        ip_address="1.2.3.4",
        user_agent="test",
        metadata={},
        created_at=datetime.now(timezone.utc),
    )
    audit.create(entry)

    result = GDPRExportUseCase(repo, audit).execute(user_id=user.id)

    assert len(result["audit_logs"]) == 1
    assert result["audit_logs"][0]["event_type"] == AuditEventType.LOGIN_SUCCESS


# GDPR erasure


def test_gdpr_erasure_anonymises_pii():
    """After erasure email, name, and avatar are replaced with anonymised values."""
    user = make_user(password_hash=make_password("TestPass1!"))
    repo = FakeUserRepository([user])

    GDPRErasureUseCase(repo, FakeTokenBlacklistService()).execute(
        user_id=user.id, current_password="TestPass1!"
    )

    updated = repo.get_by_id(user.id)
    assert "redacted.sansaar.com" in updated.email
    assert updated.first_name == "Deleted"
    assert updated.avatar_url is None
    assert updated.is_active is False
    assert updated.deleted_at is not None


def test_gdpr_erasure_blacklists_all_sessions():
    """All sessions are invalidated after erasure."""
    user = make_user(password_hash=make_password("TestPass1!"))
    repo = FakeUserRepository([user])
    blacklist = FakeTokenBlacklistService()

    GDPRErasureUseCase(repo, blacklist).execute(user_id=user.id, current_password="TestPass1!")

    assert user.id in blacklist.invalidated_users


def test_gdpr_erasure_rejects_wrong_password():
    """Erasure is rejected when the password confirmation is wrong."""
    user = make_user(password_hash=make_password("TestPass1!"))
    repo = FakeUserRepository([user])

    with pytest.raises(InvalidCredentialsError):
        GDPRErasureUseCase(repo, FakeTokenBlacklistService()).execute(
            user_id=user.id, current_password="WrongPass!"
        )


def test_gdpr_erasure_social_auth_user_exempt_from_password():
    """Social auth users (unusable password) can erase without providing a password."""
    user = make_user(password_hash=make_password(None))
    repo = FakeUserRepository([user])

    GDPRErasureUseCase(repo, FakeTokenBlacklistService()).execute(
        user_id=user.id, current_password=None
    )

    assert repo.get_by_id(user.id).is_active is False
