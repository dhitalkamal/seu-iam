"""Re-export ORM models so Django's app registry finds them under the users label."""

from __future__ import annotations

from apps.users.infrastructure.announcement_models import AnnouncementModel as Announcement
from apps.users.infrastructure.audit_models import AuditLog
from apps.users.infrastructure.backup_code_models import MFABackupCode
from apps.users.infrastructure.feature_flag_models import FeatureFlagModel
from apps.users.infrastructure.models import User
from apps.users.infrastructure.password_history_models import PasswordHistory
from apps.users.infrastructure.session_models import UserSession

__all__ = ["User", "AuditLog", "UserSession", "PasswordHistory", "MFABackupCode", "FeatureFlagModel", "Announcement"]
