"""Service for generating, verifying, and revoking MFA backup codes."""

from __future__ import annotations

import secrets
import string
import uuid

from django.contrib.auth.hashers import check_password, make_password
from django.utils import timezone

from apps.users.domain.exceptions import InvalidBackupCodeError, NoBackupCodesError
from apps.users.infrastructure.backup_code_models import MFABackupCode

_ALPHABET = string.ascii_uppercase + string.digits
_CODE_LENGTH = 8
_CODES_PER_USER = 10


def _generate_raw_code() -> str:
    """Return a cryptographically random 8-char alphanumeric code."""
    return "".join(secrets.choice(_ALPHABET) for _ in range(_CODE_LENGTH))


class BackupCodeService:
    """Manages the lifecycle of MFA backup codes for a user."""

    def generate(self, user_id: uuid.UUID) -> list[str]:
        """
        Delete all existing codes and generate a fresh set.

        Returns the plaintext codes; these are shown once and never stored in plain text.
        """
        MFABackupCode.objects.filter(user_id=user_id).delete()
        raw_codes = [_generate_raw_code() for _ in range(_CODES_PER_USER)]
        MFABackupCode.objects.bulk_create([MFABackupCode(user_id=user_id, code_hash=make_password(code)) for code in raw_codes])
        return raw_codes

    def verify_and_consume(self, user_id: uuid.UUID, code: str) -> None:
        """
        Check the code against all unused backup codes for the user.

        Marks it as used on success.
        Raises NoBackupCodesError if none remain, InvalidBackupCodeError if no match.
        """
        unused = MFABackupCode.objects.filter(user_id=user_id, used_at__isnull=True)
        if not unused.exists():
            raise NoBackupCodesError("No backup codes remaining. Please regenerate.")

        for entry in unused:
            if check_password(code, entry.code_hash):
                entry.used_at = timezone.now()
                entry.save(update_fields=["used_at"])
                return

        raise InvalidBackupCodeError("Backup code is incorrect or already used.")

    def remaining_count(self, user_id: uuid.UUID) -> int:
        """Return the number of unused backup codes for the user."""
        return MFABackupCode.objects.filter(user_id=user_id, used_at__isnull=True).count()
