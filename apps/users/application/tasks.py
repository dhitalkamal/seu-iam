"""Celery beat tasks for the users application."""

from __future__ import annotations

import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


def purge_expired_grace_period_accounts() -> int:
    """
    Anonymize accounts whose 30-day deletion grace period has elapsed.

    Intended to run once per day via Celery beat. Finds every user where
    is_active=False and scheduled_deletion_at <= now, then runs GDPR
    erasure on each one.

    Registration with Celery beat is left to the service operator because
    Celery is not yet configured in this service. Example beat schedule entry:

        "purge-expired-accounts": {
            "task": "apps.users.application.tasks.purge_expired_grace_period_accounts",
            "schedule": crontab(hour=3, minute=0),
        }

    @returns the number of accounts that were erased
    """
    # * import here to avoid circular imports at module load time
    from apps.users.application.use_cases.gdpr_erasure import GDPRErasureUseCase
    from apps.users.infrastructure.models import User
    from apps.users.infrastructure.repositories import UserRepository
    from apps.users.infrastructure.token_service import TokenBlacklistService

    now = datetime.now(timezone.utc)
    candidates = User.objects.filter(
        is_active=False,
        scheduled_deletion_at__lte=now,
        deleted_at__isnull=True,
    )

    erased = 0
    for orm_user in candidates:
        try:
            user_repo = UserRepository()
            blacklist_svc = TokenBlacklistService()
            GDPRErasureUseCase(user_repo, blacklist_svc).execute(
                user_id=orm_user.id,
                current_password=None,
            )
            erased += 1
            logger.info("GDPR erasure completed for user %s", orm_user.id)
        except Exception as exc:
            logger.error("GDPR erasure failed for user %s: %s", orm_user.id, exc)

    return erased
