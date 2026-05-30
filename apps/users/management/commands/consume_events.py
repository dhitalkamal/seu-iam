"""Management command: IAM service RabbitMQ event consumer."""

from __future__ import annotations

import json
import logging
import os
import uuid
from collections.abc import Callable

from django.core.management.base import BaseCommand

from apps.users.infrastructure.audit_models import AuditLog
from apps.users.infrastructure.org_role_client import OrgRoleClient

logger = logging.getLogger(__name__)


def _handle_member_event(payload: dict) -> None:
    """Invalidate the Redis org-role cache for the affected user.

    Called for org.member.added, org.member.removed, and org.member.role_changed.
    Silently no-ops if user_id is missing from the payload.
    """
    raw_user_id = payload.get("user_id")
    if not raw_user_id:
        logger.warning("org.member event payload missing user_id, skipping cache invalidation.")
        return
    try:
        user_id = uuid.UUID(str(raw_user_id))
    except ValueError:
        logger.warning("org.member event payload has invalid user_id %r, skipping.", raw_user_id)
        return
    OrgRoleClient().invalidate(user_id)
    logger.info("Invalidated org role cache for user %s.", user_id)


def _handle_audit_event(payload: dict) -> None:
    """Write a cross-service audit entry to iam_audit_log.

    Expected payload keys: user_id, event_type, ip_address, user_agent, metadata, timestamp.
    """
    raw_uid = payload.get("user_id")
    if not raw_uid:
        logger.warning("audit.log payload missing user_id, skipping.")
        return
    try:
        user_id = uuid.UUID(str(raw_uid))
    except ValueError:
        logger.warning("audit.log payload has invalid user_id %r, skipping.", raw_uid)
        return

    event_type = payload.get("event_type", "unknown")
    AuditLog.objects.create(
        id=uuid.uuid4(),
        user_id=user_id,
        event_type=event_type,
        ip_address=payload.get("ip_address"),
        user_agent=payload.get("user_agent"),
        metadata=payload.get("metadata") or {},
    )
    logger.info("Audit entry written: %s for user %s.", event_type, user_id)


# routing key -> handler function
_HANDLERS: dict[str, Callable[[dict], None]] = {
    "org.member.added": _handle_member_event,
    "org.member.removed": _handle_member_event,
    "org.member.role_changed": _handle_member_event,
    "audit.log": _handle_audit_event,
}


class Command(BaseCommand):
    """
    Listen for IAM-relevant domain events on the sansaar exchange.

    Handles:
    - org.member.added    - invalidate user org role cache
    - org.member.removed  - invalidate user org role cache
    - org.member.role_changed - invalidate user org role cache
    """

    help = "IAM service RabbitMQ consumer."

    def handle(self, *args: object, **options: object) -> None:
        """Connect to RabbitMQ and consume events until terminated."""
        import pika

        rabbitmq_url = os.getenv("RABBITMQ_URL", "amqp://guest:guest@localhost:5672/")
        self.stdout.write("IAM consumer started.")
        try:
            params = pika.URLParameters(rabbitmq_url)
            connection = pika.BlockingConnection(params)
            channel = connection.channel()
            channel.exchange_declare(exchange="sansaar", exchange_type="topic", durable=True)
            channel.queue_declare(queue="iam.events", durable=True)
            # bind existing iam.# routing
            channel.queue_bind(queue="iam.events", exchange="sansaar", routing_key="iam.#")
            # bind org.member.* events for cache invalidation
            channel.queue_bind(queue="iam.events", exchange="sansaar", routing_key="org.member.#")
            # bind cross-service audit events
            channel.queue_bind(queue="iam.events", exchange="sansaar", routing_key="audit.log")
            channel.basic_consume(
                queue="iam.events",
                on_message_callback=self._on_message,
                auto_ack=True,
            )
            channel.start_consuming()
        except KeyboardInterrupt:
            self.stdout.write("IAM consumer stopped.")
        except Exception:
            logger.exception("IAM consumer encountered an error.")

    @staticmethod
    def _on_message(channel: object, method: object, props: object, body: bytes) -> None:
        """Route the incoming message to the appropriate handler via _HANDLERS."""
        try:
            payload = json.loads(body)
        except Exception:
            logger.warning("IAM consumer received non-JSON message.")
            return

        routing_key: str = getattr(method, "routing_key", "")
        handler = _HANDLERS.get(routing_key)
        if handler is not None:
            try:
                handler(payload)
            except Exception:
                logger.exception("Handler for %s raised an error.", routing_key)
        else:
            logger.info("IAM consumer received unhandled event: %s", routing_key)
