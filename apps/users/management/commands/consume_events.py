"""Management command: IAM service RabbitMQ event consumer."""

from __future__ import annotations

import json
import logging
import os

from django.core.management.base import BaseCommand

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    """
    Listen for IAM-relevant domain events on the sansaar exchange.

    Currently handles:
    - No external events consumed (IAM is the source of identity events)
    - Keeps the container alive and ready for future event subscriptions
    """

    help = "IAM service RabbitMQ consumer (standby mode)."

    def handle(self, *args: object, **options: object) -> None:
        """Connect to RabbitMQ and idle until terminated."""
        import pika

        rabbitmq_url = os.getenv("RABBITMQ_URL", "amqp://guest:guest@localhost:5672/")
        self.stdout.write("IAM consumer started (standby - no events to consume).")
        try:
            params = pika.URLParameters(rabbitmq_url)
            connection = pika.BlockingConnection(params)
            channel = connection.channel()
            channel.exchange_declare(exchange="sansaar", exchange_type="topic", durable=True)
            channel.queue_declare(queue="iam.events", durable=True)
            channel.queue_bind(queue="iam.events", exchange="sansaar", routing_key="iam.#")
            channel.basic_consume(
                queue="iam.events",
                on_message_callback=self._handle,
                auto_ack=True,
            )
            channel.start_consuming()
        except KeyboardInterrupt:
            self.stdout.write("IAM consumer stopped.")
        except Exception:
            logger.exception("IAM consumer encountered an error.")

    @staticmethod
    def _handle(channel: object, method: object, props: object, body: bytes) -> None:
        """Log received events for observability."""
        try:
            payload = json.loads(body)
            logger.info("IAM consumer received event: %s", payload.get("event_type", "unknown"))
        except Exception:
            logger.warning("IAM consumer received non-JSON message.")
