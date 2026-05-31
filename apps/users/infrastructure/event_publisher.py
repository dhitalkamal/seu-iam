"""RabbitMQ event publisher using pika."""

from __future__ import annotations

import json
import logging

import pika
from django.conf import settings

from apps.users.domain.repositories import IEventPublisher

logger = logging.getLogger(__name__)

_EXCHANGE = "sansaar"
_EXCHANGE_TYPE = "topic"


class RabbitMQEventPublisher(IEventPublisher):
    """Publishes domain events to the sansaar topic exchange on RabbitMQ."""

    def publish(self, event_name: str, payload: dict) -> None:
        """
        Open a connection, declare the exchange, publish, and close.

        Uses a fresh connection per call — acceptable for low-frequency events like
        registration. If RabbitMQ is unavailable, logs a warning and continues so
        that registration is not blocked by notification infrastructure.
        """
        try:
            params = pika.URLParameters(settings.RABBITMQ_URL)
            connection = pika.BlockingConnection(params)
            channel = connection.channel()
            channel.exchange_declare(exchange=_EXCHANGE, exchange_type=_EXCHANGE_TYPE, durable=True)
            channel.basic_publish(
                exchange=_EXCHANGE,
                routing_key=event_name,
                body=json.dumps(payload),
                properties=pika.BasicProperties(
                    content_type="application/json",
                    delivery_mode=pika.DeliveryMode.Persistent,
                ),
            )
            connection.close()
        except Exception:
            logger.warning("Failed to publish event %s to RabbitMQ.", event_name, exc_info=True)
