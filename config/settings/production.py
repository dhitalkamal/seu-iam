"""Production settings for the iam-service: debug off, RS256 JWT."""

from __future__ import annotations

from decouple import config

from .base import *  # noqa: F401, F403

DEBUG = False

SIMPLE_JWT = {
    **SIMPLE_JWT,  # noqa: F405
    "ALGORITHM": "RS256",
    # IAM signs tokens with the private key
    "SIGNING_KEY": config("JWT_PRIVATE_KEY").replace("\\n", "\n"),
    "VERIFYING_KEY": config("JWT_PUBLIC_KEY").replace("\\n", "\n"),
}
