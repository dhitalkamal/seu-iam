"""Stateless JWT authentication shared across all services.

Other services copy this class verbatim. It decodes the token locally
without hitting the IAM database, reading user id, email, and role from claims.
"""

from __future__ import annotations
