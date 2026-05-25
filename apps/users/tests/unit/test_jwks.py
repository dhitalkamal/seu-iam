"""Unit tests for the JWKS endpoint."""

from __future__ import annotations

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from rest_framework.test import APIRequestFactory

from apps.users.presentation.views import JWKSView

_factory = APIRequestFactory()


def _rsa_public_pem() -> str:
    """Generate a throwaway RSA-2048 public key PEM for test use."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()


def test_jwks_returns_empty_keys_for_hs256(settings: object) -> None:  # type: ignore[misc]
    """HS256 mode cannot express a symmetric key as JWKS; must return an empty keys list."""
    settings.SIMPLE_JWT = {**settings.SIMPLE_JWT, "ALGORITHM": "HS256", "VERIFYING_KEY": ""}  # type: ignore[attr-defined]
    request = _factory.get("/api/v1/auth/jwks/")
    response = JWKSView.as_view()(request)
    assert response.status_code == 200
    assert response.data == {"keys": []}  # type: ignore[union-attr]


def test_jwks_returns_rsa_public_key_for_rs256(settings: object) -> None:  # type: ignore[misc]
    """RS256 mode returns a single JWK with the expected fields populated."""
    settings.SIMPLE_JWT = {  # type: ignore[attr-defined]
        **settings.SIMPLE_JWT,  # type: ignore[attr-defined]
        "ALGORITHM": "RS256",
        "VERIFYING_KEY": _rsa_public_pem(),
    }
    request = _factory.get("/api/v1/auth/jwks/")
    response = JWKSView.as_view()(request)
    assert response.status_code == 200
    keys = response.data["keys"]  # type: ignore[index]
    assert len(keys) == 1
    jwk = keys[0]
    assert jwk["kty"] == "RSA"
    assert jwk["alg"] == "RS256"
    assert jwk["use"] == "sig"
    assert jwk["kid"] == "1"
    assert jwk.get("n")
    assert jwk.get("e")


def test_jwks_no_authentication_required() -> None:
    """The endpoint is public and must return 200 with no credentials."""
    request = _factory.get("/api/v1/auth/jwks/")
    response = JWKSView.as_view()(request)
    assert response.status_code == 200
