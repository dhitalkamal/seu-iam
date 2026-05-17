"""Unit tests for RegisterRequestSerializer. validates confirm_password logic."""

from __future__ import annotations

from apps.users.presentation.serializers import RegisterRequestSerializer


def _valid_data(**overrides: str) -> dict:
    base = {
        "email": "kamal@example.com",
        "password": "StrongPass1!",
        "confirm_password": "StrongPass1!",
        "first_name": "Kamal",
        "last_name": "Dhital",
    }
    base.update(overrides)
    return base


def test_valid_payload_passes():
    """Matching passwords with all required fields are accepted."""
    ser = RegisterRequestSerializer(data=_valid_data())
    assert ser.is_valid(), ser.errors


def test_mismatched_passwords_are_rejected():
    """Passwords that do not match raise a validation error."""
    ser = RegisterRequestSerializer(data=_valid_data(confirm_password="WrongPass1!"))
    assert not ser.is_valid()
    assert "confirm_password" in ser.errors


def test_confirm_password_absent_from_validated_data():
    """confirm_password is stripped from validated_data so it is never passed to the use case."""
    ser = RegisterRequestSerializer(data=_valid_data())
    ser.is_valid()
    assert "confirm_password" not in ser.validated_data


def test_confirm_password_required():
    """Omitting confirm_password makes the payload invalid."""
    data = _valid_data()
    del data["confirm_password"]
    ser = RegisterRequestSerializer(data=data)
    assert not ser.is_valid()
    assert "confirm_password" in ser.errors
