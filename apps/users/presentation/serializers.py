"""DRF serializers for IAM request deserialization and response shaping."""

from __future__ import annotations

from rest_framework import serializers


class RegisterRequestSerializer(serializers.Serializer):
    """Payload for creating a new user account."""

    email = serializers.EmailField()
    password = serializers.CharField(write_only=True, min_length=8, max_length=128)
    first_name = serializers.CharField(max_length=150)
    last_name = serializers.CharField(max_length=150)


class UserResponseSerializer(serializers.Serializer):
    """Public profile shape returned after registration and on profile reads."""

    id = serializers.UUIDField()
    email = serializers.EmailField()
    first_name = serializers.CharField()
    last_name = serializers.CharField()
    avatar_url = serializers.URLField(allow_null=True)
    is_email_verified = serializers.BooleanField()
    mfa_enabled = serializers.BooleanField()
    date_joined = serializers.DateTimeField()
