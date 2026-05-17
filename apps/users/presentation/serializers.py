"""DRF serializers for IAM request deserialization and response shaping."""

from __future__ import annotations

from rest_framework import serializers


class RegisterRequestSerializer(serializers.Serializer):
    """Payload for creating a new user account."""

    email = serializers.EmailField()
    password = serializers.CharField(write_only=True, min_length=8, max_length=128)
    confirm_password = serializers.CharField(write_only=True, min_length=8, max_length=128)
    first_name = serializers.CharField(max_length=150)
    last_name = serializers.CharField(max_length=150)

    def validate(self, attrs: dict) -> dict:
        """Check that both password fields match, then remove confirm_password before returning."""
        if attrs["password"] != attrs["confirm_password"]:
            raise serializers.ValidationError({"confirm_password": "Passwords do not match."})
        attrs.pop("confirm_password")
        return attrs


class LoginRequestSerializer(serializers.Serializer):
    """Payload for authenticating with email and password."""

    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)


class LoginResponseSerializer(serializers.Serializer):
    """Login outcome: tokens for a normal login, or an MFA challenge signal."""

    mfa_required = serializers.BooleanField()
    user_id = serializers.UUIDField(allow_null=True)
    access_token = serializers.CharField(allow_null=True)
    refresh_token = serializers.CharField(allow_null=True)


class LogoutRequestSerializer(serializers.Serializer):
    """Payload for invalidating a session refresh token."""

    refresh_token = serializers.CharField()


class VerifyEmailRequestSerializer(serializers.Serializer):
    """Payload for verifying an email address with an OTP."""

    email = serializers.EmailField()
    otp = serializers.CharField(min_length=8, max_length=8)


class ResendVerificationOTPRequestSerializer(serializers.Serializer):
    """Payload for requesting a new verification OTP."""

    email = serializers.EmailField()


class UpdateProfileRequestSerializer(serializers.Serializer):
    """Partial payload for updating the authenticated user's profile."""

    first_name = serializers.CharField(max_length=150, required=False)
    last_name = serializers.CharField(max_length=150, required=False)
    avatar_url = serializers.URLField(allow_null=True, required=False)


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
