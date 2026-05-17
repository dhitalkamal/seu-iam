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


class VerifyPasswordResetOTPSerializer(serializers.Serializer):
    """Payload for verifying a password-reset OTP without consuming it."""

    email = serializers.EmailField()
    otp = serializers.CharField(min_length=8, max_length=8)


class ResendVerificationOTPRequestSerializer(serializers.Serializer):
    """Payload for requesting a new verification OTP."""

    email = serializers.EmailField()


class ChangePasswordSerializer(serializers.Serializer):
    """Payload for changing the authenticated user's password."""

    current_password = serializers.CharField(write_only=True)
    new_password = serializers.CharField(write_only=True, min_length=8, max_length=128)
    confirm_password = serializers.CharField(write_only=True, min_length=8, max_length=128)

    def validate(self, attrs: dict) -> dict:
        """Ensure the two new password fields match."""
        if attrs["new_password"] != attrs["confirm_password"]:
            raise serializers.ValidationError({"confirm_password": "Passwords do not match."})
        attrs.pop("confirm_password")
        return attrs


class RequestPasswordResetSerializer(serializers.Serializer):
    """Payload for requesting a password reset OTP."""

    email = serializers.EmailField()


class ConfirmPasswordResetSerializer(serializers.Serializer):
    """Payload for confirming a password reset with OTP and new password."""

    email = serializers.EmailField()
    otp = serializers.CharField(min_length=8, max_length=8)
    new_password = serializers.CharField(write_only=True, min_length=8, max_length=128)
    confirm_password = serializers.CharField(write_only=True, min_length=8, max_length=128)

    def validate(self, attrs: dict) -> dict:
        """Ensure the two password fields match."""
        if attrs["new_password"] != attrs["confirm_password"]:
            raise serializers.ValidationError({"confirm_password": "Passwords do not match."})
        attrs.pop("confirm_password")
        return attrs


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


class MFASetupResponseSerializer(serializers.Serializer):
    """Response returned after initiating MFA setup."""

    secret = serializers.CharField()
    provisioning_uri = serializers.CharField()


class MFACodeSerializer(serializers.Serializer):
    """Payload carrying a 6-digit TOTP code."""

    code = serializers.CharField(min_length=6, max_length=6)


class MFAChallengeSerializer(serializers.Serializer):
    """Payload for completing an MFA login challenge (TOTP code or 8-char backup code)."""

    user_id = serializers.UUIDField()
    code = serializers.CharField(
        min_length=6,
        max_length=8,
        help_text="6-digit TOTP code or 8-character backup code.",
    )


class GoogleSocialAuthSerializer(serializers.Serializer):
    """Payload for Google social sign-in."""

    id_token = serializers.CharField(write_only=True)


class MFAEnableResponseSerializer(serializers.Serializer):
    """Response after enabling MFA, includes one-time backup codes."""

    message = serializers.CharField()
    backup_codes = serializers.ListField(
        child=serializers.CharField(),
        help_text="One-time backup codes. Store these securely — they are shown only once.",
    )


class RegenerateBackupCodesResponseSerializer(serializers.Serializer):
    """Response after regenerating backup codes."""

    backup_codes = serializers.ListField(
        child=serializers.CharField(),
        help_text="New one-time backup codes. Previous codes are now invalid.",
    )


class BackupCodeStatusSerializer(serializers.Serializer):
    """Status of a user's backup codes — count only, no plaintext."""

    remaining = serializers.IntegerField(help_text="Number of unused backup codes remaining.")


class SessionInfoSerializer(serializers.Serializer):
    """Active session detail returned by the session list endpoint."""

    jti = serializers.UUIDField()
    ip_address = serializers.IPAddressField(allow_null=True)
    user_agent = serializers.CharField(allow_null=True)
    created_at = serializers.DateTimeField()
    last_seen_at = serializers.DateTimeField()


class GDPRErasureSerializer(serializers.Serializer):
    """Payload for requesting account erasure."""

    current_password = serializers.CharField(write_only=True, required=False, allow_null=True)


class InternalUserSerializer(serializers.Serializer):
    """Safe user fields exposed for service-to-service lookups. No sensitive data."""

    id = serializers.UUIDField()
    email = serializers.EmailField()
    first_name = serializers.CharField()
    last_name = serializers.CharField()
    full_name = serializers.CharField()
    avatar_url = serializers.URLField(allow_null=True)
    is_active = serializers.BooleanField()
