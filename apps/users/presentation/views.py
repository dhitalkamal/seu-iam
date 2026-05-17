"""DRF API views for IAM endpoints."""

from __future__ import annotations

from django.conf import settings
from drf_spectacular.utils import OpenApiResponse, extend_schema, inline_serializer
from rest_framework import serializers
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.common.api.responses import created_response, error_response, success_response
from apps.common.health import check_database, check_rabbitmq, check_redis
from apps.users.application.use_cases.change_password import ChangePasswordUseCase
from apps.users.application.use_cases.confirm_password_reset import ConfirmPasswordResetUseCase
from apps.users.application.use_cases.disable_mfa import DisableMFAUseCase
from apps.users.application.use_cases.enable_mfa import EnableMFAUseCase
from apps.users.application.use_cases.login import LoginUseCase
from apps.users.application.use_cases.logout import LogoutUseCase
from apps.users.application.use_cases.mfa_challenge import MFAChallengeUseCase
from apps.users.application.use_cases.profile import GetProfileUseCase, UpdateProfileUseCase
from apps.users.application.use_cases.register import RegisterUseCase
from apps.users.application.use_cases.request_password_reset import RequestPasswordResetUseCase
from apps.users.application.use_cases.resend_verification_otp import ResendVerificationOTPUseCase
from apps.users.application.use_cases.setup_mfa import SetupMFAUseCase
from apps.users.application.use_cases.verify_email import VerifyEmailUseCase
from apps.users.infrastructure.event_publisher import RabbitMQEventPublisher
from apps.users.infrastructure.otp_service import RedisOTPService
from apps.users.infrastructure.repositories import DjangoUserRepository
from apps.users.infrastructure.token_service import JWTTokenBlacklistService, JWTTokenService
from apps.users.infrastructure.totp_service import PyOTPService
from apps.users.presentation.serializers import (
    ChangePasswordSerializer,
    ConfirmPasswordResetSerializer,
    LoginRequestSerializer,
    LogoutRequestSerializer,
    MFAChallengeSerializer,
    MFACodeSerializer,
    MFASetupResponseSerializer,
    RegisterRequestSerializer,
    RequestPasswordResetSerializer,
    ResendVerificationOTPRequestSerializer,
    UpdateProfileRequestSerializer,
    UserResponseSerializer,
    VerifyEmailRequestSerializer,
)

_CHECKS = inline_serializer(
    name="DependencyChecks",
    fields={
        "database": serializers.ChoiceField(choices=["healthy", "unhealthy"]),
        "redis": serializers.ChoiceField(choices=["healthy", "unhealthy"]),
        "rabbitmq": serializers.ChoiceField(choices=["healthy", "unhealthy"]),
    },
)
_META = inline_serializer(
    name="ResponseMeta",
    fields={
        "request_id": serializers.CharField(),
        "timestamp": serializers.CharField(),
    },
)


class HealthCheckView(APIView):
    """Reports the operational status of all external dependencies."""

    authentication_classes: list = []
    permission_classes = [AllowAny]

    @extend_schema(
        tags=["Health"],
        summary="Service health check",
        description=(
            "Checks connectivity to PostgreSQL, Redis, and RabbitMQ. "
            "Returns 200 when all dependencies are healthy, 503 when any are down."
        ),
        auth=[],
        responses={
            200: OpenApiResponse(
                description="All dependencies are healthy.",
                response=inline_serializer(
                    name="HealthyResponse",
                    fields={
                        "data": inline_serializer(
                            name="HealthyData",
                            fields={
                                "service": serializers.CharField(),
                                "status": serializers.CharField(),
                                "version": serializers.CharField(),
                                "checks": _CHECKS,
                            },
                        ),
                        "error": serializers.JSONField(allow_null=True),
                        "meta": _META,
                    },
                ),
            ),
            503: OpenApiResponse(description="One or more dependencies are unavailable."),
        },
    )
    def get(self, request: Request) -> Response:
        """Check DB, Redis, and RabbitMQ and return an aggregated status."""
        db_status, db_err = check_database()
        redis_status, redis_err = check_redis()
        rmq_status, rmq_err = check_rabbitmq()

        checks: dict = {
            "database": db_status,
            "redis": redis_status,
            "rabbitmq": rmq_status,
        }
        dep_errors: dict = {
            k: v
            for k, v in {"database": db_err, "redis": redis_err, "rabbitmq": rmq_err}.items()
            if v is not None
        }

        if all(s == "healthy" for s in checks.values()):
            return success_response(
                {
                    "service": settings.SERVICE_NAME,
                    "status": "healthy",
                    "version": "0.1.0",
                    "checks": checks,
                },
                request=request,
            )

        return error_response(
            code="ERR_SERVICE_UNHEALTHY",
            message="One or more dependencies are unavailable.",
            details={"checks": checks, **({"errors": dep_errors} if dep_errors else {})},
            http_status=503,
            request=request,
        )


class RegisterView(APIView):
    """Create a new unverified user account and dispatch an email verification OTP."""

    authentication_classes: list = []
    permission_classes = [AllowAny]

    @extend_schema(
        tags=["Auth"],
        summary="Register a new account",
        description=(
            "Creates an unverified user account and sends a verification OTP to the email. "
            "Returns 409 if the email is already taken, 422 if the payload fails validation."
        ),
        auth=[],
        request=RegisterRequestSerializer,
        responses={
            201: OpenApiResponse(description="Account created.", response=UserResponseSerializer),
            409: OpenApiResponse(description="Email already in use."),
            422: OpenApiResponse(description="Validation error."),
        },
    )
    def post(self, request: Request) -> Response:
        """Validate the payload, hash the password, persist the account, and send OTP."""
        ser = RegisterRequestSerializer(data=request.data)
        ser.is_valid(raise_exception=True)
        d = ser.validated_data

        entity = RegisterUseCase(
            DjangoUserRepository(), RedisOTPService(), RabbitMQEventPublisher()
        ).execute(
            email=d["email"],
            password=d["password"],
            first_name=d["first_name"],
            last_name=d["last_name"],
        )
        return created_response(UserResponseSerializer(entity).data, request=request)


class LoginView(APIView):
    """Authenticate with email and password."""

    authentication_classes: list = []
    permission_classes = [AllowAny]

    @extend_schema(
        tags=["Auth"],
        summary="Log in",
        description=(
            "Authenticate with email and password. "
            "Returns JWT tokens on success. "
            "If MFA is enabled returns mfa_required=true with a user_id. "
            "Submit that user_id and a TOTP code to the MFA challenge endpoint to get tokens."
        ),
        auth=[],
        request=LoginRequestSerializer,
        responses={
            200: OpenApiResponse(
                description="Tokens issued or MFA challenge required.",
                response=inline_serializer(
                    name="LoginResponse",
                    fields={
                        "data": inline_serializer(
                            name="LoginData",
                            fields={
                                "mfa_required": serializers.BooleanField(),
                                "user_id": serializers.UUIDField(allow_null=True),
                                "access_token": serializers.CharField(allow_null=True),
                                "refresh_token": serializers.CharField(allow_null=True),
                            },
                        ),
                        "error": serializers.JSONField(allow_null=True),
                        "meta": _META,
                    },
                ),
            ),
            401: OpenApiResponse(description="Invalid credentials or unverified account."),
            423: OpenApiResponse(description="Account locked due to too many failed attempts."),
        },
    )
    def post(self, request: Request) -> Response:
        """Validate credentials and return tokens or an MFA challenge signal."""
        ser = LoginRequestSerializer(data=request.data)
        ser.is_valid(raise_exception=True)
        d = ser.validated_data

        result = LoginUseCase(DjangoUserRepository(), JWTTokenService()).execute(
            email=d["email"],
            password=d["password"],
        )
        return success_response(
            {
                "mfa_required": result.mfa_required,
                "user_id": str(result.user_id) if result.user_id else None,
                "access_token": result.access_token,
                "refresh_token": result.refresh_token,
            },
            request=request,
        )


class LogoutView(APIView):
    """Blacklist the refresh token to terminate the current session."""

    permission_classes = [IsAuthenticated]

    @extend_schema(
        tags=["Auth"],
        summary="Log out",
        description="Blacklists the provided refresh token server-side so it cannot be reused.",
        request=LogoutRequestSerializer,
        responses={
            200: OpenApiResponse(description="Session terminated successfully."),
            400: OpenApiResponse(description="Token is invalid or already blacklisted."),
        },
    )
    def post(self, request: Request) -> Response:
        """Blacklist the refresh token from the request body."""
        ser = LogoutRequestSerializer(data=request.data)
        ser.is_valid(raise_exception=True)

        LogoutUseCase(JWTTokenBlacklistService()).execute(ser.validated_data["refresh_token"])
        return success_response({"message": "Logged out successfully."}, request=request)


class VerifyEmailView(APIView):
    """Verify a user's email address with the OTP sent on registration."""

    authentication_classes: list = []
    permission_classes = [AllowAny]

    @extend_schema(
        tags=["Auth"],
        summary="Verify email with OTP",
        description=(
            "Submit the 8-character OTP that was emailed on registration. "
            "Returns 400 if the OTP is wrong or expired, 409 if already verified."
        ),
        auth=[],
        request=VerifyEmailRequestSerializer,
        responses={
            200: OpenApiResponse(description="Email verified successfully."),
            400: OpenApiResponse(description="OTP invalid or expired."),
            404: OpenApiResponse(description="Email not found."),
            409: OpenApiResponse(description="Email already verified."),
        },
    )
    def post(self, request: Request) -> Response:
        """Validate the OTP and mark the account as verified."""
        ser = VerifyEmailRequestSerializer(data=request.data)
        ser.is_valid(raise_exception=True)
        d = ser.validated_data

        VerifyEmailUseCase(DjangoUserRepository(), RedisOTPService()).execute(
            email=d["email"],
            otp=d["otp"],
        )
        return success_response({"message": "Email verified successfully."}, request=request)


class ResendVerificationOTPView(APIView):
    """Send a fresh OTP to the given email address."""

    authentication_classes: list = []
    permission_classes = [AllowAny]

    @extend_schema(
        tags=["Auth"],
        summary="Resend verification OTP",
        description=(
            "Generates a new OTP and sends it to the email. "
            "Returns 409 if the email is already verified, 404 if the email is unknown."
        ),
        auth=[],
        request=ResendVerificationOTPRequestSerializer,
        responses={
            200: OpenApiResponse(description="OTP resent successfully."),
            404: OpenApiResponse(description="Email not found."),
            409: OpenApiResponse(description="Email already verified."),
        },
    )
    def post(self, request: Request) -> Response:
        """Generate a new OTP and publish the verification event."""
        ser = ResendVerificationOTPRequestSerializer(data=request.data)
        ser.is_valid(raise_exception=True)

        ResendVerificationOTPUseCase(
            DjangoUserRepository(), RedisOTPService(), RabbitMQEventPublisher()
        ).execute(email=ser.validated_data["email"])
        return success_response({"message": "Verification OTP sent."}, request=request)


class RequestPasswordResetView(APIView):
    """Send a password-reset OTP to the given email address."""

    authentication_classes: list = []
    permission_classes = [AllowAny]

    @extend_schema(
        tags=["Auth"],
        summary="Request password reset",
        description=(
            "Generates a password-reset OTP and sends it to the email. "
            "Returns 401 if the email is not yet verified, 404 if the email is unknown."
        ),
        auth=[],
        request=RequestPasswordResetSerializer,
        responses={
            200: OpenApiResponse(description="Password reset OTP sent."),
            401: OpenApiResponse(description="Email not verified."),
            404: OpenApiResponse(description="Email not found."),
        },
    )
    def post(self, request: Request) -> Response:
        """Generate and publish a password-reset OTP."""
        ser = RequestPasswordResetSerializer(data=request.data)
        ser.is_valid(raise_exception=True)

        RequestPasswordResetUseCase(
            DjangoUserRepository(), RedisOTPService("password_reset"), RabbitMQEventPublisher()
        ).execute(email=ser.validated_data["email"])
        return success_response({"message": "Password reset OTP sent."}, request=request)


class ConfirmPasswordResetView(APIView):
    """Reset the password using the OTP received by email."""

    authentication_classes: list = []
    permission_classes = [AllowAny]

    @extend_schema(
        tags=["Auth"],
        summary="Confirm password reset",
        description=(
            "Submit the OTP and a new password to complete the reset. "
            "All existing sessions are invalidated on success."
        ),
        auth=[],
        request=ConfirmPasswordResetSerializer,
        responses={
            200: OpenApiResponse(description="Password reset successfully."),
            400: OpenApiResponse(description="OTP invalid or expired."),
            404: OpenApiResponse(description="Email not found."),
            422: OpenApiResponse(description="Validation error."),
        },
    )
    def post(self, request: Request) -> Response:
        """Validate OTP, update password, and invalidate all sessions."""
        ser = ConfirmPasswordResetSerializer(data=request.data)
        ser.is_valid(raise_exception=True)
        d = ser.validated_data

        ConfirmPasswordResetUseCase(
            DjangoUserRepository(), RedisOTPService("password_reset"), JWTTokenBlacklistService()
        ).execute(
            email=d["email"],
            otp=d["otp"],
            new_password=d["new_password"],
        )
        return success_response({"message": "Password reset successfully."}, request=request)


class ChangePasswordView(APIView):
    """Change the authenticated user's own password."""

    permission_classes = [IsAuthenticated]

    @extend_schema(
        tags=["Auth"],
        summary="Change password",
        description=(
            "Change the authenticated user's password. "
            "Requires the current password for verification. "
            "All existing sessions are invalidated on success."
        ),
        request=ChangePasswordSerializer,
        responses={
            200: OpenApiResponse(description="Password changed successfully."),
            401: OpenApiResponse(description="Current password is incorrect."),
            422: OpenApiResponse(description="Validation error."),
        },
    )
    def post(self, request: Request) -> Response:
        """Verify current password, set new one, and blacklist all sessions."""
        ser = ChangePasswordSerializer(data=request.data)
        ser.is_valid(raise_exception=True)
        d = ser.validated_data

        ChangePasswordUseCase(DjangoUserRepository(), JWTTokenBlacklistService()).execute(
            user_id=request.user.id,  # type: ignore[attr-defined]
            current_password=d["current_password"],
            new_password=d["new_password"],
        )
        return success_response({"message": "Password changed successfully."}, request=request)


class MFASetupView(APIView):
    """Generate a TOTP secret and provisioning URI to configure an authenticator app."""

    permission_classes = [IsAuthenticated]

    @extend_schema(
        tags=["MFA"],
        summary="Initiate MFA setup",
        description=(
            "Generates a TOTP secret and provisioning URI. "
            "Scan the URI with an authenticator app then call the enable endpoint to activate MFA."
        ),
        responses={
            200: OpenApiResponse(description="Setup data.", response=MFASetupResponseSerializer),
            409: OpenApiResponse(description="MFA already enabled."),
        },
    )
    def post(self, request: Request) -> Response:
        """Generate and return the TOTP secret and provisioning URI."""
        result = SetupMFAUseCase(DjangoUserRepository(), PyOTPService()).execute(
            user_id=request.user.id,  # type: ignore[attr-defined]
        )
        return success_response(result, request=request)


class MFAEnableView(APIView):
    """Confirm MFA setup by verifying the first TOTP code."""

    permission_classes = [IsAuthenticated]

    @extend_schema(
        tags=["MFA"],
        summary="Enable MFA",
        description="Submit a valid TOTP code to activate MFA on the account.",
        request=MFACodeSerializer,
        responses={
            200: OpenApiResponse(description="MFA enabled."),
            400: OpenApiResponse(description="Invalid TOTP code."),
            409: OpenApiResponse(description="MFA already enabled."),
        },
    )
    def post(self, request: Request) -> Response:
        """Verify the code and activate MFA."""
        ser = MFACodeSerializer(data=request.data)
        ser.is_valid(raise_exception=True)

        EnableMFAUseCase(DjangoUserRepository(), PyOTPService()).execute(
            user_id=request.user.id,  # type: ignore[attr-defined]
            code=ser.validated_data["code"],
        )
        return success_response({"message": "MFA enabled successfully."}, request=request)


class MFADisableView(APIView):
    """Disable MFA after verifying a TOTP code."""

    permission_classes = [IsAuthenticated]

    @extend_schema(
        tags=["MFA"],
        summary="Disable MFA",
        description="Submit a valid TOTP code to deactivate MFA and clear the stored secret.",
        request=MFACodeSerializer,
        responses={
            200: OpenApiResponse(description="MFA disabled."),
            400: OpenApiResponse(description="Invalid TOTP code."),
            409: OpenApiResponse(description="MFA not enabled."),
        },
    )
    def post(self, request: Request) -> Response:
        """Verify the code and deactivate MFA."""
        ser = MFACodeSerializer(data=request.data)
        ser.is_valid(raise_exception=True)

        DisableMFAUseCase(DjangoUserRepository(), PyOTPService()).execute(
            user_id=request.user.id,  # type: ignore[attr-defined]
            code=ser.validated_data["code"],
        )
        return success_response({"message": "MFA disabled successfully."}, request=request)


class MFAChallengeView(APIView):
    """Complete an MFA login by verifying a TOTP code and issuing tokens."""

    authentication_classes: list = []
    permission_classes = [AllowAny]

    @extend_schema(
        tags=["MFA"],
        summary="MFA challenge",
        description=(
            "Submit the user_id (from the login response) and a TOTP code. "
            "Returns JWT tokens on success."
        ),
        auth=[],
        request=MFAChallengeSerializer,
        responses={
            200: OpenApiResponse(description="Tokens issued."),
            400: OpenApiResponse(description="Invalid TOTP code."),
            401: OpenApiResponse(description="MFA not enabled for this user."),
        },
    )
    def post(self, request: Request) -> Response:
        """Verify the TOTP code and return access and refresh tokens."""
        ser = MFAChallengeSerializer(data=request.data)
        ser.is_valid(raise_exception=True)
        d = ser.validated_data

        result = MFAChallengeUseCase(
            DjangoUserRepository(), PyOTPService(), JWTTokenService()
        ).execute(
            user_id=d["user_id"],
            code=d["code"],
        )
        return success_response(
            {"access_token": result.access_token, "refresh_token": result.refresh_token},
            request=request,
        )


class ProfileView(APIView):
    """Get or update the authenticated user's own profile."""

    permission_classes = [IsAuthenticated]

    @extend_schema(
        tags=["Profile"],
        summary="Get my profile",
        responses={
            200: OpenApiResponse(description="User profile.", response=UserResponseSerializer),
        },
    )
    def get(self, request: Request) -> Response:
        """Return the full profile of the authenticated user."""
        entity = GetProfileUseCase(DjangoUserRepository()).execute(
            user_id=request.user.id,  # type: ignore[attr-defined]
        )
        return success_response(UserResponseSerializer(entity).data, request=request)

    @extend_schema(
        tags=["Profile"],
        summary="Update my profile",
        request=UpdateProfileRequestSerializer,
        responses={
            200: OpenApiResponse(description="Updated profile.", response=UserResponseSerializer),
            422: OpenApiResponse(description="Validation error."),
        },
    )
    def patch(self, request: Request) -> Response:
        """Apply partial updates to the authenticated user's profile."""
        ser = UpdateProfileRequestSerializer(data=request.data)
        ser.is_valid(raise_exception=True)
        d = ser.validated_data

        entity = UpdateProfileUseCase(DjangoUserRepository()).execute(
            user_id=request.user.id,  # type: ignore[attr-defined]
            first_name=d.get("first_name"),
            last_name=d.get("last_name"),
            avatar_url=d.get("avatar_url"),
        )
        return success_response(UserResponseSerializer(entity).data, request=request)
