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

# shared schema building blocks
_META = inline_serializer(
    name="ResponseMeta",
    fields={
        "request_id": serializers.CharField(),
        "timestamp": serializers.CharField(),
    },
)

_ERROR_ENVELOPE = inline_serializer(
    name="ErrorEnvelope",
    fields={
        "data": serializers.JSONField(allow_null=True, default=None),
        "error": inline_serializer(
            name="ErrorEnvelopeBody",
            fields={
                "code": serializers.CharField(help_text="Machine-readable error code."),
                "message": serializers.CharField(help_text="Human-readable error description."),
                "details": serializers.JSONField(
                    allow_null=True,
                    help_text="Extra context: flat list of {field, message} for validation errors, dict for domain errors.",
                ),
            },
        ),
        "meta": _META,
    },
)

_MSG_ENVELOPE = inline_serializer(
    name="MessageEnvelope",
    fields={
        "data": inline_serializer(
            name="MessageEnvelopeData",
            fields={"message": serializers.CharField()},
        ),
        "error": serializers.JSONField(allow_null=True, default=None),
        "meta": _META,
    },
)

_TOKEN_PAIR_ENVELOPE = inline_serializer(
    name="TokenPairEnvelope",
    fields={
        "data": inline_serializer(
            name="TokenPairData",
            fields={
                "access_token": serializers.CharField(),
                "refresh_token": serializers.CharField(),
            },
        ),
        "error": serializers.JSONField(allow_null=True, default=None),
        "meta": _META,
    },
)

_CHECKS = inline_serializer(
    name="DependencyChecks",
    fields={
        "database": serializers.ChoiceField(choices=["healthy", "unhealthy"]),
        "redis": serializers.ChoiceField(choices=["healthy", "unhealthy"]),
        "rabbitmq": serializers.ChoiceField(choices=["healthy", "unhealthy"]),
    },
)

# reusable per-status OpenApiResponse objects
_R400 = OpenApiResponse(
    description="Request contains invalid data (e.g. wrong or expired OTP).",
    response=_ERROR_ENVELOPE,
)
_R401 = OpenApiResponse(
    description="Authentication credentials are missing or invalid.",
    response=_ERROR_ENVELOPE,
)
_R403 = OpenApiResponse(
    description="You do not have permission to perform this action.",
    response=_ERROR_ENVELOPE,
)
_R404 = OpenApiResponse(
    description="The requested resource was not found.",
    response=_ERROR_ENVELOPE,
)
_R409 = OpenApiResponse(
    description="Request conflicts with the current resource state.",
    response=_ERROR_ENVELOPE,
)
_R422 = OpenApiResponse(
    description="Payload failed validation. details contains a flat list of {field, message} objects.",
    response=_ERROR_ENVELOPE,
)
_R423 = OpenApiResponse(
    description="Account is temporarily locked. details.locked_until contains the unlock timestamp.",
    response=_ERROR_ENVELOPE,
)
_R503 = OpenApiResponse(
    description="One or more dependencies are unavailable.",
    response=_ERROR_ENVELOPE,
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
                    name="HealthSuccessEnvelope",
                    fields={
                        "data": inline_serializer(
                            name="HealthData",
                            fields={
                                "service": serializers.CharField(),
                                "status": serializers.CharField(),
                                "version": serializers.CharField(),
                                "checks": _CHECKS,
                            },
                        ),
                        "error": serializers.JSONField(allow_null=True, default=None),
                        "meta": _META,
                    },
                ),
            ),
            503: _R503,
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
            "Creates an unverified user account and sends a verification OTP to the email address. "
            "The account cannot log in until the email is verified."
        ),
        auth=[],
        request=RegisterRequestSerializer,
        responses={
            201: OpenApiResponse(
                description="Account created. A verification OTP has been sent to the email.",
                response=inline_serializer(
                    name="RegisterSuccessEnvelope",
                    fields={
                        "data": UserResponseSerializer(),
                        "error": serializers.JSONField(allow_null=True, default=None),
                        "meta": _META,
                    },
                ),
            ),
            409: _R409,
            422: _R422,
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
            "When MFA is enabled, returns mfa_required=true and user_id instead of tokens — "
            "complete login via POST /auth/mfa/challenge/."
        ),
        auth=[],
        request=LoginRequestSerializer,
        responses={
            200: OpenApiResponse(
                description="Tokens issued, or MFA challenge required.",
                response=inline_serializer(
                    name="LoginSuccessEnvelope",
                    fields={
                        "data": inline_serializer(
                            name="LoginData",
                            fields={
                                "mfa_required": serializers.BooleanField(),
                                "user_id": serializers.UUIDField(
                                    allow_null=True,
                                    help_text="Populated only when mfa_required is true.",
                                ),
                                "access_token": serializers.CharField(
                                    allow_null=True,
                                    help_text="Populated only when mfa_required is false.",
                                ),
                                "refresh_token": serializers.CharField(
                                    allow_null=True,
                                    help_text="Populated only when mfa_required is false.",
                                ),
                            },
                        ),
                        "error": serializers.JSONField(allow_null=True, default=None),
                        "meta": _META,
                    },
                ),
            ),
            401: _R401,
            403: _R403,
            423: _R423,
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
            200: OpenApiResponse(
                description="Session terminated successfully.",
                response=_MSG_ENVELOPE,
            ),
            400: _R400,
            401: _R401,
            422: _R422,
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
            "Submit the 8-character alphanumeric OTP that was emailed on registration. "
            "OTPs expire after 10 minutes. Use POST /auth/email/resend/ to get a fresh one."
        ),
        auth=[],
        request=VerifyEmailRequestSerializer,
        responses={
            200: OpenApiResponse(
                description="Email verified successfully.",
                response=_MSG_ENVELOPE,
            ),
            400: _R400,
            404: _R404,
            409: _R409,
            422: _R422,
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
    """Send a fresh email verification OTP."""

    authentication_classes: list = []
    permission_classes = [AllowAny]

    @extend_schema(
        tags=["Auth"],
        summary="Resend verification OTP",
        description=(
            "Generates a new 8-character OTP and sends it to the email address. "
            "Any previously issued OTP is overwritten."
        ),
        auth=[],
        request=ResendVerificationOTPRequestSerializer,
        responses={
            200: OpenApiResponse(
                description="Verification OTP sent to the email address.",
                response=_MSG_ENVELOPE,
            ),
            404: _R404,
            409: _R409,
            422: _R422,
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
            "Sends a password-reset OTP to the email address. "
            "The account email must be verified before a reset can be requested. "
            "OTPs expire after 10 minutes."
        ),
        auth=[],
        request=RequestPasswordResetSerializer,
        responses={
            200: OpenApiResponse(
                description="Password reset OTP sent to the email address.",
                response=_MSG_ENVELOPE,
            ),
            401: _R401,
            404: _R404,
            422: _R422,
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
            "All existing sessions are invalidated on success. "
            "The new password must meet the minimum security requirements."
        ),
        auth=[],
        request=ConfirmPasswordResetSerializer,
        responses={
            200: OpenApiResponse(
                description="Password reset successfully. All sessions have been invalidated.",
                response=_MSG_ENVELOPE,
            ),
            400: _R400,
            404: _R404,
            422: _R422,
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
            200: OpenApiResponse(
                description="Password changed successfully. All sessions have been invalidated.",
                response=_MSG_ENVELOPE,
            ),
            401: _R401,
            422: _R422,
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
    """Generate a TOTP secret and provisioning URI for authenticator app setup."""

    permission_classes = [IsAuthenticated]

    @extend_schema(
        tags=["MFA"],
        summary="Initiate MFA setup",
        description=(
            "Generates a TOTP secret and provisioning URI (otpauth:// URL). "
            "Scan the URI with an authenticator app (e.g. Google Authenticator, Authy), "
            "then confirm setup by calling POST /auth/mfa/enable/ with a valid code. "
            "MFA is not active until the enable step is completed."
        ),
        responses={
            200: OpenApiResponse(
                description="TOTP secret and provisioning URI for authenticator app setup.",
                response=inline_serializer(
                    name="MFASetupEnvelope",
                    fields={
                        "data": MFASetupResponseSerializer(),
                        "error": serializers.JSONField(allow_null=True, default=None),
                        "meta": _META,
                    },
                ),
            ),
            401: _R401,
            409: _R409,
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
        description=(
            "Submit a valid 6-digit TOTP code from the authenticator app to activate MFA. "
            "Must be called after POST /auth/mfa/setup/ and before MFA is enforced on login."
        ),
        request=MFACodeSerializer,
        responses={
            200: OpenApiResponse(
                description="MFA enabled successfully.",
                response=_MSG_ENVELOPE,
            ),
            400: _R400,
            401: _R401,
            409: _R409,
            422: _R422,
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
        description=(
            "Submit a valid 6-digit TOTP code to deactivate MFA and clear the stored secret. "
            "After this, login returns tokens directly without an MFA challenge."
        ),
        request=MFACodeSerializer,
        responses={
            200: OpenApiResponse(
                description="MFA disabled successfully. Secret cleared.",
                response=_MSG_ENVELOPE,
            ),
            400: _R400,
            401: _R401,
            409: _R409,
            422: _R422,
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
    """Complete an MFA login by verifying a TOTP code and issuing JWT tokens."""

    authentication_classes: list = []
    permission_classes = [AllowAny]

    @extend_schema(
        tags=["MFA"],
        summary="MFA login challenge",
        description=(
            "Submit the user_id returned by POST /auth/login/ (when mfa_required=true) "
            "together with the current 6-digit TOTP code from the authenticator app. "
            "Returns JWT tokens on success."
        ),
        auth=[],
        request=MFAChallengeSerializer,
        responses={
            200: OpenApiResponse(
                description="TOTP verified. JWT tokens issued.",
                response=_TOKEN_PAIR_ENVELOPE,
            ),
            400: _R400,
            401: _R401,
            404: _R404,
            422: _R422,
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
        description="Returns the full profile of the currently authenticated user.",
        responses={
            200: OpenApiResponse(
                description="User profile.",
                response=inline_serializer(
                    name="ProfileGetEnvelope",
                    fields={
                        "data": UserResponseSerializer(),
                        "error": serializers.JSONField(allow_null=True, default=None),
                        "meta": _META,
                    },
                ),
            ),
            401: _R401,
            404: _R404,
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
        description=(
            "Partially update the authenticated user's profile. "
            "Only provided fields are changed. Omitted fields retain their current values."
        ),
        request=UpdateProfileRequestSerializer,
        responses={
            200: OpenApiResponse(
                description="Updated profile.",
                response=inline_serializer(
                    name="ProfilePatchEnvelope",
                    fields={
                        "data": UserResponseSerializer(),
                        "error": serializers.JSONField(allow_null=True, default=None),
                        "meta": _META,
                    },
                ),
            ),
            401: _R401,
            404: _R404,
            422: _R422,
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

    @extend_schema(
        tags=["Profile"],
        summary="Delete my account",
        description=(
            "Permanently deactivates the authenticated user's account. "
            "The account is soft-deleted: is_active is set to false and deleted_at is recorded. "
            "All existing sessions are immediately invalidated."
        ),
        responses={
            204: OpenApiResponse(description="Account deleted successfully. No response body."),
            401: _R401,
            404: _R404,
        },
    )
    def delete(self, request: Request) -> Response:
        """Soft-delete the account and blacklist all sessions."""
        from apps.users.application.use_cases.delete_account import DeleteAccountUseCase

        DeleteAccountUseCase(DjangoUserRepository(), JWTTokenBlacklistService()).execute(
            user_id=request.user.id,  # type: ignore[attr-defined]
        )
        return Response(status=204)


class InternalUserView(APIView):
    """Service-to-service endpoint for resolving user details by ID."""

    authentication_classes: list = []
    permission_classes = [AllowAny]

    @extend_schema(
        tags=["Internal"],
        summary="Get user by ID (internal)",
        description=(
            "Returns safe user fields for service-to-service lookups. "
            "No sensitive data (password, MFA secret, lock state) is included. "
            "This endpoint trusts the internal network — restrict it at the gateway in production."
        ),
        auth=[],
        responses={
            200: OpenApiResponse(
                description="User details.",
                response=inline_serializer(
                    name="InternalUserEnvelope",
                    fields={
                        "data": inline_serializer(
                            name="InternalUserData",
                            fields={
                                "id": serializers.UUIDField(),
                                "email": serializers.EmailField(),
                                "first_name": serializers.CharField(),
                                "last_name": serializers.CharField(),
                                "full_name": serializers.CharField(),
                                "avatar_url": serializers.URLField(allow_null=True),
                                "is_active": serializers.BooleanField(),
                            },
                        ),
                        "error": serializers.JSONField(allow_null=True, default=None),
                        "meta": _META,
                    },
                ),
            ),
            404: _R404,
        },
    )
    def get(self, request: Request, user_id: uuid.UUID) -> Response:
        """Return safe user fields for the given user ID."""
        from apps.users.application.use_cases.profile import GetProfileUseCase
        from apps.users.presentation.serializers import InternalUserSerializer

        entity = GetProfileUseCase(DjangoUserRepository()).execute(user_id=user_id)
        return success_response(InternalUserSerializer(entity).data, request=request)
