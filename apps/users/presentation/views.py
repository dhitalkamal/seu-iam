"""DRF API views for IAM endpoints."""

from __future__ import annotations

import uuid

from django.conf import settings
from drf_spectacular.utils import OpenApiResponse, extend_schema, inline_serializer
from rest_framework import serializers
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.common.api.responses import created_response, error_response, success_response
from apps.common.health import check_database, check_rabbitmq, check_redis
from apps.common.permissions import IsSuperAdminFromAllowedIP
from apps.users.application.use_cases.admin_user_management import (
    ActivateUserUseCase,
    ListUsersUseCase,
    SuspendUserUseCase,
)
from apps.users.application.use_cases.announcements import (
    CreateAnnouncementUseCase,
    ListAnnouncementsUseCase,
)
from apps.users.application.use_cases.change_password import ChangePasswordUseCase
from apps.users.application.use_cases.confirm_password_reset import ConfirmPasswordResetUseCase
from apps.users.application.use_cases.disable_mfa import DisableMFAUseCase
from apps.users.application.use_cases.enable_email_mfa import EnableEmailMFAUseCase
from apps.users.application.use_cases.enable_mfa import EnableMFAUseCase
from apps.users.application.use_cases.enable_sms_mfa import EnableSMSMFAUseCase
from apps.users.application.use_cases.feature_flags import (
    CreateFeatureFlagUseCase,
    DeleteFeatureFlagUseCase,
    ListFeatureFlagsUseCase,
    UpdateFeatureFlagUseCase,
)
from apps.users.application.use_cases.login import LoginUseCase
from apps.users.application.use_cases.logout import LogoutUseCase
from apps.users.application.use_cases.mfa_challenge import MFAChallengeUseCase
from apps.users.application.use_cases.profile import GetProfileUseCase, UpdateProfileUseCase
from apps.users.application.use_cases.register import RegisterUseCase
from apps.users.application.use_cases.request_password_reset import RequestPasswordResetUseCase
from apps.users.application.use_cases.resend_verification_otp import ResendVerificationOTPUseCase
from apps.users.application.use_cases.setup_email_mfa import SetupEmailMFAUseCase
from apps.users.application.use_cases.setup_mfa import SetupMFAUseCase
from apps.users.application.use_cases.setup_sms_mfa import SetupSMSMFAUseCase
from apps.users.application.use_cases.verify_email import VerifyEmailUseCase
from apps.users.domain.audit import AuditEventType
from apps.users.infrastructure.announcement_repository import DjangoAnnouncementRepository
from apps.users.infrastructure.audit_repository import DjangoAuditLogRepository
from apps.users.infrastructure.audit_service import AuditService
from apps.users.infrastructure.event_publisher import RabbitMQEventPublisher
from apps.users.infrastructure.feature_flag_repository import DjangoFeatureFlagRepository
from apps.users.infrastructure.otp_service import RedisOTPService
from apps.users.infrastructure.password_history_service import PasswordHistoryService
from apps.users.infrastructure.repositories import DjangoUserRepository
from apps.users.infrastructure.session_service import SessionService
from apps.users.infrastructure.token_service import (
    JWTTokenBlacklistService,
    JWTTokenService,
    extract_jti,
)
from apps.users.infrastructure.totp_service import PyOTPService
from apps.users.presentation.serializers import (
    AnnouncementRequestSerializer,
    AnnouncementResponseSerializer,
    ChangePasswordSerializer,
    ConfirmPasswordResetSerializer,
    DisableMFASerializer,
    FeatureFlagRequestSerializer,
    FeatureFlagResponseSerializer,
    FeatureFlagUpdateSerializer,
    LoginRequestSerializer,
    LogoutRequestSerializer,
    MFAChallengeSerializer,
    MFACodeSerializer,
    MFASetupResponseSerializer,
    OTPConfirmSerializer,
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

_R400 = OpenApiResponse(
    description="Request contains invalid data (e.g. wrong or expired OTP).",
    response=_ERROR_ENVELOPE,
)
_R401 = OpenApiResponse(description="Authentication credentials are missing or invalid.", response=_ERROR_ENVELOPE)
_R403 = OpenApiResponse(description="You do not have permission to perform this action.", response=_ERROR_ENVELOPE)
_R404 = OpenApiResponse(description="The requested resource was not found.", response=_ERROR_ENVELOPE)
_R409 = OpenApiResponse(description="Request conflicts with the current resource state.", response=_ERROR_ENVELOPE)
_R422 = OpenApiResponse(
    description="Payload failed validation. details contains a flat list of {field, message} objects.",
    response=_ERROR_ENVELOPE,
)
_R423 = OpenApiResponse(
    description="Account is temporarily locked. details.locked_until contains the unlock timestamp.",
    response=_ERROR_ENVELOPE,
)
_R503 = OpenApiResponse(description="One or more dependencies are unavailable.", response=_ERROR_ENVELOPE)


def _audit(request: Request, user_id: uuid.UUID, event_type: str, metadata: dict | None = None) -> None:
    """Write an audit log entry, swallowing persistence errors so they never block responses."""
    AuditService(DjangoAuditLogRepository()).log(request, user_id, event_type, metadata)


def _notify_security(
    request: Request,
    event_type: str,
    extra: dict | None = None,
) -> None:
    """Publish a security notification event via RabbitMQ, swallowing errors."""
    try:
        user = request.user  # type: ignore[attr-defined]
        from apps.users.infrastructure.audit_service import _get_ip

        RabbitMQEventPublisher().publish(
            event_type,
            {
                "user_id": str(user.id),
                "email": user.email,
                "first_name": getattr(user, "first_name", ""),
                "ip_address": _get_ip(request),
                **(extra or {}),
            },
        )
    except Exception:
        pass


def _create_session(request: Request, refresh_token: str) -> None:
    """Create a UserSession record for the issued refresh token, swallowing errors."""
    try:
        jti = extract_jti(refresh_token)
        from rest_framework_simplejwt.tokens import RefreshToken as JWTRefresh

        token = JWTRefresh(refresh_token)
        user_id = uuid.UUID(str(token["user_id"]))
        SessionService().create_session(request, user_id, jti)
    except Exception:
        pass


class HealthCheckView(APIView):
    """Reports the operational status of all external dependencies."""

    authentication_classes: list = []
    permission_classes = [AllowAny]

    @extend_schema(
        tags=["Health"],
        summary="Service health check",
        description=(
            "Checks connectivity to PostgreSQL, Redis, and RabbitMQ. Returns 200 when all dependencies are healthy, 503 when any are down."
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
        dep_errors: dict = {k: v for k, v in {"database": db_err, "redis": redis_err, "rabbitmq": rmq_err}.items() if v is not None}

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


class PlatformStatusView(APIView):
    """Public endpoint that returns platform-wide flags like maintenance mode."""

    authentication_classes: list = []
    permission_classes = [AllowAny]

    @extend_schema(
        tags=["Platform"],
        summary="Platform status",
        description="Returns platform status flags. No authentication required.",
        auth=[],
        responses={200: OpenApiResponse(description="Platform status.")},
    )
    def get(self, request: Request) -> Response:
        """Check if maintenance_mode flag is enabled."""
        repo = DjangoFeatureFlagRepository()
        try:
            flag = repo.get_by_key("maintenance_mode")
            maintenance = flag.is_enabled
        except Exception:
            maintenance = False
        return success_response({"maintenance": maintenance}, request=request)


class RegisterView(APIView):
    """Create a new unverified user account and dispatch an email verification OTP."""

    authentication_classes: list = []
    permission_classes = [AllowAny]
    throttle_scope = "registration"

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

        entity = RegisterUseCase(DjangoUserRepository(), RedisOTPService(), RabbitMQEventPublisher()).execute(
            email=d["email"],
            password=d["password"],
            first_name=d["first_name"],
            last_name=d["last_name"],
        )
        _audit(request, entity.id, AuditEventType.USER_REGISTERED, {"email": entity.email})
        return created_response(UserResponseSerializer(entity).data, request=request)


class LoginView(APIView):
    """Authenticate with email and password."""

    authentication_classes: list = []
    permission_classes = [AllowAny]
    throttle_scope = "login"

    @extend_schema(
        tags=["Auth"],
        summary="Log in",
        description=(
            "Authenticate with email and password. "
            "Returns JWT tokens on success. "
            "When MFA is enabled, returns mfa_required=true and user_id instead of tokens; "
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
                                "mfa_type": serializers.CharField(
                                    allow_null=True,
                                    help_text="Populated when mfa_required is true: 'totp', 'sms', or 'email'.",
                                ),
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

        from apps.users.domain.exceptions import AccountLockedError, InvalidCredentialsError

        try:
            result = LoginUseCase(
                DjangoUserRepository(),
                JWTTokenService(),
                otp_service=RedisOTPService("mfa_login"),
                event_publisher=RabbitMQEventPublisher(),
            ).execute(
                email=d["email"],
                password=d["password"],
            )
        except AccountLockedError as exc:
            try:
                from apps.users.infrastructure.audit_service import _get_ip

                user = DjangoUserRepository().get_by_email(d["email"].lower().strip())
                _audit(request, user.id, AuditEventType.ACCOUNT_LOCKED, {"email": user.email})
                RabbitMQEventPublisher().publish(
                    "iam.account_locked",
                    {
                        "user_id": str(user.id),
                        "email": user.email,
                        "first_name": user.first_name,
                        "locked_until": exc.details["locked_until"] if exc.details else None,
                        "ip_address": _get_ip(request),
                    },
                )
            except Exception:
                pass
            raise
        except InvalidCredentialsError:
            # audit failed login attempts for security monitoring
            try:
                user = DjangoUserRepository().get_by_email(d["email"].lower().strip())
                _audit(request, user.id, AuditEventType.LOGIN_FAILED, {"email": d["email"]})
            except Exception:
                pass
            raise

        if result.user_id:
            if result.mfa_required:
                _audit(request, result.user_id, AuditEventType.LOGIN_MFA_CHALLENGED)
            else:
                if result.refresh_token:
                    _create_session(request, result.refresh_token)
                _audit(request, result.user_id, AuditEventType.LOGIN_SUCCESS)

        return success_response(
            {
                "mfa_required": result.mfa_required,
                "mfa_type": result.mfa_type,
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
            200: OpenApiResponse(description="Session terminated successfully.", response=_MSG_ENVELOPE),
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
        _audit(request, request.user.id, AuditEventType.LOGOUT)  # type: ignore[attr-defined]
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
            200: OpenApiResponse(description="Email verified successfully.", response=_MSG_ENVELOPE),
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

        VerifyEmailUseCase(DjangoUserRepository(), RedisOTPService()).execute(email=d["email"], otp=d["otp"])
        try:
            user = DjangoUserRepository().get_by_email(d["email"])
            _audit(request, user.id, AuditEventType.EMAIL_VERIFIED)
        except Exception:
            pass
        return success_response({"message": "Email verified successfully."}, request=request)


class ResendVerificationOTPView(APIView):
    """Send a fresh email verification OTP."""

    authentication_classes: list = []
    permission_classes = [AllowAny]

    @extend_schema(
        tags=["Auth"],
        summary="Resend verification OTP",
        description=("Generates a new 8-character OTP and sends it to the email address. Any previously issued OTP is overwritten."),
        auth=[],
        request=ResendVerificationOTPRequestSerializer,
        responses={
            200: OpenApiResponse(description="Verification OTP sent to the email address.", response=_MSG_ENVELOPE),
            404: _R404,
            409: _R409,
            422: _R422,
        },
    )
    def post(self, request: Request) -> Response:
        """Generate a new OTP and publish the verification event."""
        ser = ResendVerificationOTPRequestSerializer(data=request.data)
        ser.is_valid(raise_exception=True)

        ResendVerificationOTPUseCase(DjangoUserRepository(), RedisOTPService(), RabbitMQEventPublisher()).execute(
            email=ser.validated_data["email"]
        )
        return success_response({"message": "Verification OTP sent."}, request=request)


class RequestPasswordResetView(APIView):
    """Send a password-reset OTP to the given email address."""

    authentication_classes: list = []
    permission_classes = [AllowAny]
    throttle_scope = "password_reset"

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
            200: OpenApiResponse(description="Password reset OTP sent to the email address.", response=_MSG_ENVELOPE),
            401: _R401,
            404: _R404,
            422: _R422,
        },
    )
    def post(self, request: Request) -> Response:
        """Generate and publish a password-reset OTP."""
        ser = RequestPasswordResetSerializer(data=request.data)
        ser.is_valid(raise_exception=True)

        RequestPasswordResetUseCase(DjangoUserRepository(), RedisOTPService("password_reset"), RabbitMQEventPublisher()).execute(
            email=ser.validated_data["email"]
        )
        try:
            user = DjangoUserRepository().get_by_email(ser.validated_data["email"])
            _audit(request, user.id, AuditEventType.PASSWORD_RESET_REQUESTED)
        except Exception:
            pass
        return success_response({"message": "Password reset OTP sent."}, request=request)


class VerifyPasswordResetOTPView(APIView):
    """Verify a password-reset OTP is valid without consuming it (step 2 of 3-page reset flow)."""

    authentication_classes: list = []
    permission_classes = [AllowAny]

    @extend_schema(
        tags=["Auth"],
        summary="Verify password-reset OTP",
        description=(
            "Validates the OTP without consuming it. "
            "Call this on page 2 of the reset flow to confirm the code before showing the "
            "new-password form. The OTP is only consumed when POST /auth/password/reset/confirm/ is called."
        ),
        auth=[],
        request=inline_serializer(
            name="VerifyPasswordResetOTPRequest",
            fields={
                "email": serializers.EmailField(),
                "otp": serializers.CharField(min_length=8, max_length=8),
            },
        ),
        responses={
            200: OpenApiResponse(description="OTP is valid.", response=_MSG_ENVELOPE),
            400: _R400,
            404: _R404,
            422: _R422,
        },
    )
    def post(self, request: Request) -> Response:
        """Check the OTP without deleting it."""
        from apps.users.application.use_cases.verify_password_reset_otp import (
            VerifyPasswordResetOTPUseCase,
        )
        from apps.users.presentation.serializers import VerifyPasswordResetOTPSerializer

        ser = VerifyPasswordResetOTPSerializer(data=request.data)
        ser.is_valid(raise_exception=True)
        d = ser.validated_data

        VerifyPasswordResetOTPUseCase(DjangoUserRepository(), RedisOTPService("password_reset")).execute(email=d["email"], otp=d["otp"])
        return success_response({"message": "OTP is valid."}, request=request)


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
            "The new password must meet the minimum security requirements and not be recently used."
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
        """Validate OTP, check history, update password, and invalidate all sessions."""
        ser = ConfirmPasswordResetSerializer(data=request.data)
        ser.is_valid(raise_exception=True)
        d = ser.validated_data

        try:
            _uid = DjangoUserRepository().get_by_email(d["email"]).id
        except Exception:
            _uid = None

        ConfirmPasswordResetUseCase(
            DjangoUserRepository(),
            RedisOTPService("password_reset"),
            JWTTokenBlacklistService(),
            PasswordHistoryService(),
        ).execute(email=d["email"], otp=d["otp"], new_password=d["new_password"])

        if _uid:
            _audit(request, _uid, AuditEventType.PASSWORD_RESET_COMPLETED)
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
            "Cannot reuse any of the last 5 passwords. "
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
        """Verify current password, check history, set new one, and blacklist all sessions."""
        ser = ChangePasswordSerializer(data=request.data)
        ser.is_valid(raise_exception=True)
        d = ser.validated_data

        ChangePasswordUseCase(DjangoUserRepository(), JWTTokenBlacklistService(), PasswordHistoryService()).execute(
            user_id=request.user.id,  # type: ignore[attr-defined]
            current_password=d["current_password"],
            new_password=d["new_password"],
        )
        _audit(request, request.user.id, AuditEventType.PASSWORD_CHANGED)  # type: ignore[attr-defined]
        _notify_security(request, "iam.password_changed")
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
            200: OpenApiResponse(description="MFA enabled successfully.", response=_MSG_ENVELOPE),
            400: _R400,
            401: _R401,
            409: _R409,
            422: _R422,
        },
    )
    def post(self, request: Request) -> Response:
        """Verify the code, activate MFA, and return one-time backup codes."""
        from apps.users.infrastructure.backup_code_service import BackupCodeService

        ser = MFACodeSerializer(data=request.data)
        ser.is_valid(raise_exception=True)

        result = EnableMFAUseCase(DjangoUserRepository(), PyOTPService(), BackupCodeService()).execute(
            user_id=request.user.id,  # type: ignore[attr-defined]
            code=ser.validated_data["code"],
        )
        _audit(request, request.user.id, AuditEventType.MFA_ENABLED)  # type: ignore[attr-defined]
        _notify_security(request, "iam.mfa_enabled")
        return success_response(
            {"message": "MFA enabled successfully.", "backup_codes": result.backup_codes},
            request=request,
        )


class MFADisableView(APIView):
    """Disable MFA after verifying a TOTP code (totp) or current password (sms/email)."""

    permission_classes = [IsAuthenticated]

    @extend_schema(
        tags=["MFA"],
        summary="Disable MFA",
        description=(
            "Deactivate MFA and clear the stored secret. "
            "TOTP users must supply a valid 6-digit code. "
            "SMS/email users must supply their current password. "
            "After this, login returns tokens directly without an MFA challenge."
        ),
        request=DisableMFASerializer,
        responses={
            200: OpenApiResponse(description="MFA disabled successfully. Secret cleared.", response=_MSG_ENVELOPE),
            400: _R400,
            401: _R401,
            409: _R409,
            422: _R422,
        },
    )
    def post(self, request: Request) -> Response:
        """Verify the credential appropriate for the MFA type and deactivate MFA."""
        ser = DisableMFASerializer(data=request.data)
        ser.is_valid(raise_exception=True)
        d = ser.validated_data

        DisableMFAUseCase(DjangoUserRepository(), PyOTPService()).execute(
            user_id=request.user.id,  # type: ignore[attr-defined]
            code=d.get("code"),
            current_password=d.get("current_password"),
        )
        _audit(request, request.user.id, AuditEventType.MFA_DISABLED)  # type: ignore[attr-defined]
        _notify_security(request, "iam.mfa_disabled")
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
            200: OpenApiResponse(description="TOTP verified. JWT tokens issued.", response=_TOKEN_PAIR_ENVELOPE),
            400: _R400,
            401: _R401,
            404: _R404,
            422: _R422,
        },
    )
    def post(self, request: Request) -> Response:
        """Verify the TOTP or backup code and return access and refresh tokens."""
        from apps.users.infrastructure.backup_code_service import BackupCodeService

        ser = MFAChallengeSerializer(data=request.data)
        ser.is_valid(raise_exception=True)
        d = ser.validated_data

        result = MFAChallengeUseCase(
            DjangoUserRepository(),
            PyOTPService(),
            JWTTokenService(),
            BackupCodeService(),
            otp_service=RedisOTPService("mfa_login"),
        ).execute(user_id=d["user_id"], code=d["code"])

        if result.refresh_token:
            _create_session(request, result.refresh_token)
        _audit(
            request,
            d["user_id"],
            AuditEventType.LOGIN_MFA_SUCCESS,
            {"used_backup_code": result.used_backup_code},
        )

        return success_response(
            {
                "access_token": result.access_token,
                "refresh_token": result.refresh_token,
                "used_backup_code": result.used_backup_code,
            },
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
            phone=d.get("phone"),
            bio=d.get("bio"),
        )
        _audit(request, request.user.id, AuditEventType.PROFILE_UPDATED, {"fields": list(d.keys())})  # type: ignore[attr-defined]
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

        user_id = request.user.id  # type: ignore[attr-defined]
        DeleteAccountUseCase(DjangoUserRepository(), JWTTokenBlacklistService()).execute(
            user_id=user_id,
        )
        _audit(request, user_id, AuditEventType.ACCOUNT_DELETED)
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
            "This endpoint trusts the internal network; restrict it at the gateway in production."
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


class GoogleSocialAuthView(APIView):
    """Sign in or register with a Google ID token."""

    authentication_classes: list = []
    permission_classes = [AllowAny]

    @extend_schema(
        tags=["Social Auth"],
        summary="Sign in with Google",
        description=(
            "Accepts a Google ID token obtained from Google's client-side SDK "
            "(e.g. @react-oauth/google). "
            "Verifies the token, then either logs in the existing account or creates a new one. "
            "Existing accounts registered with email/password are automatically linked by email. "
            "Returns JWT tokens and a flag indicating whether a new account was created."
        ),
        auth=[],
        request=inline_serializer(
            name="GoogleSocialAuthRequest",
            fields={"id_token": serializers.CharField(help_text="Google ID token from the client SDK.")},
        ),
        responses={
            200: OpenApiResponse(
                description="Sign-in successful. JWT tokens issued.",
                response=inline_serializer(
                    name="GoogleSocialAuthEnvelope",
                    fields={
                        "data": inline_serializer(
                            name="GoogleSocialAuthData",
                            fields={
                                "access_token": serializers.CharField(),
                                "refresh_token": serializers.CharField(),
                                "is_new_user": serializers.BooleanField(help_text="True if a new account was created during this sign-in."),
                            },
                        ),
                        "error": serializers.JSONField(allow_null=True, default=None),
                        "meta": _META,
                    },
                ),
            ),
            401: _R401,
            403: _R403,
            422: _R422,
        },
    )
    def post(self, request: Request) -> Response:
        """Verify the Google ID token and return JWT tokens."""
        from apps.users.application.use_cases.google_social_auth import GoogleSocialAuthUseCase
        from apps.users.infrastructure.google_verifier import GoogleTokenVerifier
        from apps.users.presentation.serializers import GoogleSocialAuthSerializer

        ser = GoogleSocialAuthSerializer(data=request.data)
        ser.is_valid(raise_exception=True)

        result = GoogleSocialAuthUseCase(DjangoUserRepository(), GoogleTokenVerifier(), JWTTokenService()).execute(
            id_token=ser.validated_data["id_token"]
        )

        if result.refresh_token:
            _create_session(request, result.refresh_token)
        try:
            user = DjangoUserRepository().get_by_email(GoogleTokenVerifier().verify(ser.validated_data["id_token"])["email"])
            _audit(
                request,
                user.id,
                AuditEventType.SOCIAL_AUTH_GOOGLE,
                {"is_new_user": result.is_new_user},
            )
        except Exception:
            pass

        return success_response(
            {
                "access_token": result.access_token,
                "refresh_token": result.refresh_token,
                "is_new_user": result.is_new_user,
            },
            request=request,
        )


class GithubSocialAuthView(APIView):
    """Sign in or register with a GitHub OAuth access token."""

    authentication_classes: list = []
    permission_classes = [AllowAny]

    @extend_schema(
        tags=["Social Auth"],
        summary="Sign in with GitHub",
        description=(
            "Accepts a GitHub OAuth access token obtained from the GitHub OAuth flow. "
            "Fetches the user profile from the GitHub API, then either logs in the existing "
            "account or creates a new one. "
            "Existing accounts registered with email/password are automatically linked by email. "
            "Returns JWT tokens and a flag indicating whether a new account was created."
        ),
        auth=[],
        request=inline_serializer(
            name="GithubSocialAuthRequest",
            fields={"access_token": serializers.CharField(help_text="GitHub OAuth access token.")},
        ),
        responses={
            200: OpenApiResponse(
                description="Sign-in successful. JWT tokens issued.",
                response=inline_serializer(
                    name="GithubSocialAuthEnvelope",
                    fields={
                        "data": inline_serializer(
                            name="GithubSocialAuthData",
                            fields={
                                "access_token": serializers.CharField(),
                                "refresh_token": serializers.CharField(),
                                "is_new_user": serializers.BooleanField(help_text="True if a new account was created during this sign-in."),
                            },
                        ),
                        "error": serializers.JSONField(allow_null=True, default=None),
                        "meta": _META,
                    },
                ),
            ),
            401: _R401,
            403: _R403,
            422: _R422,
        },
    )
    def post(self, request: Request) -> Response:
        """Fetch the GitHub profile and return JWT tokens."""
        from apps.users.application.use_cases.github_social_auth import GithubSocialAuthUseCase
        from apps.users.infrastructure.github_verifier import GithubTokenVerifier

        token = request.data.get("access_token", "")
        if not token:
            return Response({"error": "access_token is required."}, status=422)

        result = GithubSocialAuthUseCase(DjangoUserRepository(), GithubTokenVerifier(), JWTTokenService()).execute(access_token=token)

        if result.refresh_token:
            _create_session(request, result.refresh_token)
        try:
            user = DjangoUserRepository().get_by_email(GithubTokenVerifier().verify(token)["email"])
            _audit(
                request,
                user.id,
                AuditEventType.SOCIAL_AUTH_GITHUB,
                {"is_new_user": result.is_new_user},
            )
        except Exception:
            pass

        return success_response(
            {
                "access_token": result.access_token,
                "refresh_token": result.refresh_token,
                "is_new_user": result.is_new_user,
            },
            request=request,
        )


class AdminUserListView(APIView):
    """Superadmin: list all platform users."""

    permission_classes = [IsSuperAdminFromAllowedIP]

    @extend_schema(
        tags=["Admin"],
        summary="List all users",
        description="Returns every non-deleted user. Restricted to is_staff=True accounts.",
        responses={
            200: OpenApiResponse(description="User list.", response=UserResponseSerializer(many=True)),
            401: OpenApiResponse(description="Missing or invalid JWT."),
            403: OpenApiResponse(description="Not a staff account."),
        },
    )
    def get(self, request: Request) -> Response:
        """Return all users. Staff only."""
        users = ListUsersUseCase(DjangoUserRepository()).execute()
        return success_response(UserResponseSerializer(users, many=True).data, request=request)


class AdminUserSuspendView(APIView):
    """Superadmin: suspend a user account."""

    permission_classes = [IsSuperAdminFromAllowedIP]

    @extend_schema(
        tags=["Admin"],
        summary="Suspend user",
        request=None,
        responses={
            200: OpenApiResponse(description="User suspended.", response=UserResponseSerializer),
            401: OpenApiResponse(description="Missing or invalid JWT."),
            403: OpenApiResponse(description="Not a staff account."),
            404: OpenApiResponse(description="User not found."),
        },
    )
    def post(self, request: Request, user_id: uuid.UUID) -> Response:
        """Set is_active=False on the given user. Staff only."""
        entity = SuspendUserUseCase(DjangoUserRepository()).execute(user_id=user_id)
        _audit(request, user_id, AuditEventType.USER_SUSPENDED, {"email": entity.email})
        return success_response(UserResponseSerializer(entity).data, request=request)


class AdminUserActivateView(APIView):
    """Superadmin: activate a suspended user account."""

    permission_classes = [IsSuperAdminFromAllowedIP]

    @extend_schema(
        tags=["Admin"],
        summary="Activate user",
        request=None,
        responses={
            200: OpenApiResponse(description="User activated.", response=UserResponseSerializer),
            401: OpenApiResponse(description="Missing or invalid JWT."),
            403: OpenApiResponse(description="Not a staff account."),
            404: OpenApiResponse(description="User not found."),
        },
    )
    def post(self, request: Request, user_id: uuid.UUID) -> Response:
        """Set is_active=True on the given user. Staff only."""
        entity = ActivateUserUseCase(DjangoUserRepository()).execute(user_id=user_id)
        _audit(request, user_id, AuditEventType.USER_ACTIVATED, {"email": entity.email})
        return success_response(UserResponseSerializer(entity).data, request=request)


class AdminAuditLogView(APIView):
    """GET /admin/audit-log/ - list all platform audit events, staff only."""

    permission_classes = [IsSuperAdminFromAllowedIP]

    @extend_schema(
        tags=["Admin"],
        summary="List platform audit log",
        description="Returns the 200 most recent audit events across all users. Staff only.",
        responses={
            200: OpenApiResponse(description="Audit log entries."),
            403: OpenApiResponse(description="Not a staff account."),
        },
    )
    def get(self, request: Request) -> Response:
        """Return the most recent audit events. Staff only."""
        from apps.users.infrastructure.audit_models import AuditLog
        from apps.users.infrastructure.models import User as UserModel

        rows = AuditLog.objects.all()[:200]

        user_ids = {str(r.user_id) for r in rows}
        user_map: dict[str, dict] = {}
        fields = ("id", "email", "first_name", "last_name", "is_staff", "is_superuser")
        for u in UserModel.objects.filter(id__in=user_ids).values(*fields):
            user_map[str(u["id"])] = u

        data = []
        for row in rows:
            uid = str(row.user_id)
            u = user_map.get(uid, {})
            first = u.get("first_name", "")
            last = u.get("last_name", "")
            actor_name = f"{first} {last}".strip() if (first or last) else uid
            role = "Super Admin" if u.get("is_superuser") else ("Staff" if u.get("is_staff") else "User")
            data.append(
                {
                    "id": str(row.id),
                    "user_id": uid,
                    "actor_name": actor_name,
                    "actor_email": u.get("email", ""),
                    "actor_role": role,
                    "event_type": row.event_type,
                    "ip_address": row.ip_address,
                    "user_agent": row.user_agent,
                    "metadata": row.metadata,
                    "created_at": row.created_at.isoformat(),
                }
            )

        return success_response(data, request=request)


class AdminIAMAnalyticsView(APIView):
    """GET /admin/analytics/ - monthly user registration stats for the superadmin dashboard."""

    permission_classes = [IsSuperAdminFromAllowedIP]

    @extend_schema(
        tags=["Admin"],
        summary="Platform user analytics",
        description="Monthly user registration series and 30-day growth. Staff only.",
        responses={200: OpenApiResponse(description="Aggregated user analytics.")},
    )
    def get(self, request: Request) -> Response:
        """Return monthly user counts and 30D growth. Staff only."""
        from datetime import datetime, timedelta, timezone

        from django.db.models import Count
        from django.db.models.functions import TruncMonth

        from apps.users.infrastructure.models import User as UserModel

        now = datetime.now(timezone.utc)
        d30 = now - timedelta(days=30)
        d60 = now - timedelta(days=60)
        d365 = now - timedelta(days=365)

        regular_qs = UserModel.objects.filter(is_superuser=False)
        new_30d = regular_qs.filter(date_joined__gte=d30).count()
        prev_30d = regular_qs.filter(date_joined__gte=d60, date_joined__lt=d30).count()
        total = regular_qs.count()

        monthly_qs = (
            regular_qs.filter(date_joined__gte=d365)
            .annotate(month=TruncMonth("date_joined"))
            .values("month")
            .annotate(count=Count("id"))
            .order_by("month")
        )
        month_map = {row["month"].strftime("%Y-%m"): row["count"] for row in monthly_qs}

        # cumulative series
        buckets = []
        for i in range(11, -1, -1):
            from datetime import timedelta as td

            dt = now.replace(day=1) - td(days=30 * i)
            key = dt.strftime("%Y-%m")
            buckets.append(month_map.get(key, 0))

        cumsum, cumulative = 0, []
        for v in buckets:
            cumsum += v
            cumulative.append(cumsum)

        return success_response(
            {
                "new_users_30d": new_30d,
                "prev_users_30d": prev_30d,
                "total_users": total,
                "monthly_series": cumulative,
            },
            request=request,
        )


class JWKSView(APIView):
    """Exposes the RSA public key(s) used to verify JWT access tokens."""

    authentication_classes: list = []
    permission_classes = [AllowAny]

    @extend_schema(
        tags=["Auth"],
        summary="JSON Web Key Set",
        description="Returns the RSA public key(s) used to verify JWT access tokens (RFC 7517).",
        auth=[],
        responses={200: OpenApiResponse(description="JWKS document.")},
    )
    def get(self, request: Request) -> Response:
        """Return the public key set; empty when the service uses HS256."""
        import json

        from jwt.algorithms import RSAAlgorithm

        algorithm: str = settings.SIMPLE_JWT.get("ALGORITHM", "HS256")
        verifying_key: str = settings.SIMPLE_JWT.get("VERIFYING_KEY", "")

        if algorithm != "RS256" or not verifying_key:
            return Response({"keys": []})

        from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
        from cryptography.hazmat.primitives.serialization import load_pem_public_key

        key_obj = load_pem_public_key(verifying_key.encode())
        if not isinstance(key_obj, RSAPublicKey):
            return Response({"keys": []})
        jwk: dict = json.loads(RSAAlgorithm.to_jwk(key_obj))
        jwk.setdefault("use", "sig")
        jwk.setdefault("alg", "RS256")
        jwk.setdefault("kid", "1")
        return Response({"keys": [jwk]})


class MFASMSSetupView(APIView):
    """Initiate SMS MFA setup by sending an OTP to the user's registered phone."""

    permission_classes = [IsAuthenticated]

    @extend_schema(
        tags=["MFA"],
        summary="Initiate SMS MFA setup",
        description=(
            "Generates an OTP and dispatches it via SMS to the user's registered phone number. "
            "Confirm setup by calling POST /auth/mfa/sms/enable/ with the received OTP. "
            "Requires a phone number on the user profile."
        ),
        request=None,
        responses={
            200: OpenApiResponse(description="OTP sent via SMS.", response=_MSG_ENVELOPE),
            400: _R400,
            401: _R401,
            409: _R409,
        },
    )
    def post(self, request: Request) -> Response:
        """Generate and dispatch the SMS OTP."""
        SetupSMSMFAUseCase(
            DjangoUserRepository(),
            RedisOTPService("mfa_sms_setup"),
            RabbitMQEventPublisher(),
        ).execute(user_id=request.user.id)  # type: ignore[attr-defined]
        return success_response({"message": "OTP sent via SMS."}, request=request)


class MFASMSEnableView(APIView):
    """Confirm SMS MFA setup by verifying the received OTP."""

    permission_classes = [IsAuthenticated]

    @extend_schema(
        tags=["MFA"],
        summary="Enable SMS MFA",
        description=(
            "Submit the OTP received via SMS to activate SMS MFA. "
            "Must be called after POST /auth/mfa/sms/setup/. "
            "Returns one-time backup codes on success."
        ),
        request=OTPConfirmSerializer,
        responses={
            200: OpenApiResponse(description="SMS MFA enabled. Backup codes returned.", response=_MSG_ENVELOPE),
            400: _R400,
            401: _R401,
            409: _R409,
            422: _R422,
        },
    )
    def post(self, request: Request) -> Response:
        """Verify the OTP, activate SMS MFA, and return backup codes."""
        from apps.users.infrastructure.backup_code_service import BackupCodeService

        ser = OTPConfirmSerializer(data=request.data)
        ser.is_valid(raise_exception=True)

        result = EnableSMSMFAUseCase(
            DjangoUserRepository(),
            RedisOTPService("mfa_sms_setup"),
            BackupCodeService(),
        ).execute(
            user_id=request.user.id,  # type: ignore[attr-defined]
            otp=ser.validated_data["otp"],
        )
        _audit(request, request.user.id, AuditEventType.MFA_ENABLED)  # type: ignore[attr-defined]
        _notify_security(request, "iam.mfa_enabled", {"mfa_type": "sms"})
        return success_response(
            {"message": "SMS MFA enabled successfully.", "backup_codes": result.backup_codes},
            request=request,
        )


class MFAEmailSetupView(APIView):
    """Initiate email MFA setup by sending an OTP to the user's registered email."""

    permission_classes = [IsAuthenticated]

    @extend_schema(
        tags=["MFA"],
        summary="Initiate email MFA setup",
        description=(
            "Generates an OTP and dispatches it to the user's email address. "
            "Confirm setup by calling POST /auth/mfa/email/enable/ with the received OTP. "
        ),
        request=None,
        responses={
            200: OpenApiResponse(description="OTP sent via email.", response=_MSG_ENVELOPE),
            400: _R400,
            401: _R401,
            409: _R409,
        },
    )
    def post(self, request: Request) -> Response:
        """Generate and dispatch the email OTP."""
        SetupEmailMFAUseCase(
            DjangoUserRepository(),
            RedisOTPService("mfa_email_setup"),
            RabbitMQEventPublisher(),
        ).execute(user_id=request.user.id)  # type: ignore[attr-defined]
        return success_response({"message": "OTP sent via email."}, request=request)


class MFAEmailEnableView(APIView):
    """Confirm email MFA setup by verifying the received OTP."""

    permission_classes = [IsAuthenticated]

    @extend_schema(
        tags=["MFA"],
        summary="Enable email MFA",
        description=(
            "Submit the OTP received via email to activate email MFA. "
            "Must be called after POST /auth/mfa/email/setup/. "
            "Returns one-time backup codes on success."
        ),
        request=OTPConfirmSerializer,
        responses={
            200: OpenApiResponse(description="Email MFA enabled. Backup codes returned.", response=_MSG_ENVELOPE),
            400: _R400,
            401: _R401,
            409: _R409,
            422: _R422,
        },
    )
    def post(self, request: Request) -> Response:
        """Verify the OTP, activate email MFA, and return backup codes."""
        from apps.users.infrastructure.backup_code_service import BackupCodeService

        ser = OTPConfirmSerializer(data=request.data)
        ser.is_valid(raise_exception=True)

        result = EnableEmailMFAUseCase(
            DjangoUserRepository(),
            RedisOTPService("mfa_email_setup"),
            BackupCodeService(),
        ).execute(
            user_id=request.user.id,  # type: ignore[attr-defined]
            otp=ser.validated_data["otp"],
        )
        _audit(request, request.user.id, AuditEventType.MFA_ENABLED)  # type: ignore[attr-defined]
        _notify_security(request, "iam.mfa_enabled", {"mfa_type": "email"})
        return success_response(
            {"message": "Email MFA enabled successfully.", "backup_codes": result.backup_codes},
            request=request,
        )


class AdminFeatureFlagListView(APIView):
    """List all platform feature flags or create a new one."""

    permission_classes = [IsSuperAdminFromAllowedIP]

    @extend_schema(
        tags=["Admin"],
        summary="List feature flags",
        responses={
            200: OpenApiResponse(description="Feature flags.", response=FeatureFlagResponseSerializer(many=True)),
            401: OpenApiResponse(description="Missing or invalid JWT."),
        },
    )
    def get(self, request: Request) -> Response:
        """Return all feature flags ordered by key."""
        flags = ListFeatureFlagsUseCase(DjangoFeatureFlagRepository()).execute()
        return success_response(FeatureFlagResponseSerializer(flags, many=True).data, request=request)

    @extend_schema(
        tags=["Admin"],
        summary="Create feature flag",
        request=FeatureFlagRequestSerializer,
        responses={
            201: OpenApiResponse(description="Flag created.", response=FeatureFlagResponseSerializer),
            401: OpenApiResponse(description="Missing or invalid JWT."),
            409: OpenApiResponse(description="Key already exists."),
        },
    )
    def post(self, request: Request) -> Response:
        """Create and persist a new feature flag."""
        ser = FeatureFlagRequestSerializer(data=request.data)
        ser.is_valid(raise_exception=True)
        d = ser.validated_data
        result = CreateFeatureFlagUseCase(DjangoFeatureFlagRepository()).execute(
            key=d["key"],
            name=d["name"],
            description=d["description"],
            is_enabled=d["is_enabled"],
            enabled_plans=d["enabled_plans"],
            enabled_org_ids=d["enabled_org_ids"],
        )
        return created_response(FeatureFlagResponseSerializer(result).data, request=request)


class AdminFeatureFlagDetailView(APIView):
    """Update or delete a specific feature flag by key."""

    permission_classes = [IsSuperAdminFromAllowedIP]

    @extend_schema(
        tags=["Admin"],
        summary="Update feature flag",
        request=FeatureFlagUpdateSerializer,
        responses={
            200: OpenApiResponse(description="Flag updated.", response=FeatureFlagResponseSerializer),
            401: OpenApiResponse(description="Missing or invalid JWT."),
            404: OpenApiResponse(description="Flag not found."),
        },
    )
    def patch(self, request: Request, key: str) -> Response:
        """Partial update on the feature flag - only provided fields are changed."""
        ser = FeatureFlagUpdateSerializer(data=request.data)
        ser.is_valid(raise_exception=True)
        result = UpdateFeatureFlagUseCase(DjangoFeatureFlagRepository()).execute(
            key=key,
            **ser.validated_data,
        )
        return success_response(FeatureFlagResponseSerializer(result).data, request=request)

    @extend_schema(
        tags=["Admin"],
        summary="Delete feature flag",
        request=None,
        responses={
            204: OpenApiResponse(description="Flag deleted."),
            401: OpenApiResponse(description="Missing or invalid JWT."),
            404: OpenApiResponse(description="Flag not found."),
        },
    )
    def delete(self, request: Request, key: str) -> Response:
        """Permanently remove a feature flag."""
        DeleteFeatureFlagUseCase(DjangoFeatureFlagRepository()).execute(key=key)
        return Response(status=204)


class AdminAnnouncementView(APIView):
    """List all announcements or create a new one."""

    permission_classes = [IsSuperAdminFromAllowedIP]

    @extend_schema(
        tags=["Admin"],
        summary="List announcements",
        responses={
            200: OpenApiResponse(description="Announcements.", response=AnnouncementResponseSerializer(many=True)),
            401: OpenApiResponse(description="Missing or invalid JWT."),
        },
    )
    def get(self, request: Request) -> Response:
        """Return all announcements ordered by created_at descending."""
        items = ListAnnouncementsUseCase(DjangoAnnouncementRepository()).execute()
        return success_response(AnnouncementResponseSerializer(items, many=True).data, request=request)

    @extend_schema(
        tags=["Admin"],
        summary="Create announcement",
        request=AnnouncementRequestSerializer,
        responses={
            201: OpenApiResponse(description="Announcement created.", response=AnnouncementResponseSerializer),
            401: OpenApiResponse(description="Missing or invalid JWT."),
        },
    )
    def post(self, request: Request) -> Response:
        """Create and persist a new platform announcement."""
        ser = AnnouncementRequestSerializer(data=request.data)
        ser.is_valid(raise_exception=True)
        d = ser.validated_data
        result = CreateAnnouncementUseCase(DjangoAnnouncementRepository()).execute(
            title=d["title"],
            body=d["body"],
            target_plans=d["target_plans"],
            is_active=d["is_active"],
            scheduled_at=d["scheduled_at"],
        )
        return created_response(AnnouncementResponseSerializer(result).data, request=request)


class _GithubSocialAuthViewDuplicate(APIView):
    """DUPLICATE - kept to avoid import errors. Use the one defined earlier."""

    authentication_classes: list = []
    permission_classes = [AllowAny]

    @extend_schema(
        tags=["Social Auth"],
        summary="Sign in with GitHub (duplicate)",
        description="Duplicate class - see earlier definition.",
        auth=[],
        request=inline_serializer(
            name="GithubSocialAuthRequest2",
            fields={"access_token": serializers.CharField(help_text="GitHub OAuth access token.")},
        ),
        responses={
            200: OpenApiResponse(
                description="Sign-in successful. JWT tokens issued.",
                response=inline_serializer(
                    name="GithubSocialAuthEnvelope2",
                    fields={
                        "data": inline_serializer(
                            name="GithubSocialAuthData",
                            fields={
                                "access_token": serializers.CharField(),
                                "refresh_token": serializers.CharField(),
                                "is_new_user": serializers.BooleanField(help_text="True if a new account was created during this sign-in."),
                            },
                        ),
                        "error": serializers.JSONField(allow_null=True, default=None),
                        "meta": _META,
                    },
                ),
            ),
            401: _R401,
            403: _R403,
            422: _R422,
        },
    )
    def post(self, request: Request) -> Response:
        """Verify the GitHub access token and return JWT tokens."""
        from apps.users.application.use_cases.github_social_auth import GithubSocialAuthUseCase
        from apps.users.infrastructure.github_verifier import GithubTokenVerifier

        token = request.data.get("access_token", "")
        if not token:
            return error_response("access_token is required.", status=400, request=request)

        result = GithubSocialAuthUseCase(
            DjangoUserRepository(),
            GithubTokenVerifier(),
            JWTTokenService(),
        ).execute(access_token=token)

        if result.refresh_token:
            _create_session(request, result.refresh_token)

        return success_response(
            {
                "access_token": result.access_token,
                "refresh_token": result.refresh_token,
                "is_new_user": result.is_new_user,
            },
            request=request,
        )
