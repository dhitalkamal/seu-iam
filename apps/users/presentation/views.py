"""DRF API views for IAM endpoints."""

from __future__ import annotations

from django.conf import settings
from drf_spectacular.utils import OpenApiResponse, extend_schema, inline_serializer
from rest_framework import serializers
from rest_framework.permissions import AllowAny
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.common.api.responses import created_response, error_response, success_response
from apps.common.health import check_database, check_rabbitmq, check_redis
from apps.users.application.use_cases.register import RegisterUseCase
from apps.users.infrastructure.repositories import DjangoUserRepository
from apps.users.presentation.serializers import RegisterRequestSerializer, UserResponseSerializer

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
    """Create a new unverified user account."""

    authentication_classes: list = []
    permission_classes = [AllowAny]

    @extend_schema(
        tags=["Auth"],
        summary="Register a new account",
        description=(
            "Creates an unverified user account. "
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
        """Validate the payload, hash the password, and persist the account."""
        ser = RegisterRequestSerializer(data=request.data)
        ser.is_valid(raise_exception=True)
        d = ser.validated_data

        entity = RegisterUseCase(DjangoUserRepository()).execute(
            email=d["email"],
            password=d["password"],
            first_name=d["first_name"],
            last_name=d["last_name"],
        )
        return created_response(UserResponseSerializer(entity).data, request=request)
