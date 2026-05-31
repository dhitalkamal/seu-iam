"""Views for MFA backup code management."""

from __future__ import annotations

import uuid

from drf_spectacular.utils import OpenApiResponse, extend_schema, inline_serializer
from rest_framework import serializers
from rest_framework.permissions import IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.common.api.responses import success_response
from apps.users.application.use_cases.regenerate_backup_codes import RegenerateBackupCodesUseCase
from apps.users.domain.audit import AuditEventType
from apps.users.infrastructure.audit_repository import DjangoAuditLogRepository
from apps.users.infrastructure.audit_service import AuditService
from apps.users.infrastructure.backup_code_service import BackupCodeService
from apps.users.infrastructure.repositories import DjangoUserRepository
from apps.users.infrastructure.totp_service import PyOTPService
from apps.users.presentation.serializers import (
    BackupCodeStatusSerializer,
    MFACodeSerializer,
    RegenerateBackupCodesResponseSerializer,
)

_META = inline_serializer(
    name="BackupCodeMeta",
    fields={
        "request_id": serializers.CharField(),
        "timestamp": serializers.CharField(),
    },
)

_ERROR = inline_serializer(
    name="BackupCodeError",
    fields={
        "data": serializers.JSONField(allow_null=True, default=None),
        "error": inline_serializer(
            name="BackupCodeErrorBody",
            fields={
                "code": serializers.CharField(),
                "message": serializers.CharField(),
                "details": serializers.JSONField(allow_null=True),
            },
        ),
        "meta": _META,
    },
)

_R400 = OpenApiResponse(description="Invalid TOTP code or no backup codes remaining.", response=_ERROR)
_R401 = OpenApiResponse(description="Authentication credentials are missing or invalid.", response=_ERROR)
_R409 = OpenApiResponse(description="MFA is not enabled on this account.", response=_ERROR)


def _audit(request: Request, user_id: uuid.UUID, event_type: str, metadata: dict | None = None) -> None:
    """Write an audit log entry, swallowing persistence errors."""
    AuditService(DjangoAuditLogRepository()).log(request, user_id, event_type, metadata)


class BackupCodeStatusView(APIView):
    """Return how many unused backup codes remain for the authenticated user."""

    permission_classes = [IsAuthenticated]

    @extend_schema(
        tags=["MFA"],
        summary="Backup code status",
        description=("Returns the number of unused backup codes remaining. The codes themselves are never shown after initial generation."),
        responses={
            200: OpenApiResponse(
                description="Backup code count.",
                response=inline_serializer(
                    name="BackupCodeStatusEnvelope",
                    fields={
                        "data": BackupCodeStatusSerializer(),
                        "error": serializers.JSONField(allow_null=True, default=None),
                        "meta": _META,
                    },
                ),
            ),
            401: _R401,
        },
    )
    def get(self, request: Request) -> Response:
        """Return the count of remaining unused backup codes."""
        user_id = uuid.UUID(str(request.user.id))  # type: ignore[attr-defined]
        remaining = BackupCodeService().remaining_count(user_id)
        return success_response({"remaining": remaining}, request=request)


class RegenerateBackupCodesView(APIView):
    """Invalidate all existing backup codes and issue a fresh set."""

    permission_classes = [IsAuthenticated]

    @extend_schema(
        tags=["MFA"],
        summary="Regenerate backup codes",
        description=(
            "Requires a valid TOTP code to confirm ownership. "
            "All existing backup codes are immediately invalidated. "
            "The new plaintext codes are shown exactly once — store them securely."
        ),
        request=MFACodeSerializer,
        responses={
            200: OpenApiResponse(
                description="New backup codes issued. Previous codes are now invalid.",
                response=inline_serializer(
                    name="RegenerateBackupCodesEnvelope",
                    fields={
                        "data": RegenerateBackupCodesResponseSerializer(),
                        "error": serializers.JSONField(allow_null=True, default=None),
                        "meta": _META,
                    },
                ),
            ),
            400: _R400,
            401: _R401,
            409: _R409,
            422: OpenApiResponse(description="Validation error.", response=_ERROR),
        },
    )
    def post(self, request: Request) -> Response:
        """Verify the TOTP code and generate a fresh set of backup codes."""
        ser = MFACodeSerializer(data=request.data)
        ser.is_valid(raise_exception=True)

        user_id = uuid.UUID(str(request.user.id))  # type: ignore[attr-defined]
        codes = RegenerateBackupCodesUseCase(DjangoUserRepository(), PyOTPService(), BackupCodeService()).execute(
            user_id=user_id, code=ser.validated_data["code"]
        )

        _audit(request, user_id, AuditEventType.MFA_ENABLED, {"action": "backup_codes_regenerated"})
        return success_response({"backup_codes": codes}, request=request)
