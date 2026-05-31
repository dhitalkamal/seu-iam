"""Session management, GDPR, and audit-aware token refresh views."""

from __future__ import annotations

import csv
import io
import uuid

from django.http import HttpResponse
from drf_spectacular.utils import OpenApiResponse, extend_schema, inline_serializer
from rest_framework import serializers
from rest_framework.permissions import IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.views import TokenRefreshView as BaseTokenRefreshView

from apps.common.api.responses import success_response
from apps.users.application.use_cases.gdpr_erasure import GDPRErasureUseCase
from apps.users.application.use_cases.gdpr_export import GDPRExportUseCase
from apps.users.domain.audit import AuditEventType
from apps.users.infrastructure.audit_repository import DjangoAuditLogRepository
from apps.users.infrastructure.audit_service import AuditService
from apps.users.infrastructure.repositories import DjangoUserRepository
from apps.users.infrastructure.session_service import SessionService
from apps.users.infrastructure.token_service import JWTTokenBlacklistService, extract_jti
from apps.users.presentation.serializers import GDPRErasureSerializer, SessionInfoSerializer

_META = inline_serializer(
    name="ComplianceMeta",
    fields={
        "request_id": serializers.CharField(),
        "timestamp": serializers.CharField(),
    },
)

_ERROR_ENVELOPE = inline_serializer(
    name="ComplianceErrorEnvelope",
    fields={
        "data": serializers.JSONField(allow_null=True, default=None),
        "error": inline_serializer(
            name="ComplianceErrorBody",
            fields={
                "code": serializers.CharField(),
                "message": serializers.CharField(),
                "details": serializers.JSONField(allow_null=True),
            },
        ),
        "meta": _META,
    },
)

_R401 = OpenApiResponse(description="Authentication credentials are missing or invalid.", response=_ERROR_ENVELOPE)
_R403 = OpenApiResponse(description="Password confirmation failed.", response=_ERROR_ENVELOPE)
_R404 = OpenApiResponse(description="Session not found.", response=_ERROR_ENVELOPE)
_R422 = OpenApiResponse(description="Validation error.", response=_ERROR_ENVELOPE)


def _audit(request: Request, user_id: uuid.UUID, event_type: str, metadata: dict | None = None) -> None:
    """Write an audit log entry, swallowing any persistence errors."""
    AuditService(DjangoAuditLogRepository()).log(request, user_id, event_type, metadata)


class AuditAwareTokenRefreshView(BaseTokenRefreshView):
    """Token refresh that updates the session last_seen timestamp."""

    @extend_schema(
        tags=["Auth"],
        summary="Refresh access token",
        description=("Exchange a valid refresh token for a new access token. Updates the session last_seen timestamp."),
        responses={
            200: OpenApiResponse(description="New access token issued."),
            401: _R401,
        },
    )
    def post(self, request: Request, *args: object, **kwargs: object) -> Response:
        """Delegate to simplejwt then touch the session's last_seen."""
        refresh_str = request.data.get("refresh")
        response = super().post(request, *args, **kwargs)
        if response.status_code == 200 and refresh_str:
            try:
                jti = extract_jti(refresh_str)
                SessionService().touch_session(jti)
            except Exception:
                pass
        return response


class ListSessionsView(APIView):
    """List all active sessions for the authenticated user."""

    permission_classes = [IsAuthenticated]

    @extend_schema(
        tags=["Sessions"],
        summary="List active sessions",
        description="Returns all active (non-revoked) sessions for the authenticated user.",
        responses={
            200: OpenApiResponse(
                description="Active sessions.",
                response=inline_serializer(
                    name="SessionListEnvelope",
                    fields={
                        "data": SessionInfoSerializer(many=True),
                        "error": serializers.JSONField(allow_null=True, default=None),
                        "meta": _META,
                    },
                ),
            ),
            401: _R401,
        },
    )
    def get(self, request: Request) -> Response:
        """Return all active sessions for the current user."""
        user_id = uuid.UUID(str(request.user.id))  # type: ignore[attr-defined]
        sessions = SessionService().list_active_sessions(user_id)
        return success_response(SessionInfoSerializer(sessions, many=True).data, request=request)


class RevokeSessionView(APIView):
    """Revoke a specific session by JTI."""

    permission_classes = [IsAuthenticated]

    @extend_schema(
        tags=["Sessions"],
        summary="Revoke a session",
        description=(
            "Revoke a specific session identified by its JTI. "
            "The corresponding refresh token is blacklisted and the session is deactivated."
        ),
        responses={
            200: OpenApiResponse(
                description="Session revoked.",
                response=inline_serializer(
                    name="RevokeSessionEnvelope",
                    fields={
                        "data": inline_serializer(
                            name="RevokeSessionData",
                            fields={"message": serializers.CharField()},
                        ),
                        "error": serializers.JSONField(allow_null=True, default=None),
                        "meta": _META,
                    },
                ),
            ),
            401: _R401,
            404: _R404,
        },
    )
    def delete(self, request: Request, jti: uuid.UUID) -> Response:
        """Blacklist the session's refresh token and mark it inactive."""
        from apps.users.domain.exceptions import UserNotFoundError

        user_id = uuid.UUID(str(request.user.id))  # type: ignore[attr-defined]
        revoked = SessionService().revoke_session(jti, user_id)

        if not revoked:
            raise UserNotFoundError("Session not found or already revoked.")

        try:
            from rest_framework_simplejwt.token_blacklist.models import (
                BlacklistedToken,
                OutstandingToken,
            )

            token = OutstandingToken.objects.filter(jti=str(jti), user_id=user_id).first()
            if token:
                BlacklistedToken.objects.get_or_create(token=token)
        except Exception:
            pass

        _audit(request, user_id, AuditEventType.SESSION_REVOKED, {"jti": str(jti)})
        return success_response({"message": "Session revoked."}, request=request)


class GDPRExportView(APIView):
    """Export all personal data for the authenticated user (GDPR Article 15)."""

    permission_classes = [IsAuthenticated]

    @extend_schema(
        tags=["GDPR"],
        summary="Export personal data",
        description=("Returns all personal data held for the authenticated user. Use ?format=csv for a CSV download, or omit for JSON."),
        responses={
            200: OpenApiResponse(description="Personal data export."),
            401: _R401,
        },
    )
    def get(self, request: Request) -> Response | HttpResponse:
        """Compile and return the user's personal data as JSON or CSV."""
        user_id = uuid.UUID(str(request.user.id))  # type: ignore[attr-defined]
        data = GDPRExportUseCase(DjangoUserRepository(), DjangoAuditLogRepository()).execute(user_id=user_id)
        _audit(request, user_id, AuditEventType.GDPR_EXPORT_REQUESTED)

        if request.query_params.get("format") == "csv":
            return _build_csv_response(data, user_id)

        return success_response(data, request=request)


def _build_csv_response(data: dict, user_id: uuid.UUID) -> HttpResponse:
    """Render the export dict as a CSV download."""
    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow(["section", "field", "value"])
    for field, value in data["profile"].items():
        writer.writerow(["profile", field, value])
    for entry in data["audit_logs"]:
        for field, value in entry.items():
            writer.writerow(["audit_log", field, value])

    response = HttpResponse(output.getvalue(), content_type="text/csv")
    response["Content-Disposition"] = f'attachment; filename="sansaar_data_{user_id}.csv"'
    return response


class GDPRErasureView(APIView):
    """Anonymize all PII for the authenticated user (GDPR Article 17)."""

    permission_classes = [IsAuthenticated]

    @extend_schema(
        tags=["GDPR"],
        summary="Request account erasure",
        description=(
            "Anonymizes all personal data for the authenticated user. "
            "The account row is retained with PII replaced by placeholder values. "
            "All sessions are invalidated. "
            "Password users must confirm with their current password. "
            "Social auth users (no password) may omit current_password."
        ),
        request=GDPRErasureSerializer,
        responses={
            200: OpenApiResponse(
                description="Account erased. All PII anonymized.",
                response=inline_serializer(
                    name="GDPRErasureEnvelope",
                    fields={
                        "data": inline_serializer(
                            name="GDPRErasureData",
                            fields={"message": serializers.CharField()},
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
        """Anonymize PII and revoke all sessions."""
        ser = GDPRErasureSerializer(data=request.data)
        ser.is_valid(raise_exception=True)

        user_id = uuid.UUID(str(request.user.id))  # type: ignore[attr-defined]
        GDPRErasureUseCase(DjangoUserRepository(), JWTTokenBlacklistService()).execute(
            user_id=user_id,
            current_password=ser.validated_data.get("current_password"),
        )

        _audit(request, user_id, AuditEventType.GDPR_ERASURE_COMPLETED)
        return success_response({"message": "Account erased. All personal data anonymized."}, request=request)
