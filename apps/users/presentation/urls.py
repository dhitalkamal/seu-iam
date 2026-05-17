"""URL patterns for IAM endpoints under /api/v1/."""

from __future__ import annotations

from django.urls import URLPattern, path

from apps.users.presentation.backup_code_views import (
    BackupCodeStatusView,
    RegenerateBackupCodesView,
)
from apps.users.presentation.compliance_views import (
    AuditAwareTokenRefreshView,
    GDPRErasureView,
    GDPRExportView,
    ListSessionsView,
    RevokeSessionView,
)
from apps.users.presentation.views import (
    ChangePasswordView,
    ConfirmPasswordResetView,
    GoogleSocialAuthView,
    HealthCheckView,
    InternalUserView,
    LoginView,
    LogoutView,
    MFAChallengeView,
    MFADisableView,
    MFAEnableView,
    MFASetupView,
    ProfileView,
    RegisterView,
    RequestPasswordResetView,
    ResendVerificationOTPView,
    VerifyEmailView,
    VerifyPasswordResetOTPView,
)

urlpatterns: list[URLPattern] = [
    path("health/", HealthCheckView.as_view(), name="health"),
    # auth
    path("auth/register/", RegisterView.as_view(), name="auth-register"),
    path("auth/login/", LoginView.as_view(), name="auth-login"),
    path("auth/logout/", LogoutView.as_view(), name="auth-logout"),
    path("auth/token/refresh/", AuditAwareTokenRefreshView.as_view(), name="auth-token-refresh"),
    path("auth/email/verify/", VerifyEmailView.as_view(), name="auth-email-verify"),
    path("auth/email/resend/", ResendVerificationOTPView.as_view(), name="auth-email-resend"),
    path("auth/password/reset/", RequestPasswordResetView.as_view(), name="auth-password-reset"),
    path(
        "auth/password/reset/verify-otp/",
        VerifyPasswordResetOTPView.as_view(),
        name="auth-password-reset-verify-otp",
    ),
    path(
        "auth/password/reset/confirm/",
        ConfirmPasswordResetView.as_view(),
        name="auth-password-reset-confirm",
    ),
    path("auth/password/change/", ChangePasswordView.as_view(), name="auth-password-change"),
    # MFA
    path("auth/mfa/setup/", MFASetupView.as_view(), name="auth-mfa-setup"),
    path("auth/mfa/enable/", MFAEnableView.as_view(), name="auth-mfa-enable"),
    path("auth/mfa/disable/", MFADisableView.as_view(), name="auth-mfa-disable"),
    path("auth/mfa/challenge/", MFAChallengeView.as_view(), name="auth-mfa-challenge"),
    path(
        "auth/mfa/backup-codes/status/",
        BackupCodeStatusView.as_view(),
        name="auth-mfa-backup-codes-status",
    ),
    path(
        "auth/mfa/backup-codes/regenerate/",
        RegenerateBackupCodesView.as_view(),
        name="auth-mfa-backup-codes-regenerate",
    ),
    # social auth
    path("auth/social/google/", GoogleSocialAuthView.as_view(), name="auth-social-google"),
    # sessions
    path("auth/sessions/", ListSessionsView.as_view(), name="auth-sessions"),
    path("auth/sessions/<uuid:jti>/", RevokeSessionView.as_view(), name="auth-session-revoke"),
    # profile
    path("profile/me/", ProfileView.as_view(), name="profile-me"),
    # GDPR
    path("gdpr/export/", GDPRExportView.as_view(), name="gdpr-export"),
    path("gdpr/erasure/", GDPRErasureView.as_view(), name="gdpr-erasure"),
    # internal service-to-service
    path("internal/users/<uuid:user_id>/", InternalUserView.as_view(), name="internal-user"),
]
