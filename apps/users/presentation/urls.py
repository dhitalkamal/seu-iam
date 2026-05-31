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
    AdminAnnouncementView,
    AdminAuditLogView,
    AdminFeatureFlagDetailView,
    AdminFeatureFlagListView,
    AdminIAMAnalyticsView,
    AdminUserActivateView,
    AdminUserListView,
    AdminUserSuspendView,
    ChangePasswordView,
    ConfirmPasswordResetView,
    GithubSocialAuthView,
    GoogleSocialAuthView,
    HealthCheckView,
    InternalUserBatchView,
    InternalUserView,
    JWKSView,
    LoginView,
    LogoutView,
    MFAChallengeView,
    MFADisableView,
    MFAEmailEnableView,
    MFAEmailSetupView,
    MFAEnableView,
    MFASetupView,
    MFASMSEnableView,
    MFASMSSetupView,
    PlatformStatusView,
    ProfileView,
    RegisterView,
    RequestPasswordResetView,
    ResendVerificationOTPView,
    VerifyEmailView,
    VerifyPasswordResetOTPView,
)

urlpatterns: list[URLPattern] = [
    path("health/", HealthCheckView.as_view(), name="health"),
    path("platform/status/", PlatformStatusView.as_view(), name="platform-status"),
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
    path("auth/mfa/sms/setup/", MFASMSSetupView.as_view(), name="auth-mfa-sms-setup"),
    path("auth/mfa/sms/enable/", MFASMSEnableView.as_view(), name="auth-mfa-sms-enable"),
    path("auth/mfa/email/setup/", MFAEmailSetupView.as_view(), name="auth-mfa-email-setup"),
    path("auth/mfa/email/enable/", MFAEmailEnableView.as_view(), name="auth-mfa-email-enable"),
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
    path("auth/social/github/", GithubSocialAuthView.as_view(), name="auth-social-github"),
    path("auth/jwks/", JWKSView.as_view(), name="auth-jwks"),
    # sessions
    path("auth/sessions/", ListSessionsView.as_view(), name="auth-sessions"),
    path("auth/sessions/<uuid:jti>/", RevokeSessionView.as_view(), name="auth-session-revoke"),
    # profile
    path("profile/me/", ProfileView.as_view(), name="profile-me"),
    # user name resolution (authenticated, not internal)
    path("users/resolve/", InternalUserBatchView.as_view(), name="users-resolve"),
    # GDPR
    path("gdpr/export/", GDPRExportView.as_view(), name="gdpr-export"),
    path("gdpr/erasure/", GDPRErasureView.as_view(), name="gdpr-erasure"),
    # internal service-to-service
    path("internal/users/batch/", InternalUserBatchView.as_view(), name="internal-users-batch"),
    path("internal/users/<uuid:user_id>/", InternalUserView.as_view(), name="internal-user"),
    # superadmin user management
    path("admin/users/", AdminUserListView.as_view(), name="admin-users"),
    path("admin/users/<uuid:user_id>/suspend/", AdminUserSuspendView.as_view(), name="admin-user-suspend"),
    path("admin/users/<uuid:user_id>/activate/", AdminUserActivateView.as_view(), name="admin-user-activate"),
    path("admin/audit-log/", AdminAuditLogView.as_view(), name="admin-audit-log"),
    path("admin/analytics/", AdminIAMAnalyticsView.as_view(), name="admin-iam-analytics"),
    path("admin/feature-flags/", AdminFeatureFlagListView.as_view(), name="admin-feature-flags"),
    path("admin/feature-flags/<slug:key>/", AdminFeatureFlagDetailView.as_view(), name="admin-feature-flag-detail"),
    path("admin/announcements/", AdminAnnouncementView.as_view(), name="admin-announcements"),
]
