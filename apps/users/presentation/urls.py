"""URL patterns for IAM endpoints under /api/v1/."""

from __future__ import annotations

from django.urls import URLPattern, path
from rest_framework_simplejwt.views import TokenRefreshView

from .views import (
    ChangePasswordView,
    ConfirmPasswordResetView,
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
)

urlpatterns: list[URLPattern] = [
    path("health/", HealthCheckView.as_view(), name="health"),
    path("auth/register/", RegisterView.as_view(), name="auth-register"),
    path("auth/login/", LoginView.as_view(), name="auth-login"),
    path("auth/logout/", LogoutView.as_view(), name="auth-logout"),
    path("auth/token/refresh/", TokenRefreshView.as_view(), name="auth-token-refresh"),
    path("auth/email/verify/", VerifyEmailView.as_view(), name="auth-email-verify"),
    path("auth/email/resend/", ResendVerificationOTPView.as_view(), name="auth-email-resend"),
    path("auth/password/reset/", RequestPasswordResetView.as_view(), name="auth-password-reset"),
    path(
        "auth/password/reset/confirm/",
        ConfirmPasswordResetView.as_view(),
        name="auth-password-reset-confirm",
    ),
    path("auth/password/change/", ChangePasswordView.as_view(), name="auth-password-change"),
    path("auth/mfa/setup/", MFASetupView.as_view(), name="auth-mfa-setup"),
    path("auth/mfa/enable/", MFAEnableView.as_view(), name="auth-mfa-enable"),
    path("auth/mfa/disable/", MFADisableView.as_view(), name="auth-mfa-disable"),
    path("auth/mfa/challenge/", MFAChallengeView.as_view(), name="auth-mfa-challenge"),
    path("profile/me/", ProfileView.as_view(), name="profile-me"),
    path("internal/users/<uuid:user_id>/", InternalUserView.as_view(), name="internal-user"),
]
