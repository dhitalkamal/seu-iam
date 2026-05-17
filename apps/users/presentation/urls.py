"""URL patterns for IAM endpoints under /api/v1/."""

from __future__ import annotations

from django.urls import URLPattern, path
from rest_framework_simplejwt.views import TokenRefreshView

from .views import (
    ConfirmPasswordResetView,
    HealthCheckView,
    LoginView,
    LogoutView,
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
    path("profile/me/", ProfileView.as_view(), name="profile-me"),
]
