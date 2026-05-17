"""URL patterns for IAM endpoints under /api/v1/."""

from __future__ import annotations

from django.urls import URLPattern, path
from rest_framework_simplejwt.views import TokenRefreshView

from .views import HealthCheckView, LoginView, LogoutView, ProfileView, RegisterView

urlpatterns: list[URLPattern] = [
    path("health/", HealthCheckView.as_view(), name="health"),
    path("auth/register/", RegisterView.as_view(), name="auth-register"),
    path("auth/login/", LoginView.as_view(), name="auth-login"),
    path("auth/logout/", LogoutView.as_view(), name="auth-logout"),
    path("auth/token/refresh/", TokenRefreshView.as_view(), name="auth-token-refresh"),
    path("profile/me/", ProfileView.as_view(), name="profile-me"),
]
