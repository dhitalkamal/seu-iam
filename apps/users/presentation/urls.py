"""URL patterns for IAM endpoints under /api/v1/."""

from __future__ import annotations

from django.urls import URLPattern, path

from .views import HealthCheckView, RegisterView

urlpatterns: list[URLPattern] = [
    path("health/", HealthCheckView.as_view(), name="health"),
    path("auth/register/", RegisterView.as_view(), name="auth-register"),
]
