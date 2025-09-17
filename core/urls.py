from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static

from sso.views import google_auth_callback
from core.views import Health, SecureEcho  # add

urlpatterns = [
    path("admin/", admin.site.urls),
    path("api/auth/", include("sso.urls")),
    path("auth/google/callback/", google_auth_callback, name="google_oauth_callback"),
    path("health/", Health.as_view()),          # add
    path("secure/", SecureEcho.as_view()),      # add
    path("", include("dashboard.urls")),
]

if settings.DEBUG:
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)