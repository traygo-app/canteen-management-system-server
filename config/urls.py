from django.contrib import admin
from django.urls import include, path
from drf_spectacular.views import (
    SpectacularAPIView,
    SpectacularRedocView,
    SpectacularSwaggerView,
)

from apps.common.views import health_check

swagger_urls = [
    path("", SpectacularSwaggerView.as_view(url_name="schema"), name="swagger-ui"),
    path("schema/", SpectacularAPIView.as_view(), name="schema"),
    path("schema/redoc/", SpectacularRedocView.as_view(url_name="schema"), name="redoc"),
]

api_urls = [
    path("auth/", include("apps.authentication.urls", namespace="authentication")),
    path("users/", include("apps.users.urls", namespace="users")),
    path("wallets/", include("apps.wallets.urls", namespace="wallets")),
    path("webhooks/", include("apps.webhooks.urls", namespace="webhooks")),
    path("orders/", include("apps.orders.urls", namespace="orders")),
    path("", include("apps.menus.urls", namespace="menus")),
    path("", include(swagger_urls)),
]

urlpatterns = [
    path("health", health_check, name="health-check"),
    path("admin/", admin.site.urls),
    path("", include(api_urls)),
]
