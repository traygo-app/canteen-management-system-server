from datetime import UTC, datetime

from django.conf import settings
from django.db import connection
from django.http import JsonResponse

from apps.common.redis_client import redis_client


def health_check(request):
    """
    Health check endpoint for load balancers and container orchestration.
    Returns 200 OK if the application is healthy.
    Checks: database, Redis, and Django app readiness.
    """
    checks = {
        "database": "ok",
        "redis": "ok",
        "app": "ok",
    }
    all_healthy = True

    # Check database connection
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
    except Exception:  # noqa
        checks["database"] = "error"
        all_healthy = False

    # Check Redis connection
    try:
        redis_client.ping()
    except Exception:  # noqa
        checks["redis"] = "error"
        all_healthy = False

    # Build response
    response_data = {
        "status": "healthy" if all_healthy else "unhealthy",
        "timestamp": datetime.now(UTC).isoformat(),
        "version": settings.SPECTACULAR_SETTINGS.get("VERSION", "unknown"),
        "checks": checks,
    }

    status_code = 200 if all_healthy else 503
    return JsonResponse(response_data, status=status_code)
