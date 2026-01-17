from django.db import connection
from django.http import JsonResponse


def health_check(request):
    """
    Health check endpoint for load balancers and container orchestration.
    Returns 200 OK if the application is healthy.
    """
    try:
        # Check database connection
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")

        return JsonResponse({"status": "healthy", "database": "ok"}, status=200)
    except Exception as e:  # noqa
        return JsonResponse({"status": "unhealthy", "database": "error", "detail": str(e)}, status=503)
