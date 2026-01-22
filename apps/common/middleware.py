import logging

import redis
from django.conf import settings
from django.db import OperationalError
from django.http import JsonResponse

logger = logging.getLogger(__name__)


class MaintenanceModeMiddleware:
    """
    Middleware to handle maintenance mode and service failures.

    Features:
    - Manual maintenance mode via MAINTENANCE_MODE environment variable
    - Automatic maintenance mode on database/Redis connection failures
    - Excludes /health endpoint to allow monitoring
    - Returns clean 503 responses with minimal details
    - Logs full error details for debugging
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Skip maintenance mode for health endpoint
        if request.path == "/health":
            return self.get_response(request)

        # Check manual maintenance mode
        if getattr(settings, "MAINTENANCE_MODE", False):
            logger.warning(
                f"Maintenance mode: Request to {request.path} blocked - manual maintenance mode enabled",
                extra={"path": request.path, "method": request.method},
            )
            return self._maintenance_response()

        response = self.get_response(request)
        return response

    def process_exception(self, request, exception):
        """
        Handle exceptions that occur during view processing.
        This catches exceptions that DRF and other views don't handle internally.
        """
        # Skip maintenance mode for health endpoint
        if request.path == "/health":
            return None

        # Check if it's a database or Redis connection error
        if isinstance(exception, OperationalError | redis.ConnectionError | redis.exceptions.ConnectionError):
            logger.error(
                f"Service failure: {type(exception).__name__} on {request.method} {request.path}",
                exc_info=True,
                extra={
                    "path": request.path,
                    "method": request.method,
                    "exception_type": type(exception).__name__,
                    "exception_message": str(exception),
                },
            )
            return self._maintenance_response()

        # Return None to let Django handle other exceptions normally
        return None

    def _maintenance_response(self):
        """Return a clean 503 response with minimal information."""
        return JsonResponse({"status": "unavailable", "message": "Service temporarily unavailable"}, status=503)
