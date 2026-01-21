import logging

from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.webhooks.handlers import StripeWebhookHandler
from apps.webhooks.permissions import HasValidStripeSignature

logger = logging.getLogger(__name__)


class StripeWebhookView(APIView):
    """
    Stripe webhook endpoint.
    Receives and processes webhook events from Stripe.

    Authentication is disabled - we use Stripe signature verification instead.
    The HasValidStripeSignature permission verifies the webhook signature.
    """

    permission_classes = (HasValidStripeSignature,)
    authentication_classes = ()
    throttle_classes = []

    def post(self, request, *args, **kwargs):
        """
        Handle incoming Stripe webhook POST requests.
        The request.stripe_event is set by the permission class after verification.
        """
        try:
            handler = StripeWebhookHandler(request)
            handler.handle_event()
            return Response({"status": "success"}, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error(f"Webhook processing error: {e}", exc_info=True)
            # Return 500 so Stripe will retry
            return Response(
                {"status": "error", "message": "Internal server error"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )
