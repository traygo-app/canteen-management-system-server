from decimal import Decimal
from unittest.mock import MagicMock, patch

from django.contrib.auth import get_user_model
from django.test import RequestFactory, TestCase
from rest_framework import status
from rest_framework.test import APIClient, APITestCase

from apps.wallets.models import Balance, Transaction
from apps.webhooks.handlers import StripeWebhookError, StripeWebhookHandler
from apps.webhooks.models import WebhookEvent, WebhookSource, WebhookStatus
from apps.webhooks.permissions import HasValidStripeSignature
from apps.webhooks.services import StripeWebhookError as ServiceError

User = get_user_model()


class WebhookEventModelTests(TestCase):
    def test_create_webhook_event(self):
        event = WebhookEvent.objects.create(
            event_id="evt_test123",
            event_type="checkout.session.completed",
            source=WebhookSource.STRIPE,
            payload={"id": "evt_test123", "type": "checkout.session.completed"},
            status=WebhookStatus.PENDING,
        )
        self.assertEqual(str(event), "stripe • checkout.session.completed • pending")

    def test_webhook_event_unique_id(self):
        WebhookEvent.objects.create(
            event_id="evt_unique",
            event_type="payment_intent.succeeded",
            payload={},
        )
        with self.assertRaises(Exception):  # noqa
            WebhookEvent.objects.create(
                event_id="evt_unique",
                event_type="payment_intent.failed",
                payload={},
            )


class WebhookHandlerTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            email="webhook.test@fcim.utm.md",
            password="TestPass123!",
        )
        self.balance, _ = Balance.objects.get_or_create(
            user=self.user,
            defaults={"current_balance": Decimal("50.00")},
        )

    def test_handler_no_event_raises(self):
        request = MagicMock()
        request.stripe_event = None
        with self.assertRaises(ValueError):
            StripeWebhookHandler(request)

    def test_handler_event_already_completed(self):
        event_data = {
            "id": "evt_completed",
            "type": "checkout.session.completed",
            "data": {"object": {"id": "cs_123"}},
        }
        WebhookEvent.objects.create(
            event_id="evt_completed",
            event_type="checkout.session.completed",
            payload=event_data,
            status=WebhookStatus.COMPLETED,
        )
        request = MagicMock()
        request.stripe_event = event_data
        handler = StripeWebhookHandler(request)
        result = handler.handle_event()
        self.assertEqual(result.status, WebhookStatus.COMPLETED)

    def test_handler_unhandled_event_type(self):
        event_data = {
            "id": "evt_unhandled",
            "type": "unknown.event.type",
        }
        request = MagicMock()
        request.stripe_event = event_data
        handler = StripeWebhookHandler(request)
        result = handler.handle_event()
        self.assertEqual(result.status, WebhookStatus.COMPLETED)


class WebhookPermissionTests(TestCase):
    def setUp(self):
        self.factory = RequestFactory()

    def test_missing_signature_header(self):
        permission = HasValidStripeSignature()
        request = self.factory.post("/webhooks/stripe/")
        request.META["HTTP_STRIPE_SIGNATURE"] = None
        self.assertFalse(permission.has_permission(request, None))

    @patch("apps.webhooks.permissions.verify_webhook_signature")
    def test_valid_signature(self, mock_verify):
        mock_verify.return_value = {"id": "evt_123", "type": "test.event"}
        permission = HasValidStripeSignature()
        request = self.factory.post("/webhooks/stripe/", data=b"test", content_type="application/json")
        request.META["HTTP_STRIPE_SIGNATURE"] = "valid_signature"
        self.assertTrue(permission.has_permission(request, None))
        self.assertEqual(request.stripe_event["id"], "evt_123")

    @patch("apps.webhooks.permissions.verify_webhook_signature")
    def test_invalid_signature(self, mock_verify):
        mock_verify.side_effect = ServiceError("Invalid signature")
        permission = HasValidStripeSignature()
        request = self.factory.post("/webhooks/stripe/", data=b"test", content_type="application/json")
        request.META["HTTP_STRIPE_SIGNATURE"] = "invalid_signature"
        self.assertFalse(permission.has_permission(request, None))


class WebhookViewTests(APITestCase):
    def setUp(self):
        self.client = APIClient()

    def test_webhook_no_signature(self):
        response = self.client.post("/webhooks/stripe/", data={}, format="json")
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    @patch("apps.webhooks.permissions.verify_webhook_signature")
    def test_webhook_valid_request(self, mock_verify):
        mock_verify.return_value = {
            "id": "evt_view_test",
            "type": "unknown.event",
        }
        response = self.client.post(
            "/webhooks/stripe/",
            data={"test": "data"},
            format="json",
            HTTP_STRIPE_SIGNATURE="test_signature",
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)


class CheckoutSessionHandlerTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            email="checkout.test@fcim.utm.md",
            password="TestPass123!",
        )
        self.balance, _ = Balance.objects.get_or_create(
            user=self.user,
            defaults={"current_balance": Decimal("100.00")},
        )
        self.balance.current_balance = Decimal("100.00")
        self.balance.save()
        self.tx = Transaction.objects.create(
            balance=self.balance,
            type="deposit",
            amount=Decimal("50.00"),
            remaining_balance=Decimal("100.00"),
            status="pending",
            stripe_checkout_session_id="cs_test_session",
        )

    def test_checkout_session_completed(self):
        event_data = {
            "id": "evt_checkout_complete",
            "type": "checkout.session.completed",
            "data": {
                "object": {
                    "id": "cs_test_session",
                    "payment_intent": "pi_123",
                }
            },
        }
        request = MagicMock()
        request.stripe_event = event_data
        handler = StripeWebhookHandler(request)
        handler.handle_event()

        self.tx.refresh_from_db()
        self.assertEqual(self.tx.status, "completed")
        self.assertEqual(self.tx.stripe_payment_intent_id, "pi_123")

        self.balance.refresh_from_db()
        self.assertEqual(self.balance.current_balance, Decimal("150.00"))

    def test_checkout_session_transaction_not_found(self):
        event_data = {
            "id": "evt_not_found",
            "type": "checkout.session.completed",
            "data": {
                "object": {
                    "id": "cs_nonexistent",
                    "payment_intent": "pi_456",
                }
            },
        }
        request = MagicMock()
        request.stripe_event = event_data
        handler = StripeWebhookHandler(request)

        with self.assertRaises(StripeWebhookError):
            handler.handle_event()
