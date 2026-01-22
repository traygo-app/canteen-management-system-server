from datetime import timedelta
from decimal import Decimal

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group, Permission
from django.contrib.contenttypes.models import ContentType
from django.test import TestCase
from django.utils import timezone
from rest_framework import status
from rest_framework.test import APIClient, APITestCase

from apps.common.constants import OrderStatus, TransactionStatus, TransactionType
from apps.menus.models import Category, Item, Menu
from apps.orders.models import Order
from apps.wallets.models import Balance, Transaction
from apps.wallets.serializers import BalanceSerializer, TransactionPublicSerializer
from apps.wallets.services import (
    WalletError,
    WalletResult,
    deposit,
    place_hold,
)

User = get_user_model()


class BalanceModelTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            email="balance.model@fcim.utm.md",
            password="TestPass123!",
        )

    def test_create_balance(self):
        balance = Balance.objects.create(
            user=self.user,
            current_balance=Decimal("100.00"),
            on_hold=Decimal("20.00"),
        )
        self.assertIn(str(self.user), str(balance))
        self.assertEqual(balance.current_balance, Decimal("100.00"))
        self.assertEqual(balance.on_hold, Decimal("20.00"))


class TransactionModelTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            email="tx.model@fcim.utm.md",
            password="TestPass123!",
        )
        self.balance = Balance.objects.create(
            user=self.user,
            current_balance=Decimal("50.00"),
        )

    def test_create_deposit_transaction(self):
        tx = Transaction.objects.create(
            balance=self.balance,
            type=TransactionType.DEPOSIT,
            amount=Decimal("25.00"),
            remaining_balance=Decimal("75.00"),
            status=TransactionStatus.COMPLETED,
        )
        self.assertIn("deposit", str(tx))

    def test_transaction_with_order(self):
        now = timezone.now()
        category = Category.objects.create(name="Tx Category")
        Item.objects.create(category=category, name="Tx Item", base_price=Decimal("10.00"))
        menu = Menu.objects.create(
            name="Tx Menu",
            start_time=now + timedelta(hours=1),
            end_time=now + timedelta(hours=4),
        )
        order = Order.objects.create(
            user=self.user,
            menu=menu,
            order_no="TXO123",
            total_amount=Decimal("10.00"),
            reservation_time=now + timedelta(hours=2),
        )
        tx = Transaction.objects.create(
            balance=self.balance,
            order=order,
            type=TransactionType.PAYMENT,
            amount=Decimal("10.00"),
            remaining_balance=Decimal("40.00"),
            status=TransactionStatus.COMPLETED,
        )
        self.assertIn("TXO123", str(tx))


class WalletServicesTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            email="wallet.service@fcim.utm.md",
            password="TestPass123!",
        )
        self.balance = Balance.objects.create(
            user=self.user,
            current_balance=Decimal("100.00"),
            on_hold=Decimal("0.00"),
        )
        self.now = timezone.now()
        self.category = Category.objects.create(name="Service Category")
        self.item = Item.objects.create(category=self.category, name="Service Item", base_price=Decimal("20.00"))
        self.menu = Menu.objects.create(
            name="Service Menu",
            start_time=self.now + timedelta(hours=1),
            end_time=self.now + timedelta(hours=4),
        )

    def test_deposit_success(self):
        result = deposit(self.user, Decimal("50.00"))
        self.assertIsInstance(result, WalletResult)
        self.assertEqual(result.transaction.type, TransactionType.DEPOSIT)
        self.assertEqual(result.transaction.amount, Decimal("50.00"))
        self.balance.refresh_from_db()
        self.assertEqual(self.balance.current_balance, Decimal("150.00"))

    def test_deposit_zero_amount_raises(self):
        with self.assertRaises(WalletError):
            deposit(self.user, Decimal("0.00"))

    def test_deposit_negative_amount_raises(self):
        with self.assertRaises(WalletError):
            deposit(self.user, Decimal("-10.00"))

    def test_place_hold_success(self):
        order = Order.objects.create(
            user=self.user,
            menu=self.menu,
            order_no="HOLD01",
            total_amount=Decimal("30.00"),
            status=OrderStatus.PENDING,
            reservation_time=self.now + timedelta(hours=2),
        )
        place_hold(self.user, order.id)
        self.balance.refresh_from_db()
        self.assertEqual(self.balance.on_hold, Decimal("30.00"))
        order.refresh_from_db()
        self.assertEqual(order.status, OrderStatus.CONFIRMED)

    def test_place_hold_insufficient_funds(self):
        order = Order.objects.create(
            user=self.user,
            menu=self.menu,
            order_no="HOLD02",
            total_amount=Decimal("500.00"),
            status=OrderStatus.PENDING,
            reservation_time=self.now + timedelta(hours=2),
        )
        with self.assertRaises(WalletError):
            place_hold(self.user, order.id)

    def test_place_hold_wrong_user(self):
        other_user = User.objects.create_user(
            email="other.hold@fcim.utm.md",
            password="TestPass123!",
        )
        order = Order.objects.create(
            user=other_user,
            menu=self.menu,
            order_no="HOLD03",
            total_amount=Decimal("10.00"),
            status=OrderStatus.PENDING,
            reservation_time=self.now + timedelta(hours=2),
        )
        with self.assertRaises(WalletError):
            place_hold(self.user, order.id)


class WalletSerializerTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            email="wallet.serial@fcim.utm.md",
            password="TestPass123!",
        )
        self.balance = Balance.objects.create(
            user=self.user,
            current_balance=Decimal("100.00"),
            on_hold=Decimal("25.00"),
        )

    def test_balance_serializer(self):
        serializer = BalanceSerializer(self.balance)
        data = serializer.data
        self.assertEqual(data["current_balance"], "100.00")
        self.assertEqual(data["on_hold"], "25.00")
        self.assertEqual(data["available_balance"], Decimal("75.00"))

    def test_transaction_signed_amount_payment(self):
        tx = Transaction.objects.create(
            balance=self.balance,
            type=TransactionType.PAYMENT,
            amount=Decimal("20.00"),
            remaining_balance=Decimal("80.00"),
            status=TransactionStatus.COMPLETED,
        )
        serializer = TransactionPublicSerializer(tx)
        self.assertEqual(serializer.data["signed_amount"], Decimal("-20.00"))

    def test_transaction_signed_amount_deposit(self):
        tx = Transaction.objects.create(
            balance=self.balance,
            type=TransactionType.DEPOSIT,
            amount=Decimal("50.00"),
            remaining_balance=Decimal("150.00"),
            status=TransactionStatus.COMPLETED,
        )
        serializer = TransactionPublicSerializer(tx)
        self.assertEqual(serializer.data["signed_amount"], Decimal("50.00"))


class WalletViewsTests(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            email="wallet.view@fcim.utm.md",
            password="TestPass123!",
            is_verified=True,
        )
        self.staff = User.objects.create_user(
            email="wallet.staff@fcim.utm.md",
            password="StaffPass123!",
            is_staff=True,
        )
        self.admin = User.objects.create_superuser(
            email="wallet.admin@fcim.utm.md",
            password="AdminPass123!",
        )
        self.balance = Balance.objects.create(
            user=self.user,
            current_balance=Decimal("200.00"),
            on_hold=Decimal("0.00"),
        )
        self.client = APIClient()

        Group.objects.get_or_create(name="customer_verified")
        verified_group = Group.objects.get(name="customer_verified")
        self.user.groups.add(verified_group)

        ct = ContentType.objects.get_for_model(Balance)
        view_perm, _ = Permission.objects.get_or_create(
            codename="view_own_balance",
            content_type=ct,
            defaults={"name": "Can view own balance"},
        )
        self.user.user_permissions.add(view_perm)

    def test_wallet_me_view_authenticated(self):
        self.client.force_authenticate(user=self.user)
        response = self.client.get("/wallets/me/")
        self.assertIn(response.status_code, [status.HTTP_200_OK, status.HTTP_403_FORBIDDEN])

    def test_wallet_me_view_unauthenticated(self):
        response = self.client.get("/wallets/me/")
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_wallet_view_by_admin(self):
        self.client.force_authenticate(user=self.admin)
        response = self.client.get(f"/wallets/{self.user.id}/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_wallet_deposit_by_admin(self):
        self.client.force_authenticate(user=self.admin)
        response = self.client.post(
            f"/wallets/{self.user.id}/deposit/",
            {"amount": "50.00"},
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.balance.refresh_from_db()
        self.assertEqual(self.balance.current_balance, Decimal("250.00"))

    def test_wallet_transactions_by_admin(self):
        Transaction.objects.create(
            balance=self.balance,
            type=TransactionType.DEPOSIT,
            amount=Decimal("100.00"),
            remaining_balance=Decimal("200.00"),
            status=TransactionStatus.COMPLETED,
        )
        self.client.force_authenticate(user=self.admin)
        response = self.client.get(f"/wallets/{self.user.id}/transactions/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
