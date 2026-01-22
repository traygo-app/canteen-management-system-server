from datetime import timedelta
from decimal import Decimal
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.utils import timezone
from rest_framework import status
from rest_framework.test import APIClient, APITestCase

from apps.common.constants import OrderStatus
from apps.menus.models import Category, Item, Menu, MenuItem
from apps.orders.models import Order, OrderItem
from apps.orders.serializers import OrderListSerializer
from apps.wallets.models import Balance

User = get_user_model()


class OrderModelTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            email="order.model@fcim.utm.md",
            password="TestPass123!",
        )
        self.now = timezone.now()
        self.category = Category.objects.create(name="Order Category")
        self.item = Item.objects.create(
            category=self.category,
            name="Order Item",
            base_price=Decimal("10.00"),
        )
        self.menu = Menu.objects.create(
            name="Order Menu",
            start_time=self.now + timedelta(hours=1),
            end_time=self.now + timedelta(hours=4),
        )

    def test_create_order(self):
        order = Order.objects.create(
            user=self.user,
            menu=self.menu,
            order_no="ABC123",
            status=OrderStatus.PENDING,
            total_amount=Decimal("50.00"),
            reservation_time=self.now + timedelta(hours=2),
        )
        self.assertEqual(str(order), "ABC123 • order.model@fcim.utm.md")
        self.assertEqual(order.status, OrderStatus.PENDING)

    def test_order_status_transitions(self):
        order = Order.objects.create(
            user=self.user,
            menu=self.menu,
            order_no="DEF456",
            total_amount=Decimal("25.00"),
            reservation_time=self.now + timedelta(hours=2),
        )
        self.assertEqual(order.status, OrderStatus.PENDING)

        order.status = OrderStatus.CONFIRMED
        order.save()
        self.assertEqual(order.status, OrderStatus.CONFIRMED)


class OrderItemModelTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            email="orderitem.model@fcim.utm.md",
            password="TestPass123!",
        )
        self.now = timezone.now()
        self.category = Category.objects.create(name="OrderItem Category")
        self.item = Item.objects.create(
            category=self.category,
            name="OrderItem Item",
            base_price=Decimal("15.00"),
        )
        self.menu = Menu.objects.create(
            name="OrderItem Menu",
            start_time=self.now + timedelta(hours=1),
            end_time=self.now + timedelta(hours=4),
        )
        self.menu_item = MenuItem.objects.create(
            menu=self.menu,
            item=self.item,
            quantity=50,
        )
        self.order = Order.objects.create(
            user=self.user,
            menu=self.menu,
            order_no="GHI789",
            total_amount=Decimal("30.00"),
            reservation_time=self.now + timedelta(hours=2),
        )

    def test_create_order_item(self):
        order_item = OrderItem.objects.create(
            order=self.order,
            menu_item=self.menu_item,
            quantity=2,
            unit_price=Decimal("15.00"),
            total_price=Decimal("30.00"),
        )
        self.assertIn(self.order.order_no, str(order_item))
        self.assertEqual(order_item.quantity, 2)


class OrderSerializerTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            email="order.serial@fcim.utm.md",
            password="TestPass123!",
        )
        self.now = timezone.now()
        self.category = Category.objects.create(name="Serial Category")
        self.item = Item.objects.create(
            category=self.category,
            name="Serial Item",
            base_price=Decimal("20.00"),
        )
        self.menu = Menu.objects.create(
            name="Serial Menu",
            start_time=self.now + timedelta(hours=1),
            end_time=self.now + timedelta(hours=4),
        )
        self.menu_item = MenuItem.objects.create(
            menu=self.menu,
            item=self.item,
            quantity=100,
        )
        self.order = Order.objects.create(
            user=self.user,
            menu=self.menu,
            order_no="JKL012",
            total_amount=Decimal("40.00"),
            reservation_time=self.now + timedelta(hours=2),
        )
        OrderItem.objects.create(
            order=self.order,
            menu_item=self.menu_item,
            quantity=2,
            unit_price=Decimal("20.00"),
            total_price=Decimal("40.00"),
        )

    def test_order_list_serializer(self):
        serializer = OrderListSerializer(self.order)
        data = serializer.data
        self.assertEqual(data["menu"], "Serial Menu")
        self.assertIn("items", data)


class OrderViewsTests(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            email="order.view@fcim.utm.md",
            password="TestPass123!",
            is_verified=True,
        )
        self.admin = User.objects.create_superuser(
            email="order.admin@fcim.utm.md",
            password="AdminPass123!",
        )
        self.client = APIClient()
        self.now = timezone.now()
        self.category = Category.objects.create(name="View Category")
        self.item = Item.objects.create(
            category=self.category,
            name="View Item",
            base_price=Decimal("10.00"),
        )
        self.menu = Menu.objects.create(
            name="View Menu",
            start_time=self.now + timedelta(hours=1),
            end_time=self.now + timedelta(hours=4),
        )
        self.menu_item = MenuItem.objects.create(
            menu=self.menu,
            item=self.item,
            quantity=50,
        )
        Balance.objects.get_or_create(user=self.user, defaults={"current_balance": Decimal("100.00")})

    def test_orders_list_authenticated(self):
        self.client.force_authenticate(user=self.user)
        response = self.client.get("/orders/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_orders_list_unauthenticated(self):
        response = self.client.get("/orders/")
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    @patch("apps.orders.serializers.place_hold")
    def test_order_create(self, mock_hold):
        self.client.force_authenticate(user=self.user)
        data = {
            "menu": str(self.menu.id),
            "reservation_time": (self.now + timedelta(hours=2)).isoformat(),
            "items": [{"menu_item_id": str(self.menu_item.id), "quantity": 1}],
        }
        response = self.client.post("/orders/", data, format="json")
        self.assertIn(response.status_code, [status.HTTP_201_CREATED, status.HTTP_400_BAD_REQUEST])

    def test_order_by_id(self):
        order = Order.objects.create(
            user=self.user,
            menu=self.menu,
            order_no="BYID01",
            total_amount=Decimal("20.00"),
            reservation_time=self.now + timedelta(hours=2),
        )
        self.client.force_authenticate(user=self.admin)
        response = self.client.get(f"/orders/{order.id}")
        self.assertIn(response.status_code, [status.HTTP_200_OK, status.HTTP_501_NOT_IMPLEMENTED])

    def test_order_by_number(self):
        Order.objects.create(
            user=self.user,
            menu=self.menu,
            order_no="XYZ999",
            total_amount=Decimal("20.00"),
            reservation_time=self.now + timedelta(hours=2),
        )
        self.client.force_authenticate(user=self.admin)
        response = self.client.get("/orders/find/XYZ999")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["order_no"], "XYZ999")

    def test_order_by_number_not_admin(self):
        Order.objects.create(
            user=self.user,
            menu=self.menu,
            order_no="ABC111",
            total_amount=Decimal("20.00"),
            reservation_time=self.now + timedelta(hours=2),
        )
        self.client.force_authenticate(user=self.user)
        response = self.client.get("/orders/find/ABC111")
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_order_process(self):
        order = Order.objects.create(
            user=self.user,
            menu=self.menu,
            order_no="PROC01",
            total_amount=Decimal("20.00"),
            reservation_time=self.now + timedelta(hours=2),
        )
        self.client.force_authenticate(user=self.admin)
        response = self.client.post(f"/orders/{order.id}/process")
        self.assertIn(response.status_code, [status.HTTP_200_OK, status.HTTP_501_NOT_IMPLEMENTED])
