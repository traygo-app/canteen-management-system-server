from datetime import timedelta
from decimal import Decimal

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.utils import timezone
from rest_framework import status
from rest_framework.test import APIClient, APITestCase

from apps.common.constants import MenuType
from apps.menus.models import Category, Item, Menu, MenuItem
from apps.menus.serializers import MenuItemSerializer, MenuSerializer

User = get_user_model()


class CategoryModelTests(TestCase):
    def test_create_category(self):
        category = Category.objects.create(
            name="Main Courses",
            display_order=1,
        )
        self.assertEqual(str(category), "Main Courses")
        self.assertEqual(category.display_order, 1)

    def test_category_unique_name(self):
        Category.objects.create(name="Unique Category")
        with self.assertRaises(Exception):  # noqa
            Category.objects.create(name="Unique Category")


class ItemModelTests(TestCase):
    def setUp(self):
        self.category = Category.objects.create(name="Test Category")

    def test_create_item(self):
        item = Item.objects.create(
            category=self.category,
            name="Test Item",
            description="A test item",
            base_price=Decimal("10.50"),
        )
        self.assertEqual(str(item), "Test Item")
        self.assertEqual(item.base_price, Decimal("10.50"))

    def test_item_unique_per_category(self):
        Item.objects.create(
            category=self.category,
            name="Duplicate Item",
            base_price=Decimal("5.00"),
        )
        with self.assertRaises(Exception):  # noqa
            Item.objects.create(
                category=self.category,
                name="Duplicate Item",
                base_price=Decimal("6.00"),
            )


class MenuModelTests(TestCase):
    def setUp(self):
        self.now = timezone.now()
        self.category = Category.objects.create(name="Lunch Category")
        self.item = Item.objects.create(
            category=self.category,
            name="Lunch Item",
            base_price=Decimal("15.00"),
        )

    def test_create_menu(self):
        menu = Menu.objects.create(
            name="Today's Lunch",
            start_time=self.now + timedelta(hours=1),
            end_time=self.now + timedelta(hours=4),
            type=MenuType.LUNCH,
        )
        self.assertIn("Today's Lunch", str(menu))
        self.assertEqual(menu.type, MenuType.LUNCH)

    def test_menu_with_items(self):
        menu = Menu.objects.create(
            name="Breakfast Menu",
            start_time=self.now + timedelta(hours=1),
            end_time=self.now + timedelta(hours=3),
            type=MenuType.BREAKFAST,
        )
        MenuItem.objects.create(
            menu=menu,
            item=self.item,
            quantity=50,
            display_order=1,
        )
        self.assertEqual(menu.menu_items.count(), 1)


class MenuItemModelTests(TestCase):
    def setUp(self):
        self.now = timezone.now()
        self.category = Category.objects.create(name="MenuItem Category")
        self.item = Item.objects.create(
            category=self.category,
            name="MenuItem Item",
            base_price=Decimal("20.00"),
        )
        self.menu = Menu.objects.create(
            name="Test Menu",
            start_time=self.now + timedelta(hours=1),
            end_time=self.now + timedelta(hours=4),
        )

    def test_create_menu_item(self):
        menu_item = MenuItem.objects.create(
            menu=self.menu,
            item=self.item,
            quantity=100,
            display_order=1,
        )
        self.assertEqual(menu_item.quantity, 100)
        self.assertIn(self.item.name, str(menu_item))

    def test_menu_item_with_override_price(self):
        menu_item = MenuItem.objects.create(
            menu=self.menu,
            item=self.item,
            quantity=50,
            override_price=Decimal("18.00"),
        )
        self.assertEqual(menu_item.override_price, Decimal("18.00"))

    def test_menu_item_permanent(self):
        menu_item = MenuItem.objects.create(
            menu=self.menu,
            item=self.item,
            quantity=30,
            is_permanent=True,
        )
        self.assertTrue(menu_item.is_permanent)


class MenuSerializerTests(TestCase):
    def setUp(self):
        self.now = timezone.now()
        self.category = Category.objects.create(name="Serializer Category")
        self.item = Item.objects.create(
            category=self.category,
            name="Serializer Item",
            base_price=Decimal("12.00"),
        )
        self.menu = Menu.objects.create(
            name="Serializer Menu",
            start_time=self.now + timedelta(hours=1),
            end_time=self.now + timedelta(hours=4),
            type=MenuType.DINNER,
        )
        self.menu_item = MenuItem.objects.create(
            menu=self.menu,
            item=self.item,
            quantity=25,
        )

    def test_menu_serializer(self):
        serializer = MenuSerializer(self.menu)
        data = serializer.data
        self.assertEqual(data["name"], "Serializer Menu")
        self.assertEqual(data["type"], MenuType.DINNER)
        self.assertIn("menu_items", data)

    def test_menu_item_serializer(self):
        serializer = MenuItemSerializer(self.menu_item)
        data = serializer.data
        self.assertEqual(data["item_name"], "Serializer Item")
        self.assertEqual(data["quantity"], 25)
        self.assertEqual(data["category"], "Serializer Category")


class MenuViewsTests(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            email="menu.view@fcim.utm.md",
            password="TestPass123!",
        )
        self.admin = User.objects.create_superuser(
            email="menu.admin@fcim.utm.md",
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

    def test_menus_list_authenticated(self):
        Menu.objects.create(
            name="Future Menu",
            start_time=self.now + timedelta(days=1),
            end_time=self.now + timedelta(days=1, hours=3),
        )
        self.client.force_authenticate(user=self.user)
        response = self.client.get("/menus")
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_menus_list_unauthenticated(self):
        response = self.client.get("/menus")
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_items_view_not_implemented(self):
        self.client.force_authenticate(user=self.admin)
        response = self.client.get("/items")
        self.assertEqual(response.status_code, status.HTTP_501_NOT_IMPLEMENTED)

    def test_categories_view_not_implemented(self):
        self.client.force_authenticate(user=self.admin)
        response = self.client.get("/categories")
        self.assertEqual(response.status_code, status.HTTP_501_NOT_IMPLEMENTED)
