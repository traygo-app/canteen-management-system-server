from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.test import TestCase
from rest_framework import status
from rest_framework.test import APIClient, APITestCase

from apps.common.constants import UserRole
from apps.users.serializers import UserSerializer
from apps.users.utils import extract_name_from_email

User = get_user_model()


class ExtractNameFromEmailTests(TestCase):
    def test_simple_name(self):
        first, last = extract_name_from_email("john.doe@fcim.utm.md")
        self.assertEqual(first, "John")
        self.assertEqual(last, "Doe")

    def test_hyphenated_name(self):
        first, last = extract_name_from_email("ana-maria.popescu@fcim.utm.md")
        self.assertEqual(first, "Ana-Maria")
        self.assertEqual(last, "Popescu")

    def test_numbers_stripped(self):
        first, last = extract_name_from_email("john123.doe456@fcim.utm.md")
        self.assertEqual(first, "John")
        self.assertEqual(last, "Doe")

    def test_missing_last_name(self):
        first, last = extract_name_from_email("johnonly@fcim.utm.md")
        self.assertEqual(first, "Johnonly")
        self.assertEqual(last, "")


class UserModelTests(TestCase):
    def test_create_user(self):
        user = User.objects.create_user(
            email="test.user@fcim.utm.md",
            password="TestPass123!",
        )
        self.assertEqual(user.email, "test.user@fcim.utm.md")
        self.assertFalse(user.is_staff)
        self.assertFalse(user.is_superuser)
        self.assertTrue(user.check_password("TestPass123!"))

    def test_create_user_no_email_raises(self):
        with self.assertRaises(ValueError):
            User.objects.create_user(email="", password="TestPass123!")

    def test_create_superuser(self):
        user = User.objects.create_superuser(
            email="super.admin@fcim.utm.md",
            password="SuperPass123!",
        )
        self.assertTrue(user.is_staff)
        self.assertTrue(user.is_superuser)
        self.assertEqual(user.role, UserRole.ADMIN)
        self.assertTrue(user.is_verified)

    def test_create_superuser_not_staff_raises(self):
        with self.assertRaises(ValueError):
            User.objects.create_superuser(
                email="fail@fcim.utm.md",
                password="Pass123!",
                is_staff=False,
            )

    def test_create_superuser_not_superuser_raises(self):
        with self.assertRaises(ValueError):
            User.objects.create_superuser(
                email="fail@fcim.utm.md",
                password="Pass123!",
                is_superuser=False,
            )

    def test_default_role(self):
        user = User.objects.create_user(
            email="default.role@fcim.utm.md",
            password="TestPass123!",
        )
        self.assertEqual(user.role, UserRole.CUSTOMER)

    def test_is_verified_customer_false_by_default(self):
        user = User.objects.create_user(
            email="unverified@fcim.utm.md",
            password="TestPass123!",
        )
        self.assertFalse(user.is_verified)

    def test_group_assignment_on_role_change(self):
        Group.objects.get_or_create(name="customer_verified")
        Group.objects.get_or_create(name="customer_unverified")

        user = User.objects.create_user(
            email="group.test@fcim.utm.md",
            password="TestPass123!",
            is_verified=True,
        )
        user.assign_group_by_role()


class UserSerializerTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            email="serializer.test@fcim.utm.md",
            password="TestPass123!",
            first_name="John",
            last_name="Doe",
        )

    def test_serialize_user(self):
        serializer = UserSerializer(self.user)
        data = serializer.data
        self.assertEqual(data["email"], "serializer.test@fcim.utm.md")
        self.assertEqual(data["first_name"], "John")
        self.assertEqual(data["last_name"], "Doe")
        self.assertIn("id", data)
        self.assertIn("created_at", data)

    def test_read_only_fields(self):
        serializer = UserSerializer(self.user)
        self.assertIn("id", serializer.Meta.read_only_fields)
        self.assertIn("created_at", serializer.Meta.read_only_fields)


class UserViewsTests(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            email="view.test@fcim.utm.md",
            password="TestPass123!",
            first_name="View",
            last_name="Test",
        )
        self.admin = User.objects.create_superuser(
            email="admin@fcim.utm.md",
            password="AdminPass123!",
        )
        self.client = APIClient()

    def test_me_view_authenticated(self):
        self.client.force_authenticate(user=self.user)
        response = self.client.get("/users/me")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["email"], "view.test@fcim.utm.md")

    def test_me_view_unauthenticated(self):
        response = self.client.get("/users/me")
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_user_detail_view(self):
        self.client.force_authenticate(user=self.admin)
        response = self.client.get(f"/users/{self.user.id}")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["email"], "view.test@fcim.utm.md")

    def test_user_by_account_no_not_implemented(self):
        self.client.force_authenticate(user=self.admin)
        response = self.client.get("/users/123456")
        self.assertEqual(response.status_code, status.HTTP_501_NOT_IMPLEMENTED)

    def test_me_password_not_implemented(self):
        self.client.force_authenticate(user=self.user)
        response = self.client.patch("/users/me/password")
        self.assertEqual(response.status_code, status.HTTP_501_NOT_IMPLEMENTED)

    def test_me_balance_not_implemented(self):
        self.client.force_authenticate(user=self.user)
        response = self.client.get("/users/me/balance")
        self.assertEqual(response.status_code, status.HTTP_501_NOT_IMPLEMENTED)

    def test_me_orders_not_implemented(self):
        self.client.force_authenticate(user=self.user)
        response = self.client.get("/users/me/orders")
        self.assertEqual(response.status_code, status.HTTP_501_NOT_IMPLEMENTED)

    def test_me_transactions_not_implemented(self):
        self.client.force_authenticate(user=self.user)
        response = self.client.get("/users/me/transactions")
        self.assertEqual(response.status_code, status.HTTP_501_NOT_IMPLEMENTED)
