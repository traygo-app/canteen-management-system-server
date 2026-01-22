from unittest.mock import MagicMock

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.test import RequestFactory, TestCase

from apps.common.constants import ROLE_GROUP_NAMES, MenuType, OrderStatus, TransactionType, UserRole
from apps.common.drf_permissions import CustomerVerificationRequired, IsOwnerOrAdmin, RoleBasedPermission
from apps.common.throttling import SensitiveEndpointThrottle, UnverifiedUserThrottle, VerifiedUserThrottle
from apps.common.utils import (
    get_user_groups_set,
    is_admin_or_staff,
    is_authenticated,
    is_customer,
    is_verified_customer,
)

User = get_user_model()


class ConstantsTests(TestCase):
    def test_user_role_choices(self):
        self.assertEqual(UserRole.CUSTOMER, "customer")
        self.assertEqual(UserRole.STAFF, "staff")
        self.assertEqual(UserRole.ADMIN, "admin")

    def test_order_status_choices(self):
        self.assertIn(OrderStatus.PENDING, OrderStatus.active())
        self.assertIn(OrderStatus.CONFIRMED, OrderStatus.active())
        self.assertNotIn(OrderStatus.CANCELLED, OrderStatus.active())

    def test_transaction_types(self):
        self.assertEqual(TransactionType.DEPOSIT, "deposit")
        self.assertEqual(TransactionType.PAYMENT, "payment")
        self.assertEqual(TransactionType.REFUND, "refund")
        self.assertEqual(TransactionType.HOLD, "hold")

    def test_menu_types(self):
        self.assertEqual(MenuType.BREAKFAST, "breakfast")
        self.assertEqual(MenuType.LUNCH, "lunch")
        self.assertEqual(MenuType.DINNER, "dinner")

    def test_role_group_names(self):
        self.assertIn("admin", ROLE_GROUP_NAMES)
        self.assertIn("staff", ROLE_GROUP_NAMES)
        self.assertIn("customer_verified", ROLE_GROUP_NAMES)


class UtilsTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            email="utils.test@fcim.utm.md",
            password="TestPass123!",
        )
        Group.objects.get_or_create(name="customer_verified")
        Group.objects.get_or_create(name="staff")

    def test_is_authenticated_true(self):
        self.assertTrue(is_authenticated(self.user))

    def test_is_authenticated_anonymous(self):
        anonymous = MagicMock()
        anonymous.is_authenticated = False
        self.assertFalse(is_authenticated(anonymous))

    def test_is_admin_or_staff_superuser(self):
        self.user.is_superuser = True
        self.assertTrue(is_admin_or_staff(self.user))

    def test_is_admin_or_staff_staff(self):
        self.user.is_staff = True
        self.assertTrue(is_admin_or_staff(self.user))

    def test_is_admin_or_staff_in_group(self):
        staff_group = Group.objects.get(name="staff")
        self.user.groups.add(staff_group)
        self.user._group_names_cache = None
        self.assertTrue(is_admin_or_staff(self.user))

    def test_is_customer(self):
        verified_group = Group.objects.get(name="customer_verified")
        self.user.groups.add(verified_group)
        self.user._group_names_cache = None
        self.assertTrue(is_customer(self.user))

    def test_is_verified_customer_by_group(self):
        verified_group = Group.objects.get(name="customer_verified")
        self.user.groups.add(verified_group)
        self.user._group_names_cache = None
        self.assertTrue(is_verified_customer(self.user))

    def test_is_verified_customer_by_role(self):
        self.user.role = "customer"
        self.user.is_verified = True
        self.assertTrue(is_verified_customer(self.user))

    def test_get_user_groups_set(self):
        group = Group.objects.get(name="staff")
        self.user.groups.add(group)
        self.user._group_names_cache = None
        groups = get_user_groups_set(self.user)
        self.assertIn("staff", groups)


class PermissionsTests(TestCase):
    def setUp(self):
        self.factory = RequestFactory()
        self.user = User.objects.create_user(
            email="perm.test@fcim.utm.md",
            password="TestPass123!",
        )
        self.admin = User.objects.create_superuser(
            email="admin.perm@fcim.utm.md",
            password="AdminPass123!",
        )
        Group.objects.get_or_create(name="customer_verified")
        Group.objects.get_or_create(name="customer_unverified")

    def test_is_owner_or_admin_owner(self):
        permission = IsOwnerOrAdmin()
        request = self.factory.get("/")
        request.user = self.user

        mock_obj = MagicMock()
        mock_obj.user = self.user
        self.assertTrue(permission.has_object_permission(request, None, mock_obj))

    def test_is_owner_or_admin_not_owner(self):
        other_user = User.objects.create_user(
            email="other@fcim.utm.md",
            password="TestPass123!",
        )
        permission = IsOwnerOrAdmin()
        request = self.factory.get("/")
        request.user = self.user

        mock_obj = MagicMock()
        mock_obj.user = other_user
        mock_obj.owner = None
        self.assertFalse(permission.has_object_permission(request, None, mock_obj))

    def test_is_owner_or_admin_admin(self):
        permission = IsOwnerOrAdmin()
        request = self.factory.get("/")
        request.user = self.admin

        mock_obj = MagicMock()
        mock_obj.user = self.user
        self.assertTrue(permission.has_object_permission(request, None, mock_obj))

    def test_role_based_permission_no_perm(self):
        permission = RoleBasedPermission()
        request = self.factory.get("/")
        request.user = self.user

        view = MagicMock()
        view.required_permission = "menus.view_menu"
        self.assertFalse(permission.has_permission(request, view))

    def test_role_based_permission_missing_required(self):
        permission = RoleBasedPermission()
        request = self.factory.get("/")
        request.user = self.user

        view = MagicMock()
        view.required_permission = None
        self.assertFalse(permission.has_permission(request, view))

    def test_customer_verification_required_unverified(self):
        permission = CustomerVerificationRequired()
        request = self.factory.get("/")
        self.user.role = "customer"
        self.user.is_verified = False
        request.user = self.user

        self.assertFalse(permission.has_permission(request, None))

    def test_customer_verification_required_verified(self):
        permission = CustomerVerificationRequired()
        request = self.factory.get("/")
        self.user.role = "customer"
        self.user.is_verified = True
        verified_group = Group.objects.get(name="customer_verified")
        self.user.groups.add(verified_group)
        self.user._group_names_cache = None
        request.user = self.user

        self.assertTrue(permission.has_permission(request, None))

    def test_customer_verification_required_admin(self):
        permission = CustomerVerificationRequired()
        request = self.factory.get("/")
        request.user = self.admin

        self.assertTrue(permission.has_permission(request, None))


class ThrottlingTests(TestCase):
    def setUp(self):
        self.factory = RequestFactory()
        self.user = User.objects.create_user(
            email="throttle.test@fcim.utm.md",
            password="TestPass123!",
        )

    def test_sensitive_throttle_authenticated(self):
        throttle = SensitiveEndpointThrottle()
        request = self.factory.get("/")
        request.user = self.user
        key = throttle.get_cache_key(request, None)
        self.assertIn(str(self.user.pk), key)

    def test_sensitive_throttle_anonymous(self):
        throttle = SensitiveEndpointThrottle()
        request = self.factory.get("/")
        request.user = MagicMock()
        request.user.is_authenticated = False
        request.META["REMOTE_ADDR"] = "127.0.0.1"
        key = throttle.get_cache_key(request, None)
        self.assertIsNotNone(key)

    def test_verified_user_throttle_verified(self):
        throttle = VerifiedUserThrottle()
        request = self.factory.get("/")
        self.user.is_verified = True
        request.user = self.user
        key = throttle.get_cache_key(request, None)
        self.assertIsNotNone(key)

    def test_verified_user_throttle_unverified(self):
        throttle = VerifiedUserThrottle()
        request = self.factory.get("/")
        self.user.is_verified = False
        request.user = self.user
        key = throttle.get_cache_key(request, None)
        self.assertIsNone(key)

    def test_unverified_user_throttle_unverified(self):
        throttle = UnverifiedUserThrottle()
        request = self.factory.get("/")
        self.user.is_verified = False
        request.user = self.user
        key = throttle.get_cache_key(request, None)
        self.assertIsNotNone(key)

    def test_unverified_user_throttle_verified(self):
        throttle = UnverifiedUserThrottle()
        request = self.factory.get("/")
        self.user.is_verified = True
        request.user = self.user
        key = throttle.get_cache_key(request, None)
        self.assertIsNone(key)

    def test_unverified_throttle_anonymous(self):
        throttle = UnverifiedUserThrottle()
        request = self.factory.get("/")
        request.user = MagicMock()
        request.user.is_authenticated = False
        key = throttle.get_cache_key(request, None)
        self.assertIsNone(key)
