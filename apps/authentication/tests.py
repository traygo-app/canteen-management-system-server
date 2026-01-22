from unittest.mock import patch
from uuid import uuid4

from cryptography.fernet import Fernet
from django.contrib.auth import get_user_model
from django.test import RequestFactory, TestCase, override_settings
from rest_framework import status
from rest_framework.test import APIClient, APITestCase

from apps.authentication.crypto import decrypt_text, encrypt_text
from apps.authentication.models import MFABackupCode
from apps.authentication.serializers import (
    PasswordChangeSerializer,
    PasswordResetConfirmSerializer,
    RegisterSerializer,
)
from apps.authentication.session_service import SessionService
from apps.authentication.utils import (
    generate_password_reset_token,
    generate_verification_token,
    get_custom_token,
    verify_email_token,
    verify_password_reset_token,
)

User = get_user_model()


TEST_FERNET_KEY = Fernet.generate_key().decode()


@override_settings(MFA_FERNET_KEY=TEST_FERNET_KEY)
class CryptoTests(TestCase):
    def test_encrypt_decrypt_roundtrip(self):
        original = "test_secret_value_123"
        encrypted = encrypt_text(original)
        self.assertNotEqual(encrypted, original)
        decrypted = decrypt_text(encrypted)
        self.assertEqual(decrypted, original)

    def test_decrypt_invalid_token_raises(self):
        with self.assertRaises(ValueError):
            decrypt_text("invalid_token_data")


class TokenUtilsTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            email="token.test@fcim.utm.md",
            password="TestPass123!",
        )

    def test_generate_and_verify_email_token(self):
        token = generate_verification_token(self.user)
        self.assertIsNotNone(token)
        user_id = verify_email_token(token)
        self.assertEqual(str(self.user.id), user_id)

    def test_verify_email_token_expired(self):
        token = generate_verification_token(self.user)
        result = verify_email_token(token, max_age=-1)
        self.assertIsNone(result)

    def test_verify_email_token_invalid(self):
        result = verify_email_token("invalid.token")
        self.assertIsNone(result)

    def test_generate_and_verify_password_reset_token(self):
        token = generate_password_reset_token(self.user)
        self.assertIsNotNone(token)
        user_id = verify_password_reset_token(token)
        self.assertEqual(str(self.user.id), user_id)

    def test_password_reset_token_expired(self):
        token = generate_password_reset_token(self.user)
        result = verify_password_reset_token(token, max_age=-1)
        self.assertIsNone(result)

    def test_get_custom_token(self):
        refresh = get_custom_token(self.user)
        self.assertIn("role", refresh.payload)
        self.assertIn("verified", refresh.payload)
        self.assertEqual(refresh["role"], self.user.role)
        self.assertEqual(refresh["verified"], self.user.is_verified)


class SessionServiceTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            email="session.test@fcim.utm.md",
            password="TestPass123!",
        )
        self.factory = RequestFactory()

    @patch("apps.authentication.session_service.redis_client")
    def test_create_session(self, mock_redis):
        request = self.factory.post("/auth/login/")
        request.META["REMOTE_ADDR"] = "127.0.0.1"
        request.META["HTTP_USER_AGENT"] = "TestAgent"
        jti = str(uuid4())

        SessionService.create_session(self.user.id, jti, request)

        mock_redis.setex.assert_called_once()
        mock_redis.sadd.assert_called_once()

    @patch("apps.authentication.session_service.redis_client")
    def test_validate_session_exists(self, mock_redis):
        mock_redis.exists.return_value = True
        self.assertTrue(SessionService.validate_session("test_jti"))

    @patch("apps.authentication.session_service.redis_client")
    def test_validate_session_missing(self, mock_redis):
        mock_redis.exists.return_value = False
        self.assertFalse(SessionService.validate_session("test_jti"))

    @patch("apps.authentication.session_service.redis_client")
    def test_revoke_session(self, mock_redis):
        mock_redis.get.return_value = '{"user_id": "123"}'
        SessionService.revoke_session("test_jti")
        mock_redis.delete.assert_called()

    @patch("apps.authentication.session_service.redis_client")
    def test_rotate_session(self, mock_redis):
        mock_redis.get.return_value = '{"user_id": "123", "last_used_at": "2024-01-01"}'
        SessionService.rotate_session("old_jti", "new_jti")
        mock_redis.setex.assert_called_once()
        mock_redis.delete.assert_called()


class MFABackupCodeModelTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            email="mfa.test@fcim.utm.md",
            password="TestPass123!",
        )

    def test_backup_code_creation(self):
        code = MFABackupCode.objects.create(
            user=self.user,
            code_hash="test_hash",
        )
        self.assertIsNone(code.used_at)
        self.assertIn("MFABackupCode", str(code))


class RegisterSerializerTests(TestCase):
    def test_valid_registration(self):
        data = {
            "email": "new.user@fcim.utm.md",
            "password": "SecurePass123!",
            "password2": "SecurePass123!",
        }
        serializer = RegisterSerializer(data=data)
        self.assertTrue(serializer.is_valid(), serializer.errors)

    def test_invalid_email_domain(self):
        data = {
            "email": "test@gmail.com",
            "password": "SecurePass123!",
            "password2": "SecurePass123!",
        }
        serializer = RegisterSerializer(data=data)
        self.assertFalse(serializer.is_valid())
        self.assertIn("email", serializer.errors)

    def test_password_mismatch(self):
        data = {
            "email": "test@fcim.utm.md",
            "password": "SecurePass123!",
            "password2": "DifferentPass123!",
        }
        serializer = RegisterSerializer(data=data)
        self.assertFalse(serializer.is_valid())


class PasswordSerializerTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            email="pass.test@fcim.utm.md",
            password="OldPass123!",
        )
        self.factory = RequestFactory()

    def test_password_change_valid(self):
        request = self.factory.post("/")
        request.user = self.user
        data = {
            "old_password": "OldPass123!",
            "new_password": "NewSecure456!",
            "confirm_new_password": "NewSecure456!",
        }
        serializer = PasswordChangeSerializer(data=data, context={"request": request})
        self.assertTrue(serializer.is_valid(), serializer.errors)

    def test_password_change_wrong_old(self):
        request = self.factory.post("/")
        request.user = self.user
        data = {
            "old_password": "WrongPass123!",
            "new_password": "NewSecure456!",
            "confirm_new_password": "NewSecure456!",
        }
        serializer = PasswordChangeSerializer(data=data, context={"request": request})
        self.assertFalse(serializer.is_valid())

    def test_password_change_mismatch(self):
        request = self.factory.post("/")
        request.user = self.user
        data = {
            "old_password": "OldPass123!",
            "new_password": "NewSecure456!",
            "confirm_new_password": "Different456!",
        }
        serializer = PasswordChangeSerializer(data=data, context={"request": request})
        self.assertFalse(serializer.is_valid())

    def test_password_reset_confirm_mismatch(self):
        data = {
            "token": "sometoken",
            "new_password": "NewPass123!",
            "confirm_new_password": "Different123!",
        }
        serializer = PasswordResetConfirmSerializer(data=data)
        self.assertFalse(serializer.is_valid())


class AuthViewsTests(APITestCase):
    def setUp(self):
        self.client = APIClient()

    @patch("apps.common.throttling.SensitiveEndpointThrottle.allow_request", return_value=True)
    @patch("apps.authentication.views.send_verification_email")
    @patch("apps.authentication.session_service.redis_client")
    def test_register_success(self, mock_redis, mock_email, mock_throttle):
        data = {
            "email": "register.test@fcim.utm.md",
            "password": "SecurePass123!",
            "password2": "SecurePass123!",
        }
        response = self.client.post("/auth/register/", data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn("access", response.data)
        self.assertTrue(User.objects.filter(email=data["email"]).exists())

    @patch("apps.common.throttling.SensitiveEndpointThrottle.allow_request", return_value=True)
    @patch("apps.authentication.session_service.redis_client")
    def test_login_success(self, mock_redis, mock_throttle):
        User.objects.create_user(
            email="login.test@fcim.utm.md",
            password="TestPass123!",
        )
        response = self.client.post(
            "/auth/login/",
            {
                "email": "login.test@fcim.utm.md",
                "password": "TestPass123!",
            },
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("access", response.data)

    @patch("apps.common.throttling.SensitiveEndpointThrottle.allow_request", return_value=True)
    def test_login_invalid_credentials(self, mock_throttle):
        response = self.client.post(
            "/auth/login/",
            {
                "email": "nonexistent@fcim.utm.md",
                "password": "WrongPass123!",
            },
        )
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    @patch("apps.authentication.views.send_verification_email")
    def test_email_resend(self, mock_email):
        User.objects.create_user(
            email="resend.test@fcim.utm.md",
            password="TestPass123!",
        )
        response = self.client.post(
            "/auth/email/resend/",
            {
                "email": "resend.test@fcim.utm.md",
            },
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_email_resend_nonexistent(self):
        response = self.client.post(
            "/auth/email/resend/",
            {
                "email": "nonexistent@fcim.utm.md",
            },
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_email_verify_invalid_token(self):
        response = self.client.post(
            "/auth/email/verify/",
            {
                "token": "invalid_token_value",
            },
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_password_reset_request(self):
        User.objects.create_user(
            email="reset.test@fcim.utm.md",
            password="TestPass123!",
        )
        with patch("apps.authentication.views.send_password_reset_email"):
            response = self.client.post(
                "/auth/password/reset/",
                {
                    "email": "reset.test@fcim.utm.md",
                },
            )
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_password_reset_confirm_invalid(self):
        response = self.client.post(
            "/auth/password/reset/confirm/",
            {
                "token": "invalid_token",
                "new_password": "NewPass123!",
                "confirm_new_password": "NewPass123!",
            },
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


class AuthenticatedViewsTests(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            email="auth.view@fcim.utm.md",
            password="TestPass123!",
        )
        self.client = APIClient()
        self.client.force_authenticate(user=self.user)

    @patch("apps.authentication.session_service.redis_client")
    def test_logout(self, mock_redis):
        mock_redis.get.return_value = '{"user_id": "123"}'
        self.client.cookies["refresh_token"] = "fake_refresh_token"
        response = self.client.post("/auth/logout/")
        self.assertIn(response.status_code, [status.HTTP_200_OK, status.HTTP_204_NO_CONTENT])

    def test_password_change_requires_auth(self):
        self.client.force_authenticate(user=None)
        response = self.client.post("/auth/password/change/", {})
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    @patch("apps.authentication.services.redis_client")
    def test_mfa_setup_start(self, mock_redis):
        response = self.client.post("/auth/mfa/setup/start")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("qr_code", response.data)

    def test_mfa_disable_requires_password(self):
        response = self.client.post("/auth/mfa/disable", {})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
