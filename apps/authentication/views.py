from django.conf import settings
from django.contrib.auth import get_user_model
from django.middleware.csrf import get_token
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import ensure_csrf_cookie
from rest_framework import status
from rest_framework.generics import CreateAPIView, GenericAPIView
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

from apps.authentication.serializers import (
    CustomTokenObtainPairSerializer,
    EmailResendSerializer,
    EmailVerifySerializer,
    MFABackupCodesRegenerateSerializer,
    MFADisableSerializer,
    MFASetupConfirmSerializer,
    MFASetupStartSerializer,
    MFAVerifySerializer,
    MicrosoftAuthCallbackSerializer,
    PasswordChangeSerializer,
    PasswordResetConfirmSerializer,
    PasswordResetRequestSerializer,
    RefreshSerializer,
    RegisterSerializer,
)
from apps.authentication.services import (
    disable_mfa,
    get_microsoft_auth_url,
    handle_mfa_flow,
    handle_microsoft_callback,
    regenerate_backup_codes,
    send_password_reset_email,
    send_verification_email,
    setup_mfa_confirm,
    setup_mfa_start,
    verify_mfa,
)
from apps.authentication.session_service import SessionService
from apps.authentication.utils import verify_email_token, verify_password_reset_token
from apps.common.throttling import SensitiveEndpointThrottle

User = get_user_model()

COOKIE_NAME = "refresh_token"
COOKIE_MAX_AGE = 14 * 24 * 3600  # 14 days


def cookie_opts(request=None):
    return {
        "path": "/",
        "samesite": "Lax",
        "secure": (request.is_secure() if request else not settings.DEBUG),
        "httponly": True,
        # "domain": ".ourdomain.com"
    }


def delete_cookie_opts():
    """Options for deleting cookies - more limited than set_cookie"""
    return {
        "path": "/",
        "samesite": "Lax",
        # "domain": ".ourdomain.com"
    }


def set_refresh_cookie(response, refresh_token, request):
    """Set refresh token as httpOnly cookie and remove from response body."""
    if refresh_token:
        response.set_cookie(
            COOKIE_NAME,
            refresh_token,
            max_age=COOKIE_MAX_AGE,
            **cookie_opts(request),
        )
        # Remove refresh from response body
        if hasattr(response, "data") and "refresh" in response.data:
            del response.data["refresh"]


class CsrfView(APIView):
    permission_classes = [AllowAny]

    @method_decorator(ensure_csrf_cookie)
    def get(self, request):
        get_token(request)
        return Response(status=204)


class RegisterView(CreateAPIView):
    permission_classes = [AllowAny]
    authentication_classes = []
    throttle_classes = [SensitiveEndpointThrottle]

    queryset = User.objects.all()
    serializer_class = RegisterSerializer

    def create(self, request, *args, **kwargs):
        response = super().create(request, *args, **kwargs)

        # Send verification email
        user = User.objects.get(email=response.data["email"])
        send_verification_email(user)

        # Create session in whitelist
        refresh_token_str = response.data.get("refresh")
        if refresh_token_str:
            from rest_framework_simplejwt.tokens import RefreshToken

            token = RefreshToken(refresh_token_str)
            SessionService.create_session(user.id, token["jti"], request)

        set_refresh_cookie(response, refresh_token_str, request)
        return response


class LoginView(TokenObtainPairView):
    serializer_class = CustomTokenObtainPairSerializer
    throttle_classes = [SensitiveEndpointThrottle]

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = serializer.user

        mfa_payload = handle_mfa_flow(user)
        if mfa_payload:
            # MFA required - don't set cookies yet
            return Response(mfa_payload, status=status.HTTP_200_OK)

        # No MFA - create session and set refresh cookie
        refresh_token_str = serializer.validated_data.get("refresh")
        if refresh_token_str:
            from rest_framework_simplejwt.tokens import RefreshToken

            token = RefreshToken(refresh_token_str)
            SessionService.create_session(user.id, token["jti"], request)

        response = Response(serializer.validated_data, status=status.HTTP_200_OK)
        set_refresh_cookie(response, refresh_token_str, request)
        return response


class EmailVerifyView(APIView):
    permission_classes = [AllowAny]
    serializer_class = EmailVerifySerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        token = serializer.validated_data["token"]
        user_id = verify_email_token(token)

        if not user_id:
            return Response({"error": "Invalid or expired token"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(id=user_id)
            if not user.is_verified:
                user.is_verified = True
                user.save()
            return Response({"message": "Email verified successfully"}, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)


class EmailResendView(APIView):
    permission_classes = [AllowAny]
    serializer_class = EmailResendSerializer
    throttle_classes = [SensitiveEndpointThrottle]

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data["email"]
        try:
            user = User.objects.get(email=email)
            if user.is_verified:
                return Response({"message": "Email already verified"}, status=status.HTTP_400_BAD_REQUEST)

            send_verification_email(user)
            return Response({"message": "Verification email sent"}, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            # Don't reveal user existence
            return Response({"message": "Verification email sent"}, status=status.HTTP_200_OK)


class MFASetupStartView(APIView):
    serializer_class = MFASetupStartSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = setup_mfa_start(request.user)
        return Response(data)


class MFASetupConfirmView(APIView):
    serializer_class = MFASetupConfirmSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = setup_mfa_confirm(request.user, serializer.validated_data["code"])
        return Response(data)


class MFABackupCodesRegenerateView(APIView):
    serializer_class = MFABackupCodesRegenerateSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = regenerate_backup_codes(request.user, serializer.validated_data["password"])
        return Response(data)


class MFAVerifyView(APIView):
    permission_classes = [AllowAny]
    serializer_class = MFAVerifySerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = verify_mfa(serializer.validated_data["ticket"], serializer.validated_data["code"])

        # Create session after successful MFA verification
        refresh_token_str = data.get("refresh")
        if refresh_token_str:
            from rest_framework_simplejwt.tokens import RefreshToken

            token = RefreshToken(refresh_token_str)
            # Get user_id from the token payload
            user_id = token.payload.get("user_id")
            SessionService.create_session(user_id, token["jti"], request)

        # Set refresh cookie
        response = Response(data, status=status.HTTP_200_OK)
        set_refresh_cookie(response, refresh_token_str, request)
        return response


class MFADisableView(APIView):
    serializer_class = MFADisableSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = disable_mfa(request.user, serializer.validated_data["password"])
        return Response(data)


class RefreshView(TokenRefreshView):
    serializer_class = RefreshSerializer

    def post(self, request, *args, **kwargs):
        # Get the old refresh token from cookie to extract JTI
        old_refresh_str = request.COOKIES.get(COOKIE_NAME)
        if not old_refresh_str:
            raise InvalidToken("No valid token found in cookie")

        from rest_framework_simplejwt.tokens import RefreshToken

        try:
            old_token = RefreshToken(old_refresh_str)
            old_jti = old_token["jti"]
        except (InvalidToken, TokenError) as e:
            raise InvalidToken("Invalid refresh token") from e

        # Validate session exists in whitelist
        if not SessionService.validate_session(old_jti):
            raise InvalidToken("Session has been revoked")

        # Proceed with token refresh
        response = super().post(request, *args, **kwargs)

        # Rotate session in whitelist
        if response.status_code == 200:
            new_refresh_str = response.data.get("refresh")
            if new_refresh_str:
                new_token = RefreshToken(new_refresh_str)
                new_jti = new_token["jti"]
                SessionService.rotate_session(old_jti, new_jti)

        return response

    def finalize_response(self, request, response, *args, **kwargs):
        set_refresh_cookie(response, response.data.get("refresh"), request)
        return super().finalize_response(request, response, *args, **kwargs)


class LogoutView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        refresh = request.COOKIES.get(COOKIE_NAME)

        if refresh:
            try:
                from rest_framework_simplejwt.tokens import RefreshToken

                token = RefreshToken(refresh)
                # Revoke session from whitelist
                SessionService.revoke_session(token["jti"])
                # Also blacklist the token (defense in depth)
                token.blacklist()
            except (InvalidToken, TokenError):
                pass  # logout as idempotent

        resp = Response(status=status.HTTP_204_NO_CONTENT)
        resp.delete_cookie(COOKIE_NAME, **delete_cookie_opts())
        return resp


class PasswordChangeView(GenericAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = PasswordChangeSerializer

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = request.user
        user.set_password(serializer.validated_data["new_password"])
        user.save()

        return Response({"message": "Password changed successfully."}, status=status.HTTP_200_OK)


class SessionListView(APIView):
    """List all active sessions for the current user."""

    permission_classes = [IsAuthenticated]

    def get(self, request):
        sessions = SessionService.list_sessions(request.user.id)

        # Mark the current session
        current_jti = None
        refresh = request.COOKIES.get(COOKIE_NAME)
        if refresh:
            try:
                from rest_framework_simplejwt.tokens import RefreshToken

                token = RefreshToken(refresh)
                current_jti = token["jti"]
            except (InvalidToken, TokenError):
                pass

        for session in sessions:
            session["is_current"] = session["jti"] == current_jti

        return Response({"sessions": sessions}, status=status.HTTP_200_OK)


class SessionRevokeView(APIView):
    """Revoke a specific session by JTI."""

    permission_classes = [IsAuthenticated]

    def delete(self, request, jti):
        # Verify the session belongs to the current user
        sessions = SessionService.list_sessions(request.user.id)
        session_jtis = [s["jti"] for s in sessions]

        if jti not in session_jtis:
            return Response({"error": "Session not found"}, status=status.HTTP_404_NOT_FOUND)

        SessionService.revoke_session(jti)
        return Response({"message": "Session revoked"}, status=status.HTTP_200_OK)


class SessionRevokeAllView(APIView):
    """Revoke all sessions except the current one."""

    permission_classes = [IsAuthenticated]

    def post(self, request):
        current_jti = None
        refresh = request.COOKIES.get(COOKIE_NAME)
        if refresh:
            try:
                from rest_framework_simplejwt.tokens import RefreshToken

                token = RefreshToken(refresh)
                current_jti = token["jti"]
            except (InvalidToken, TokenError):
                pass

        if current_jti:
            SessionService.revoke_all_other_sessions(request.user.id, current_jti)

        return Response({"message": "All other sessions revoked"}, status=status.HTTP_200_OK)


class PasswordResetRequestView(APIView):
    permission_classes = [AllowAny]
    serializer_class = PasswordResetRequestSerializer
    throttle_classes = [SensitiveEndpointThrottle]

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data["email"]
        try:
            user = User.objects.get(email=email)
            send_password_reset_email(user)
        except User.DoesNotExist:
            pass  # Don't reveal user existence

        return Response({"message": "Password reset email sent if account exists."}, status=status.HTTP_200_OK)


class PasswordResetConfirmView(APIView):
    permission_classes = [AllowAny]
    serializer_class = PasswordResetConfirmSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        token = serializer.validated_data["token"]
        user_id = verify_password_reset_token(token)

        if not user_id:
            return Response({"error": "Invalid or expired token"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(id=user_id)
            user.set_password(serializer.validated_data["new_password"])
            user.save()
            return Response({"message": "Password reset successfully"}, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)


class MicrosoftAuthStartView(APIView):
    """Start Microsoft OAuth flow - returns authorization URL."""

    permission_classes = [AllowAny]
    authentication_classes = []

    def get(self, request):
        data = get_microsoft_auth_url()
        return Response(data, status=status.HTTP_200_OK)


class MicrosoftAuthCallbackView(APIView):
    """Handle Microsoft OAuth callback - exchanges code for tokens and authenticates user."""

    permission_classes = [AllowAny]
    authentication_classes = []
    serializer_class = MicrosoftAuthCallbackSerializer

    def post(self, request):
        """Handle callback via POST (recommended for SPA flow)."""
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        code = serializer.validated_data["code"]
        state = serializer.validated_data.get("state")

        data = handle_microsoft_callback(code, state)

        # Check if MFA is required
        if data.get("mfa_required"):
            return Response(data, status=status.HTTP_200_OK)

        # Create session in whitelist
        refresh_token_str = data.get("refresh")
        if refresh_token_str:
            from rest_framework_simplejwt.tokens import RefreshToken

            token = RefreshToken(refresh_token_str)
            user_id = token.payload.get("user_id")
            SessionService.create_session(user_id, token["jti"], request)

        # Set refresh token as httpOnly cookie
        response = Response(data, status=status.HTTP_200_OK)
        set_refresh_cookie(response, refresh_token_str, request)
        return response

    def get(self, request):
        """Handle callback via GET (Microsoft redirect)."""
        code = request.query_params.get("code")
        state = request.query_params.get("state")
        error = request.query_params.get("error")
        error_description = request.query_params.get("error_description")

        # Handle error from Microsoft
        if error:
            frontend_url = settings.FRONTEND_URL
            error_params = f"?error={error}&error_description={error_description or 'Authentication failed'}"
            from django.shortcuts import redirect

            return redirect(f"{frontend_url}/auth/microsoft/callback{error_params}")

        if not code:
            return Response({"error": "Authorization code not provided"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            data = handle_microsoft_callback(code, state)

            # For development/testing: return JSON if no frontend
            # In production, set FRONTEND_URL and this will redirect
            frontend_url = settings.FRONTEND_URL
            if not frontend_url or frontend_url == "http://localhost:3000":
                # Create session in whitelist
                refresh_token_str = data.get("refresh")
                if refresh_token_str:
                    from rest_framework_simplejwt.tokens import RefreshToken

                    token = RefreshToken(refresh_token_str)
                    user_id = token.payload.get("user_id")
                    SessionService.create_session(user_id, token["jti"], request)

                # Return JSON response for testing (no frontend running)
                response = Response(data, status=status.HTTP_200_OK)
                set_refresh_cookie(response, refresh_token_str, request)
                return response

            # Check if MFA is required
            if data.get("mfa_required"):
                # Redirect to frontend with MFA ticket
                mfa_ticket = data.get("mfa_ticket")
                mfa_type = data.get("mfa_type")
                from django.shortcuts import redirect

                return redirect(f"{frontend_url}/auth/mfa?ticket={mfa_ticket}&type={mfa_type}")

            # Create session in whitelist before redirect
            refresh_token_str = data.get("refresh")
            if refresh_token_str:
                from rest_framework_simplejwt.tokens import RefreshToken

                token = RefreshToken(refresh_token_str)
                user_id = token.payload.get("user_id")
                SessionService.create_session(user_id, token["jti"], request)

            # Redirect to frontend with tokens (access token in URL, refresh in cookie)
            from django.shortcuts import redirect

            access_token = data.get("access")
            response = redirect(f"{frontend_url}/auth/microsoft/callback?access_token={access_token}")
            set_refresh_cookie(response, refresh_token_str, request)
            return response

        except (ValueError, KeyError) as e:
            frontend_url = settings.FRONTEND_URL
            if not frontend_url or frontend_url == "http://localhost:3000":
                # Return JSON error for testing
                return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

            from urllib.parse import quote

            from django.shortcuts import redirect

            return redirect(f"{frontend_url}/auth/microsoft/callback?error={quote(str(e))}")
