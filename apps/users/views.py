from django.contrib.auth import get_user_model
from rest_framework import status
from rest_framework.generics import RetrieveAPIView
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.common.drf_permissions import IsOwnerOrAdmin

from .serializers import UserSerializer

User = get_user_model()

# class UsersView(APIView):
#     def get(self, request):
#         return Response(status=status.HTTP_501_NOT_IMPLEMENTED)

#     def post(self, request):
#         return Response(status=status.HTTP_501_NOT_IMPLEMENTED)


class UserDetailView(RetrieveAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    lookup_field = "id"
    permission_classes = [IsOwnerOrAdmin]

    # def patch(self, request, *args, **kwargs):
    #     return Response(status=status.HTTP_501_NOT_IMPLEMENTED)

    # def delete(self, request, *args, **kwargs):
    #     return Response(status=status.HTTP_501_NOT_IMPLEMENTED)


# class UserPasswordAdminView(APIView):
#     def patch(self, request, user_id):
#         return Response(status=status.HTTP_501_NOT_IMPLEMENTED)


# class UserBalanceView(APIView):
#     def get(self, request, user_id):
#         return Response(status=status.HTTP_501_NOT_IMPLEMENTED)


# class UserOrdersView(APIView):
#     def get(self, request, user_id):
#         return Response(status=status.HTTP_501_NOT_IMPLEMENTED)


# class UserTransactionsView(APIView):
#     def get(self, request, user_id):
#         return Response(status=status.HTTP_501_NOT_IMPLEMENTED)


class UserByAccountNoView(APIView):
    def get(self, request, account_no):
        return Response(status=status.HTTP_501_NOT_IMPLEMENTED)


# Self Profile (aliases)
class MeView(RetrieveAPIView):
    serializer_class = UserSerializer

    def get_object(self):
        return self.request.user

    def patch(self, request, *args, **kwargs):
        return Response(status=status.HTTP_501_NOT_IMPLEMENTED)


class MePasswordView(APIView):
    def patch(self, request):
        return Response(status=status.HTTP_501_NOT_IMPLEMENTED)


class MeBalanceView(APIView):
    def get(self, request):
        return Response(status=status.HTTP_501_NOT_IMPLEMENTED)


class MeOrdersView(APIView):
    def get(self, request):
        return Response(status=status.HTTP_501_NOT_IMPLEMENTED)


class MeTransactionsView(APIView):
    def get(self, request):
        return Response(status=status.HTTP_501_NOT_IMPLEMENTED)
