# core/views.py
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView

from common.permissions import RoleUser  # uses roles from SSOValidationAuthentication


class Health(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        return Response({"status": "ok"})


class SecureEcho(APIView):
    permission_classes = [RoleUser]  # requires "user" role by default

    def get(self, request):
        return Response({"ok": True, "roles": getattr(request, "roles", [])})
