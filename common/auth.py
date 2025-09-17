from django.conf import settings
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
from django.utils.functional import SimpleLazyObject
import requests

class SSOValidationAuthentication(BaseAuthentication):
    """
    Dev/interop auth: forwards Bearer token to SSO VALIDATION URL.
    Returns a lightweight user object with .id and .roles.
    """
    def authenticate(self, request):
        auth = request.META.get("HTTP_AUTHORIZATION", "")
        if not auth.startswith("Bearer "):
            return None  # allow other authenticators or 401 later
        token = auth.split(" ", 1)[1]
        try:
            r = requests.get(settings.SSO_VALIDATION_URL, headers={"Authorization": f"Bearer {token}"}, timeout=3)
        except requests.RequestException:
            raise AuthenticationFailed("sso_unreachable")
        if r.status_code != 200:
            raise AuthenticationFailed("invalid_token")
        data = r.json()
        roles = (data.get("user") or {}).get("roles", [])
        uid = (data.get("user") or {}).get("id")
        user = SimpleLazyObject(lambda: type("SSOUser", (object,), {"id": uid, "roles": roles})())
        request.roles = roles
        return (user, {"roles": roles, "token": token})
