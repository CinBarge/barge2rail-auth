from rest_framework.permissions import BasePermission

class RequireRole(BasePermission):
    required_role = None
    def has_permission(self, request, view):
        roles = getattr(request, "roles", []) or getattr(getattr(request, "user", None), "roles", []) or []
        return self.required_role in roles

class RoleUser(RequireRole):
    required_role = "user"
