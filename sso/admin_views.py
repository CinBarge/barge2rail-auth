"""
Custom admin views for SSO.

Role Permission Matrix: QuickBooks-style grid for editing role permissions.
"""

from django.contrib import messages
from django.contrib.admin.views.decorators import staff_member_required
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse

from .models import Feature, Permission, Role, RoleFeaturePermission


@staff_member_required
def role_permission_matrix(request, role_id):
    """
    Display and edit role permissions in a matrix view.

    Shows a grid with features as rows and permissions as columns.
    Checkboxes indicate which permissions are granted for each feature.
    """
    role = get_object_or_404(Role, pk=role_id)
    features = Feature.objects.filter(
        application=role.application, is_active=True
    ).order_by("display_order", "name")
    permissions = Permission.objects.all().order_by("display_order", "code")

    # Build current permissions matrix: {feature_id: {perm_id, ...}}
    current_perms = {}
    for rfp in role.feature_permissions.select_related("feature", "permission"):
        if rfp.feature_id not in current_perms:
            current_perms[rfp.feature_id] = set()
        current_perms[rfp.feature_id].add(rfp.permission_id)

    if request.method == "POST":
        # Clear existing permissions for this role
        RoleFeaturePermission.objects.filter(role=role).delete()

        # Process form submission - create new permissions
        created_count = 0
        for feature in features:
            selected_perm_ids = request.POST.getlist(f"feature_{feature.id}")
            for perm_id in selected_perm_ids:
                try:
                    perm = Permission.objects.get(id=perm_id)
                    RoleFeaturePermission.objects.create(
                        role=role,
                        feature=feature,
                        permission=perm,
                    )
                    created_count += 1
                except Permission.DoesNotExist:
                    pass

        messages.success(
            request,
            f"Permissions updated for {role.name}. {created_count} permission(s) set.",
        )
        return redirect(reverse("admin:sso_role_change", args=[role_id]))

    context = {
        "role": role,
        "features": features,
        "permissions": permissions,
        "current_perms": current_perms,
        "title": f"Edit Permissions: {role.name}",
        "opts": Role._meta,  # For admin breadcrumbs
        "has_view_permission": True,
        "has_change_permission": True,
    }
    return render(request, "admin/sso/role_permission_matrix.html", context)
