"""
Custom admin views for SSO.

Role Permission Matrix: QuickBooks-style grid for editing role permissions.
"""

import re

from django.contrib import messages
from django.contrib.admin.views.decorators import staff_member_required
from django.shortcuts import get_object_or_404, redirect, render

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
            f'Permissions for "{role.name}" saved successfully. '
            f"{created_count} permission(s) set.",
        )
        # Stay on the permission matrix page (not redirect to role change)
        return redirect("sso_role_permission_matrix", role_id=role_id)

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


@staff_member_required
def clone_role(request, role_id):
    """
    Clone an existing role with all its permissions.

    Creates a new role with the same application and permissions,
    then redirects to the permission matrix for the new role.
    """
    original = get_object_or_404(Role, pk=role_id)
    new_name = request.GET.get("name", f"{original.name} (Copy)")

    # Generate a unique code from the name
    base_code = re.sub(r"[^a-z0-9]+", "_", new_name.lower()).strip("_")
    code = base_code

    # Ensure code is unique for this application
    counter = 1
    while Role.objects.filter(application=original.application, code=code).exists():
        code = f"{base_code}_{counter}"
        counter += 1

    # Create new role
    new_role = Role.objects.create(
        application=original.application,
        code=code,
        name=new_name,
        description=f"Cloned from {original.name}",
        legacy_role="",  # Don't copy legacy role mapping
        is_active=True,
    )

    # Copy all permissions
    copied_count = 0
    for rfp in original.feature_permissions.select_related("feature", "permission"):
        RoleFeaturePermission.objects.create(
            role=new_role,
            feature=rfp.feature,
            permission=rfp.permission,
        )
        copied_count += 1

    messages.success(
        request,
        f'Role "{new_name}" created with {copied_count} permission(s) '
        f'copied from "{original.name}".',
    )

    # Redirect to permission matrix for the new role
    return redirect("sso_role_permission_matrix", role_id=new_role.id)
