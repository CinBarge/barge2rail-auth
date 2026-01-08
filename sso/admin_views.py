"""
Custom admin views for SSO.

Role Permission Matrix: QuickBooks-style grid for editing role permissions.
Enterprise RBAC Management: History, user impact, comparison, bulk assignment.
"""

import json
import re

from django.contrib import messages
from django.contrib.admin.views.decorators import staff_member_required
from django.http import HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone

from .models import (
    Application,
    Feature,
    Permission,
    Role,
    RoleFeaturePermission,
    Tenant,
    User,
    UserAppRole,
)


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

    # Get users affected by this role
    affected_users = User.objects.filter(
        app_roles__role=role,
        app_roles__is_active=True,
    ).distinct()

    if request.method == "POST":
        # Get current permissions as set of (feature_id, permission_id) tuples
        current_perms_set = set(
            RoleFeaturePermission.objects.filter(role=role).values_list(
                "feature_id", "permission_id"
            )
        )

        # Build submitted permissions set from form
        submitted_perms_set = set()
        for feature in features:
            selected_perm_ids = request.POST.getlist(f"feature_{feature.id}")
            for perm_id in selected_perm_ids:
                try:
                    perm_id_int = int(perm_id)
                    submitted_perms_set.add((feature.id, perm_id_int))
                except ValueError:
                    pass

        # Calculate differences
        to_delete = current_perms_set - submitted_perms_set
        to_create = submitted_perms_set - current_perms_set

        # Only delete removed permissions
        deleted_count = 0
        for feature_id, perm_id in to_delete:
            RoleFeaturePermission.objects.filter(
                role=role, feature_id=feature_id, permission_id=perm_id
            ).delete()
            deleted_count += 1

        # Only create added permissions
        created_count = 0
        for feature_id, perm_id in to_create:
            try:
                perm = Permission.objects.get(id=perm_id)
                feature = Feature.objects.get(id=feature_id)
                RoleFeaturePermission.objects.create(
                    role=role,
                    feature=feature,
                    permission=perm,
                )
                created_count += 1
            except (Permission.DoesNotExist, Feature.DoesNotExist):
                pass

        # Informative message about what changed
        if created_count == 0 and deleted_count == 0:
            messages.info(request, f'No changes to "{role.name}" permissions.')
        else:
            parts = []
            if created_count:
                parts.append(f"{created_count} added")
            if deleted_count:
                parts.append(f"{deleted_count} removed")
            messages.success(
                request,
                f'Permissions for "{role.name}" updated: {", ".join(parts)}.',
            )
        # Stay on the permission matrix page (not redirect to role change)
        return redirect("sso_role_permission_matrix", role_id=role_id)

    context = {
        "role": role,
        "features": features,
        "permissions": permissions,
        "current_perms": current_perms,
        "affected_users": affected_users,
        "affected_count": affected_users.count(),
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


# =============================================================================
# Feature 1: Audit Trail / History
# =============================================================================


@staff_member_required
def role_history(request, role_id):
    """Display audit history for a role and its permission changes."""
    role = get_object_or_404(Role, pk=role_id)

    # Get role history
    role_history_records = role.history.all().select_related("history_user")[:50]

    # Get permission change history for this role
    perm_history = (
        RoleFeaturePermission.history.filter(role_id=role_id)
        .select_related("history_user")
        .order_by("-history_date")[:100]
    )

    context = {
        "role": role,
        "role_history": role_history_records,
        "perm_history": perm_history,
        "title": f"History: {role.name}",
    }
    return render(request, "admin/sso/role_history.html", context)


# =============================================================================
# Feature 3: Effective Permissions View
# =============================================================================


@staff_member_required
def effective_permissions(request):
    """Show what a specific user can actually do across all their roles."""
    user_id = request.GET.get("user_id")
    selected_user = None
    permissions_by_app = {}

    if user_id:
        selected_user = get_object_or_404(User, pk=user_id)

        # Get all active roles for this user
        user_roles = UserAppRole.objects.filter(
            user=selected_user,
            is_active=True,
        ).select_related("role", "role__application")

        for user_role in user_roles:
            app_name = user_role.role.application.name
            if app_name not in permissions_by_app:
                permissions_by_app[app_name] = {
                    "roles": [],
                    "tenant": user_role.tenant_code,
                    "features": {},
                }

            permissions_by_app[app_name]["roles"].append(user_role.role.name)

            # Merge permissions from this role
            for rfp in user_role.role.feature_permissions.select_related(
                "feature", "permission"
            ):
                feature_name = rfp.feature.name
                if feature_name not in permissions_by_app[app_name]["features"]:
                    permissions_by_app[app_name]["features"][feature_name] = set()

                permissions_by_app[app_name]["features"][feature_name].add(
                    rfp.permission.code
                )

    # Get all users for dropdown
    all_users = User.objects.filter(is_active=True).order_by("email")
    all_permissions = Permission.objects.all().order_by("display_order", "code")

    context = {
        "all_users": all_users,
        "selected_user": selected_user,
        "permissions_by_app": permissions_by_app,
        "all_permissions": all_permissions,
        "title": "Effective Permissions",
    }
    return render(request, "admin/sso/effective_permissions.html", context)


# =============================================================================
# Feature 5: Role Comparison
# =============================================================================


@staff_member_required
def compare_roles(request):
    """Side-by-side comparison of two roles."""
    role1_id = request.GET.get("role1")
    role2_id = request.GET.get("role2")
    app_id = request.GET.get("app")

    role1 = role2 = None
    comparison = []

    # Get apps for dropdown
    apps = Application.objects.all()
    selected_app = None
    available_roles = []

    if app_id:
        selected_app = get_object_or_404(Application, pk=app_id)
        available_roles = Role.objects.filter(application=selected_app)

        if role1_id and role2_id:
            role1 = get_object_or_404(Role, pk=role1_id)
            role2 = get_object_or_404(Role, pk=role2_id)

            # Build comparison data
            features = Feature.objects.filter(application=selected_app)
            permissions = Permission.objects.all().order_by("display_order", "code")

            role1_perms = {}
            for rfp in role1.feature_permissions.select_related(
                "feature", "permission"
            ):
                if rfp.feature_id not in role1_perms:
                    role1_perms[rfp.feature_id] = set()
                role1_perms[rfp.feature_id].add(rfp.permission.code)

            role2_perms = {}
            for rfp in role2.feature_permissions.select_related(
                "feature", "permission"
            ):
                if rfp.feature_id not in role2_perms:
                    role2_perms[rfp.feature_id] = set()
                role2_perms[rfp.feature_id].add(rfp.permission.code)

            for feature in features:
                r1_perms = role1_perms.get(feature.id, set())
                r2_perms = role2_perms.get(feature.id, set())

                feature_comparison = {
                    "feature": feature,
                    "permissions": [],
                }

                for perm in permissions:
                    in_r1 = perm.code in r1_perms
                    in_r2 = perm.code in r2_perms
                    diff = "same" if in_r1 == in_r2 else "different"
                    feature_comparison["permissions"].append(
                        {
                            "perm": perm,
                            "role1": in_r1,
                            "role2": in_r2,
                            "diff": diff,
                        }
                    )

                comparison.append(feature_comparison)

    context = {
        "apps": apps,
        "selected_app": selected_app,
        "available_roles": available_roles,
        "role1": role1,
        "role2": role2,
        "comparison": comparison,
        "title": "Compare Roles",
    }
    return render(request, "admin/sso/compare_roles.html", context)


# =============================================================================
# Feature 6: Bulk User Assignment
# =============================================================================


@staff_member_required
def bulk_assign_role(request):
    """Assign multiple users to a role at once."""
    if request.method == "POST":
        role_id = request.POST.get("role")
        user_ids = request.POST.getlist("users")
        tenant_code = request.POST.get("tenant_code") or None

        role = get_object_or_404(Role, pk=role_id)
        created_count = 0
        assigned_emails = []

        for user_id in user_ids:
            user = User.objects.get(pk=user_id)
            _, created = UserAppRole.objects.get_or_create(
                user=user,
                role=role,
                tenant_code=tenant_code,
                defaults={"is_active": True, "assigned_by": request.user},
            )
            if created:
                created_count += 1
                assigned_emails.append(user.email)

        # Detailed success message with user emails
        if assigned_emails:
            email_list = ", ".join(assigned_emails)
            messages.success(request, f"Assigned {email_list} to {role.name}")
        else:
            messages.info(request, "No new assignments - users already have this role")
        return redirect("sso_bulk_assign_role")

    # GET: show form
    roles = Role.objects.select_related("application").filter(is_active=True)
    users = User.objects.filter(is_active=True).order_by("email")

    # Get tenants for dropdown (active tenants from Tenant model)
    tenants = Tenant.objects.filter(is_active=True)

    context = {
        "roles": roles,
        "users": users,
        "tenants": tenants,
        "title": "Bulk Role Assignment",
    }
    return render(request, "admin/sso/bulk_assign_role.html", context)


# =============================================================================
# Feature 7: Export/Import JSON
# =============================================================================


@staff_member_required
def export_roles(request, app_id=None):
    """Export roles and permissions as JSON."""
    roles_query = Role.objects.all()
    if app_id:
        roles_query = roles_query.filter(application_id=app_id)

    export_data = {
        "exported_at": timezone.now().isoformat(),
        "roles": [],
    }

    for role in roles_query.select_related("application").prefetch_related(
        "feature_permissions__permission", "feature_permissions__feature"
    ):
        role_data = {
            "application": role.application.slug,
            "code": role.code,
            "name": role.name,
            "description": role.description,
            "legacy_role": role.legacy_role,
            "permissions": {},
        }

        for rfp in role.feature_permissions.all():
            if rfp.feature.code not in role_data["permissions"]:
                role_data["permissions"][rfp.feature.code] = []
            role_data["permissions"][rfp.feature.code].append(rfp.permission.code)

        export_data["roles"].append(role_data)

    response = HttpResponse(
        json.dumps(export_data, indent=2),
        content_type="application/json",
    )
    response["Content-Disposition"] = 'attachment; filename="rbac_export.json"'
    return response


@staff_member_required
def import_roles(request):
    """Import roles and permissions from JSON."""
    if request.method == "POST" and request.FILES.get("file"):
        try:
            data = json.load(request.FILES["file"])
            created = 0
            updated = 0

            for role_data in data.get("roles", []):
                app = Application.objects.get(slug__iexact=role_data["application"])

                role, was_created = Role.objects.update_or_create(
                    application=app,
                    code=role_data["code"],
                    defaults={
                        "name": role_data.get("name", role_data["code"]),
                        "description": role_data.get("description", ""),
                        "legacy_role": role_data.get("legacy_role", ""),
                    },
                )

                if was_created:
                    created += 1
                else:
                    updated += 1

                # Clear existing permissions and set new ones
                RoleFeaturePermission.objects.filter(role=role).delete()

                for feature_code, perm_codes in role_data.get(
                    "permissions", {}
                ).items():
                    try:
                        feature = Feature.objects.get(
                            application=app, code=feature_code
                        )
                        for perm_code in perm_codes:
                            try:
                                perm = Permission.objects.get(code=perm_code)
                                RoleFeaturePermission.objects.create(
                                    role=role,
                                    feature=feature,
                                    permission=perm,
                                )
                            except Permission.DoesNotExist:
                                pass
                    except Feature.DoesNotExist:
                        pass

            messages.success(
                request, f"Import complete: {created} created, {updated} updated"
            )
        except Exception as e:
            messages.error(request, f"Import failed: {e!s}")

        return redirect("sso_import_roles")

    return render(request, "admin/sso/import_roles.html", {"title": "Import Roles"})


# =============================================================================
# Feature 8: Permission Search
# =============================================================================


@staff_member_required
def permission_search(request):
    """Find which roles have specific permissions."""
    feature_code = request.GET.get("feature")
    perm_code = request.GET.get("permission")
    app_id = request.GET.get("app")

    results = []

    if feature_code and perm_code:
        query = RoleFeaturePermission.objects.filter(
            feature__code=feature_code,
            permission__code=perm_code,
        ).select_related("role", "role__application", "feature")

        if app_id:
            query = query.filter(role__application_id=app_id)

        for rfp in query:
            user_count = UserAppRole.objects.filter(
                role=rfp.role, is_active=True
            ).count()
            results.append(
                {
                    "role": rfp.role,
                    "feature": rfp.feature,
                    "user_count": user_count,
                }
            )

    apps = Application.objects.all()
    features = Feature.objects.all().order_by("application", "name")
    permissions = Permission.objects.all().order_by("display_order", "code")

    context = {
        "apps": apps,
        "features": features,
        "permissions": permissions,
        "results": results,
        "selected_feature": feature_code,
        "selected_permission": perm_code,
        "selected_app": app_id,
        "title": "Permission Search",
    }
    return render(request, "admin/sso/permission_search.html", context)


# =============================================================================
# RBAC Dashboard
# =============================================================================


@staff_member_required
def rbac_dashboard(request):
    """Main dashboard for RBAC management tools."""
    # Get some stats
    stats = {
        "total_roles": Role.objects.count(),
        "active_roles": Role.objects.filter(is_active=True).count(),
        "total_users_with_roles": UserAppRole.objects.filter(is_active=True)
        .values("user")
        .distinct()
        .count(),
        "total_permissions": RoleFeaturePermission.objects.count(),
        "total_features": Feature.objects.filter(is_active=True).count(),
        "total_assignments": UserAppRole.objects.filter(is_active=True).count(),
    }

    context = {
        "stats": stats,
        "title": "RBAC Management",
    }
    return render(request, "admin/sso/rbac_dashboard.html", context)


# =============================================================================
# Feature Management (RBAC Dashboard v2)
# =============================================================================


@staff_member_required
def feature_list(request):
    """List all features with filtering by application."""
    app_id = request.GET.get("app")
    features = Feature.objects.select_related("application").order_by(
        "application__name", "display_order", "name"
    )

    if app_id:
        features = features.filter(application_id=app_id)

    apps = Application.objects.all()

    context = {
        "features": features,
        "apps": apps,
        "selected_app": app_id,
        "title": "Manage Features",
    }
    return render(request, "admin/sso/feature_list.html", context)


@staff_member_required
def feature_create(request):
    """Create a new feature."""
    if request.method == "POST":
        application_id = request.POST.get("application")
        code = request.POST.get("code", "").lower().strip()
        name = request.POST.get("name", "").strip()
        description = request.POST.get("description", "").strip()
        display_order = request.POST.get("display_order", 0) or 0
        is_active = request.POST.get("is_active") == "on"

        if not application_id or not code or not name:
            messages.error(request, "Application, code, and name are required.")
            return redirect("sso_feature_create")

        try:
            application = Application.objects.get(pk=application_id)
            # Check if code already exists for this application
            if Feature.objects.filter(application=application, code=code).exists():
                messages.error(
                    request,
                    f'Feature "{code}" already exists for {application.name}.',
                )
                return redirect("sso_feature_create")

            Feature.objects.create(
                application=application,
                code=code,
                name=name,
                description=description,
                display_order=int(display_order),
                is_active=is_active,
            )
            messages.success(request, f'Feature "{name}" created successfully.')
            return redirect("sso_feature_list")
        except Application.DoesNotExist:
            messages.error(request, "Invalid application selected.")
            return redirect("sso_feature_create")
        except Exception as e:
            messages.error(request, f"Error creating feature: {e}")
            return redirect("sso_feature_create")

    apps = Application.objects.all()
    context = {
        "apps": apps,
        "title": "Add Feature",
        "is_edit": False,
    }
    return render(request, "admin/sso/feature_form.html", context)


@staff_member_required
def feature_edit(request, feature_id):
    """Edit an existing feature."""
    feature = get_object_or_404(Feature, pk=feature_id)

    if request.method == "POST":
        code = request.POST.get("code", "").lower().strip()
        name = request.POST.get("name", "").strip()
        description = request.POST.get("description", "").strip()
        display_order = request.POST.get("display_order", 0) or 0
        is_active = request.POST.get("is_active") == "on"

        if not code or not name:
            messages.error(request, "Code and name are required.")
            return redirect("sso_feature_edit", feature_id=feature_id)

        # Check if code conflicts with another feature
        if (
            Feature.objects.filter(application=feature.application, code=code)
            .exclude(pk=feature_id)
            .exists()
        ):
            messages.error(
                request, f'Another feature with code "{code}" already exists.'
            )
            return redirect("sso_feature_edit", feature_id=feature_id)

        feature.code = code
        feature.name = name
        feature.description = description
        feature.display_order = int(display_order)
        feature.is_active = is_active
        feature.save()

        messages.success(request, f'Feature "{name}" updated successfully.')
        return redirect("sso_feature_list")

    apps = Application.objects.all()
    context = {
        "feature": feature,
        "apps": apps,
        "title": f"Edit Feature: {feature.name}",
        "is_edit": True,
    }
    return render(request, "admin/sso/feature_form.html", context)


@staff_member_required
def feature_delete(request, feature_id):
    """Delete a feature (only if no permissions assigned)."""
    feature = get_object_or_404(Feature, pk=feature_id)

    # Check if feature has any permissions
    perm_count = RoleFeaturePermission.objects.filter(feature=feature).count()
    if perm_count > 0:
        messages.error(
            request,
            f'Cannot delete "{feature.name}" - has {perm_count} permission(s). '
            f"Remove them first.",
        )
        return redirect("sso_feature_list")

    if request.method == "POST":
        name = feature.name
        feature.delete()
        messages.success(request, f'Feature "{name}" deleted.')
        return redirect("sso_feature_list")

    context = {
        "feature": feature,
        "title": f"Delete Feature: {feature.name}",
    }
    return render(request, "admin/sso/feature_delete.html", context)


# =============================================================================
# Role Management (RBAC Dashboard v2)
# =============================================================================


@staff_member_required
def role_list(request):
    """List all roles with filtering by application."""
    app_id = request.GET.get("app")
    roles = Role.objects.select_related("application").order_by(
        "application__name", "name"
    )

    if app_id:
        roles = roles.filter(application_id=app_id)

    # Annotate with user count and permission count
    role_data = []
    for role in roles:
        user_count = UserAppRole.objects.filter(role=role, is_active=True).count()
        perm_count = RoleFeaturePermission.objects.filter(role=role).count()
        role_data.append(
            {
                "role": role,
                "user_count": user_count,
                "perm_count": perm_count,
            }
        )

    apps = Application.objects.all()

    context = {
        "role_data": role_data,
        "apps": apps,
        "selected_app": app_id,
        "title": "Manage Roles",
    }
    return render(request, "admin/sso/role_list.html", context)


@staff_member_required
def role_create(request):
    """Create a new role."""
    if request.method == "POST":
        application_id = request.POST.get("application")
        code = request.POST.get("code", "").lower().strip()
        name = request.POST.get("name", "").strip()
        description = request.POST.get("description", "").strip()
        legacy_role = request.POST.get("legacy_role", "")
        is_active = request.POST.get("is_active") == "on"

        if not application_id or not code or not name:
            messages.error(request, "Application, code, and name are required.")
            return redirect("sso_role_create")

        try:
            application = Application.objects.get(pk=application_id)
            # Check if code already exists for this application
            if Role.objects.filter(application=application, code=code).exists():
                messages.error(
                    request,
                    f'Role with code "{code}" already exists for {application.name}.',
                )
                return redirect("sso_role_create")

            role = Role.objects.create(
                application=application,
                code=code,
                name=name,
                description=description,
                legacy_role=legacy_role,
                is_active=is_active,
            )
            messages.success(
                request,
                f'Role "{name}" created. '
                f'<a href="{role.id}/permissions/">Edit permissions</a>',
            )
            return redirect("sso_role_list")
        except Application.DoesNotExist:
            messages.error(request, "Invalid application selected.")
            return redirect("sso_role_create")
        except Exception as e:
            messages.error(request, f"Error creating role: {e}")
            return redirect("sso_role_create")

    apps = Application.objects.all()
    legacy_choices = [
        ("", "-"),
        ("Admin", "Admin"),
        ("Office", "Office"),
        ("Operator", "Operator"),
        ("Client", "Client"),
    ]
    context = {
        "apps": apps,
        "legacy_choices": legacy_choices,
        "title": "Add Role",
        "is_edit": False,
    }
    return render(request, "admin/sso/role_form.html", context)


@staff_member_required
def role_edit(request, role_id):
    """Edit an existing role."""
    role = get_object_or_404(Role, pk=role_id)

    if request.method == "POST":
        code = request.POST.get("code", "").lower().strip()
        name = request.POST.get("name", "").strip()
        description = request.POST.get("description", "").strip()
        legacy_role = request.POST.get("legacy_role", "")
        is_active = request.POST.get("is_active") == "on"

        if not code or not name:
            messages.error(request, "Code and name are required.")
            return redirect("sso_role_edit", role_id=role_id)

        # Check if code conflicts with another role
        if (
            Role.objects.filter(application=role.application, code=code)
            .exclude(pk=role_id)
            .exists()
        ):
            messages.error(request, f'Another role with code "{code}" already exists.')
            return redirect("sso_role_edit", role_id=role_id)

        role.code = code
        role.name = name
        role.description = description
        role.legacy_role = legacy_role
        role.is_active = is_active
        role.save()

        messages.success(request, f'Role "{name}" updated successfully.')
        return redirect("sso_role_list")

    apps = Application.objects.all()
    legacy_choices = [
        ("", "-"),
        ("Admin", "Admin"),
        ("Office", "Office"),
        ("Operator", "Operator"),
        ("Client", "Client"),
    ]
    context = {
        "role": role,
        "apps": apps,
        "legacy_choices": legacy_choices,
        "title": f"Edit Role: {role.name}",
        "is_edit": True,
    }
    return render(request, "admin/sso/role_form.html", context)


@staff_member_required
def role_delete(request, role_id):
    """Delete a role (only if no users assigned)."""
    role = get_object_or_404(Role, pk=role_id)

    # Check if role has any users
    user_count = UserAppRole.objects.filter(role=role, is_active=True).count()
    if user_count > 0:
        messages.error(
            request,
            f'Cannot delete "{role.name}" - {user_count} user(s) are assigned. '
            f"Remove user assignments first.",
        )
        return redirect("sso_role_list")

    if request.method == "POST":
        name = role.name
        role.delete()
        messages.success(request, f'Role "{name}" deleted.')
        return redirect("sso_role_list")

    context = {
        "role": role,
        "title": f"Delete Role: {role.name}",
    }
    return render(request, "admin/sso/role_delete.html", context)


# =============================================================================
# User Role Assignment Management (RBAC Dashboard v2)
# =============================================================================


@staff_member_required
def assignment_list(request):
    """List all user role assignments with filtering."""
    app_id = request.GET.get("app")
    role_id = request.GET.get("role")
    search = request.GET.get("q", "").strip()

    assignments = UserAppRole.objects.select_related(
        "user", "role", "role__application", "assigned_by"
    ).order_by("-assigned_at")

    if app_id:
        assignments = assignments.filter(role__application_id=app_id)
    if role_id:
        assignments = assignments.filter(role_id=role_id)
    if search:
        assignments = assignments.filter(user__email__icontains=search)

    apps = Application.objects.all()
    roles = Role.objects.select_related("application").filter(is_active=True)

    context = {
        "assignments": assignments[:100],  # Limit for performance
        "apps": apps,
        "roles": roles,
        "selected_app": app_id,
        "selected_role": role_id,
        "search": search,
        "title": "User Role Assignments",
    }
    return render(request, "admin/sso/assignment_list.html", context)


@staff_member_required
def assignment_edit(request, assignment_id):
    """Edit a user role assignment (tenant code only)."""
    assignment = get_object_or_404(
        UserAppRole.objects.select_related("user", "role", "role__application"),
        pk=assignment_id,
    )

    if request.method == "POST":
        tenant_code = request.POST.get("tenant_code", "").strip() or None
        is_active = request.POST.get("is_active") == "on"

        assignment.tenant_code = tenant_code
        assignment.is_active = is_active
        assignment.save()

        messages.success(
            request,
            f"Assignment for {assignment.user.email} updated.",
        )
        return redirect("sso_assignment_list")

    # Get tenants for dropdown (active tenants from Tenant model)
    tenants = Tenant.objects.filter(is_active=True)

    context = {
        "assignment": assignment,
        "tenants": tenants,
        "title": f"Edit Assignment: {assignment.user.email}",
    }
    return render(request, "admin/sso/assignment_form.html", context)


@staff_member_required
def assignment_delete(request, assignment_id):
    """Remove a user role assignment."""
    assignment = get_object_or_404(
        UserAppRole.objects.select_related("user", "role", "role__application"),
        pk=assignment_id,
    )

    if request.method == "POST":
        email = assignment.user.email
        role_name = assignment.role.name
        assignment.delete()
        messages.success(request, f"Removed {email} from {role_name}.")
        return redirect("sso_assignment_list")

    context = {
        "assignment": assignment,
        "title": f"Remove Assignment: {assignment.user.email}",
    }
    return render(request, "admin/sso/assignment_delete.html", context)


# =============================================================================
# User Management (for Command Center integration)
# =============================================================================


@staff_member_required
def user_list(request):
    """List all users with search/filter."""
    from django.db.models import Q

    users = User.objects.all().order_by("-date_joined")

    q = request.GET.get("q", "").strip()
    if q:
        users = users.filter(
            Q(email__icontains=q)
            | Q(first_name__icontains=q)
            | Q(last_name__icontains=q)
        )

    status = request.GET.get("status", "")
    if status == "active":
        users = users.filter(is_active=True)
    elif status == "inactive":
        users = users.filter(is_active=False)

    # Get role count for each user
    user_data = []
    for user in users[:100]:
        role_count = UserAppRole.objects.filter(user=user, is_active=True).count()
        user_data.append({"user": user, "role_count": role_count})

    context = {
        "user_data": user_data,
        "q": q,
        "status": status,
        "total_count": users.count(),
        "title": "User Management",
    }
    return render(request, "admin/sso/user_list.html", context)


@staff_member_required
def user_create(request):
    """Create a new user with chosen auth method."""
    return_url = request.GET.get("return_url", "")

    if request.method == "POST":
        email = request.POST.get("email", "").strip().lower()
        first_name = request.POST.get("first_name", "").strip()
        last_name = request.POST.get("last_name", "").strip()
        auth_method = request.POST.get("auth_method", "google")
        password = request.POST.get("password", "").strip()
        username = request.POST.get("username", "").strip().lower()
        pin = request.POST.get("pin", "").strip()

        # Validation based on auth method
        if auth_method == "anonymous":
            # Username + PIN validation
            if not username:
                messages.error(request, "Username is required.")
                return redirect("sso_user_create")
            if not pin or len(pin) != 4 or not pin.isdigit():
                messages.error(request, "PIN must be exactly 4 digits.")
                return redirect("sso_user_create")
            if User.objects.filter(anonymous_username=username).exists():
                messages.error(request, f"Username '{username}' already exists.")
                return redirect("sso_user_create")
        else:
            # Email-based auth validation
            if not email:
                messages.error(request, "Email is required.")
                return redirect("sso_user_create")
            if User.objects.filter(email=email).exists():
                messages.error(request, f"User with email {email} already exists.")
                return redirect("sso_user_create")

        # Validate password if password auth selected
        if auth_method == "password":
            if not password or len(password) < 8:
                messages.error(request, "Password must be at least 8 characters.")
                return redirect("sso_user_create")

        # Create user based on auth method
        if auth_method == "anonymous":
            # Username + PIN user
            user = User(
                first_name=first_name,
                last_name=last_name,
                auth_type="anonymous",
                auth_method="password",
                anonymous_username=username,
                is_active=True,
            )
            user.set_password(pin)
            user.save()
            messages.success(request, f"User '{username}' created with PIN login.")
        elif auth_method == "password":
            user = User.objects.create_user(
                email=email,
                first_name=first_name,
                last_name=last_name,
                password=password,
            )
            user.auth_type = "email"
            user.auth_method = "password"
            user.save()
            messages.success(
                request, f"User {email} created with email/password login."
            )
        else:
            # Google OAuth - no password
            user = User.objects.create_user(
                email=email,
                first_name=first_name,
                last_name=last_name,
                password=None,
            )
            user.auth_type = "google"
            user.auth_method = "google"
            user.save()
            messages.success(
                request, f"User {email} created. They can log in via Google SSO."
            )

        # Return to Command Center if return_url provided
        return_url = request.POST.get("return_url", "")
        if return_url and (
            return_url.startswith("https://") or return_url.startswith("http://")
        ):
            return redirect(return_url)

        return redirect("sso_user_list")

    context = {
        "return_url": return_url,
        "title": "Add User",
    }
    return render(request, "admin/sso/user_form.html", context)


@staff_member_required
def user_edit(request, user_id):
    """Edit an existing user."""
    user = get_object_or_404(User, pk=user_id)

    if request.method == "POST":
        user.first_name = request.POST.get("first_name", "").strip()
        user.last_name = request.POST.get("last_name", "").strip()
        user.is_active = request.POST.get("is_active") == "on"
        user.save()

        messages.success(request, f"User {user.email} updated.")
        return redirect("sso_user_list")

    # Get user's role assignments
    assignments = UserAppRole.objects.filter(user=user).select_related(
        "role", "role__application"
    )

    context = {
        "edit_user": user,
        "assignments": assignments,
        "title": f"Edit User: {user.email}",
    }
    return render(request, "admin/sso/user_form.html", context)
