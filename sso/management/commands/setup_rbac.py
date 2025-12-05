"""
Management command to set up RBAC (Role-Based Access Control) seed data.

This command creates:
1. Base permissions (view, create, modify, delete)
2. Application features for specified apps
3. Default roles with appropriate feature permissions

Usage:
    # Set up RBAC for all registered applications:
    python manage.py setup_rbac

    # Set up RBAC for specific application(s):
    python manage.py setup_rbac --app senco
    python manage.py setup_rbac --app primetrade --app senco

    # Show what would be created without making changes:
    python manage.py setup_rbac --dry-run

    # Reset and recreate all permissions (WARNING: destructive):
    python manage.py setup_rbac --reset
"""

from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

from sso.models import (
    Application,
    Feature,
    Permission,
    Role,
    RoleFeaturePermission,
)

# Base permissions that apply to all features
BASE_PERMISSIONS = [
    {"code": "view", "name": "View", "description": "Can view/read data", "order": 1},
    {
        "code": "create",
        "name": "Create",
        "description": "Can create new records",
        "order": 2,
    },
    {
        "code": "modify",
        "name": "Modify",
        "description": "Can update existing records",
        "order": 3,
    },
    {
        "code": "delete",
        "name": "Delete",
        "description": "Can delete records",
        "order": 4,
    },
    {
        "code": "export",
        "name": "Export",
        "description": "Can export/download data",
        "order": 5,
    },
    {
        "code": "approve",
        "name": "Approve",
        "description": "Can approve workflows",
        "order": 6,
    },
]


# Application-specific feature and role definitions
# Add new applications here as they are migrated to RBAC
APP_DEFINITIONS = {
    "senco": {
        "features": [
            {
                "code": "coils",
                "name": "Coil Inventory",
                "description": "Coil management",
            },
            {
                "code": "shipments",
                "name": "Shipments",
                "description": "Shipment tracking",
            },
            {"code": "weights", "name": "Weights", "description": "Weight records"},
            {
                "code": "reports",
                "name": "Reports",
                "description": "Reporting dashboard",
            },
        ],
        "roles": [
            {
                "code": "senco_admin",
                "name": "Senco Admin",
                "description": "Full access to all Senco features",
                "legacy_role": "Admin",
                "permissions": {
                    "coils": ["view", "create", "modify", "delete", "export"],
                    "shipments": ["view", "create", "modify", "delete", "export"],
                    "weights": ["view", "create", "modify", "delete", "export"],
                    "reports": ["view", "export"],
                },
            },
            {
                "code": "senco_office",
                "name": "Senco Office",
                "description": "Daily operations access for Senco",
                "legacy_role": "Office",
                "permissions": {
                    "coils": ["view", "create", "modify"],
                    "shipments": ["view", "create", "modify"],
                    "weights": ["view", "create", "modify"],
                    "reports": ["view"],
                },
            },
            {
                "code": "senco_viewer",
                "name": "Senco Viewer",
                "description": "Read-only access to Senco",
                "legacy_role": "Client",
                "permissions": {
                    "coils": ["view"],
                    "shipments": ["view"],
                    "weights": ["view"],
                    "reports": ["view"],
                },
            },
        ],
    },
    "primetrade": {
        "features": [
            {"code": "bol", "name": "Bill of Lading", "description": "BOL management"},
            {
                "code": "releases",
                "name": "Releases",
                "description": "Release management",
            },
            {"code": "schedule", "name": "Schedule", "description": "Loading schedule"},
            {"code": "products", "name": "Products", "description": "Product catalog"},
            {
                "code": "customers",
                "name": "Customers",
                "description": "Customer database",
            },
            {
                "code": "carriers",
                "name": "Carriers",
                "description": "Carrier management",
            },
            {
                "code": "reports",
                "name": "Reports",
                "description": "Reporting dashboard",
            },
        ],
        "roles": [
            {
                "code": "primetrade_admin",
                "name": "PrimeTrade Admin",
                "description": "Full access to all PrimeTrade features",
                "legacy_role": "Admin",
                "permissions": {
                    "bol": ["view", "create", "modify", "delete", "export"],
                    "releases": ["view", "create", "modify", "delete", "export"],
                    "schedule": ["view", "create", "modify", "delete", "export"],
                    "products": ["view", "create", "modify", "delete"],
                    "customers": ["view", "create", "modify", "delete"],
                    "carriers": ["view", "create", "modify", "delete"],
                    "reports": ["view", "export"],
                },
            },
            {
                "code": "primetrade_office",
                "name": "PrimeTrade Office",
                "description": "Daily operations access for PrimeTrade",
                "legacy_role": "Office",
                "permissions": {
                    "bol": ["view", "create", "modify"],
                    "releases": ["view", "create", "modify"],
                    "schedule": ["view", "create", "modify"],
                    "products": ["view"],
                    "customers": ["view"],
                    "carriers": ["view"],
                    "reports": ["view"],
                },
            },
            {
                "code": "primetrade_operator",
                "name": "PrimeTrade Operator",
                "description": "Field operations access for PrimeTrade",
                "legacy_role": "Operator",
                "permissions": {
                    "bol": ["view"],
                    "releases": ["view", "modify"],
                    "schedule": ["view"],
                    "products": ["view"],
                    "customers": ["view"],
                    "carriers": ["view"],
                    "reports": [],
                },
            },
            {
                "code": "primetrade_client",
                "name": "PrimeTrade Client",
                "description": "Client view-only access to PrimeTrade",
                "legacy_role": "Client",
                "permissions": {
                    "bol": ["view"],
                    "releases": ["view"],
                    "schedule": ["view"],
                    "products": [],
                    "customers": [],
                    "carriers": [],
                    "reports": [],
                },
            },
        ],
    },
    "sacks": {
        "features": [
            {
                "code": "inventory",
                "name": "Inventory",
                "description": "Sack inventory management",
            },
            {
                "code": "transactions",
                "name": "Transactions",
                "description": "Transaction history",
            },
            {
                "code": "reports",
                "name": "Reports",
                "description": "Reporting dashboard",
            },
        ],
        "roles": [
            {
                "code": "sacks_admin",
                "name": "Sacks Admin",
                "description": "Full access to all Sacks features",
                "legacy_role": "Admin",
                "permissions": {
                    "inventory": ["view", "create", "modify", "delete", "export"],
                    "transactions": ["view", "create", "modify", "delete"],
                    "reports": ["view", "export"],
                },
            },
            {
                "code": "sacks_office",
                "name": "Sacks Office",
                "description": "Daily operations for Sacks",
                "legacy_role": "Office",
                "permissions": {
                    "inventory": ["view", "create", "modify"],
                    "transactions": ["view", "create"],
                    "reports": ["view"],
                },
            },
        ],
    },
}


class Command(BaseCommand):
    help = "Set up RBAC seed data (permissions, features, roles)"

    def add_arguments(self, parser):
        parser.add_argument(
            "--app",
            action="append",
            dest="apps",
            help="Specific application(s) to set up. Can be used multiple times.",
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Show what would be created without making changes.",
        )
        parser.add_argument(
            "--reset",
            action="store_true",
            help="Reset and recreate all RBAC data (WARNING: destructive).",
        )

    def handle(self, *args, **options):
        dry_run = options["dry_run"]
        reset = options["reset"]
        apps = options.get("apps")

        if dry_run:
            self.stdout.write(self.style.WARNING("DRY RUN - No changes will be made"))

        if reset and not dry_run:
            if not self._confirm_reset():
                self.stdout.write("Aborted.")
                return

        try:
            with transaction.atomic():
                # Step 1: Create base permissions
                self._create_permissions(dry_run, reset)

                # Step 2: Determine which apps to process
                if apps:
                    app_slugs = apps
                else:
                    app_slugs = list(APP_DEFINITIONS.keys())

                # Step 3: Process each application
                for app_slug in app_slugs:
                    self._setup_application(app_slug, dry_run, reset)

                if dry_run:
                    raise CommandError("Dry run complete - rolling back transaction")

        except CommandError as e:
            if "Dry run complete" in str(e):
                self.stdout.write(self.style.SUCCESS("\nDry run complete!"))
            else:
                raise

        if not dry_run:
            self.stdout.write(self.style.SUCCESS("\nRBAC setup complete!"))

    def _confirm_reset(self):
        """Confirm destructive reset operation."""
        self.stdout.write(
            self.style.WARNING(
                "\nWARNING: This will delete all existing RBAC data including:\n"
                "  - Role-Feature-Permission mappings\n"
                "  - Roles\n"
                "  - Features\n"
                "  - User role assignments (UserAppRole)\n\n"
                "Existing users will need to be re-assigned to roles.\n"
            )
        )
        response = input("Are you sure you want to continue? [y/N]: ")
        return response.lower() == "y"

    def _create_permissions(self, dry_run, reset):
        """Create base permission types."""
        self.stdout.write("\n=== Base Permissions ===")

        for perm_data in BASE_PERMISSIONS:
            if reset and not dry_run:
                Permission.objects.filter(code=perm_data["code"]).delete()

            perm, created = Permission.objects.get_or_create(
                code=perm_data["code"],
                defaults={
                    "name": perm_data["name"],
                    "description": perm_data["description"],
                    "display_order": perm_data["order"],
                },
            )
            status = "CREATED" if created else "EXISTS"
            if dry_run:
                status = (
                    "WOULD CREATE"
                    if not Permission.objects.filter(code=perm_data["code"]).exists()
                    else "EXISTS"
                )

            self.stdout.write(f"  [{status}] {perm_data['code']}: {perm_data['name']}")

    def _setup_application(self, app_slug, dry_run, reset):
        """Set up features and roles for an application."""
        self.stdout.write(f"\n=== Application: {app_slug} ===")

        # Check if app exists
        try:
            app = Application.objects.get(slug=app_slug)
        except Application.DoesNotExist:
            self.stdout.write(
                self.style.WARNING(
                    f"  Application '{app_slug}' not found in database. Skipping."
                )
            )
            return

        # Check if app has definitions
        if app_slug not in APP_DEFINITIONS:
            self.stdout.write(
                self.style.WARNING(
                    f"  No RBAC definitions found for '{app_slug}'. Skipping."
                )
            )
            return

        app_def = APP_DEFINITIONS[app_slug]

        # Reset existing data if requested
        if reset and not dry_run:
            RoleFeaturePermission.objects.filter(role__application=app).delete()
            Role.objects.filter(application=app).delete()
            Feature.objects.filter(application=app).delete()

        # Create features
        self.stdout.write("  Features:")
        features = {}
        for i, feat_data in enumerate(app_def["features"]):
            feat, created = Feature.objects.get_or_create(
                application=app,
                code=feat_data["code"],
                defaults={
                    "name": feat_data["name"],
                    "description": feat_data.get("description", ""),
                    "display_order": i,
                },
            )
            features[feat_data["code"]] = feat
            status = "CREATED" if created else "EXISTS"
            if dry_run:
                status = (
                    "WOULD CREATE"
                    if not Feature.objects.filter(
                        application=app, code=feat_data["code"]
                    ).exists()
                    else "EXISTS"
                )
            self.stdout.write(
                f"    [{status}] {feat_data['code']}: {feat_data['name']}"
            )

        # Create roles and permissions
        self.stdout.write("  Roles:")
        permissions = {p.code: p for p in Permission.objects.all()}

        for role_data in app_def["roles"]:
            role, created = Role.objects.get_or_create(
                application=app,
                code=role_data["code"],
                defaults={
                    "name": role_data["name"],
                    "description": role_data.get("description", ""),
                    "legacy_role": role_data.get("legacy_role", ""),
                },
            )
            status = "CREATED" if created else "EXISTS"
            if dry_run:
                status = (
                    "WOULD CREATE"
                    if not Role.objects.filter(
                        application=app, code=role_data["code"]
                    ).exists()
                    else "EXISTS"
                )
            self.stdout.write(
                f"    [{status}] {role_data['code']}: {role_data['name']}"
            )

            # Create role-feature-permission mappings
            for feat_code, perm_codes in role_data.get("permissions", {}).items():
                if feat_code not in features:
                    continue
                feature = features[feat_code]
                for perm_code in perm_codes:
                    if perm_code not in permissions:
                        continue
                    permission = permissions[perm_code]
                    rfp, rfp_created = RoleFeaturePermission.objects.get_or_create(
                        role=role,
                        feature=feature,
                        permission=permission,
                    )
                    if rfp_created:
                        self.stdout.write(f"      + {feat_code}.{perm_code}")
