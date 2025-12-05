"""
Authorization Security Tests

Tests for tenant isolation and privilege escalation prevention.
Phase 1 security fixes ensure:
1. ApplicationDetailView restricts access by ownership/admin
2. UserRoleDetailView restricts access by authorization
3. UserRoleListCreateView validates ownership before creation
4. OIDC claims only return roles for requesting application
"""

from django.contrib.auth import get_user_model
from django.test import TestCase
from rest_framework import status
from rest_framework.test import APIClient

from sso.models import Application, ApplicationRole, UserRole

User = get_user_model()

# Base URL for API endpoints (includes /api/auth/ prefix from core/urls.py)
API_BASE = "/api/auth"


class ApplicationAccessTests(TestCase):
    """Test ApplicationDetailView access controls."""

    def setUp(self):
        """Create test users and applications."""
        # Create SSO admin user
        self.admin_user = User.objects.create_user(
            email="admin@barge2rail.com",
            username="admin@barge2rail.com",
            password="adminpass123",  # pragma: allowlist secret
        )
        self.admin_user.is_sso_admin = True
        self.admin_user.save()

        # Create regular user who owns an application
        self.app_owner = User.objects.create_user(
            email="owner@example.com",
            username="owner@example.com",
            password="ownerpass123",  # pragma: allowlist secret
        )

        # Create another regular user with no applications
        self.other_user = User.objects.create_user(
            email="other@example.com",
            username="other@example.com",
            password="otherpass123",  # pragma: allowlist secret
        )

        # Create application owned by app_owner
        self.owned_app = Application.objects.create(
            name="Owner's App",
            slug="owner-app",
            user=self.app_owner,
        )

        # Create application with no owner (legacy)
        self.unowned_app = Application.objects.create(
            name="Unowned App",
            slug="unowned-app",
            user=None,
        )

        self.client = APIClient()

    def test_admin_can_access_any_application(self):
        """SSO admin should be able to access any application."""
        self.client.force_authenticate(user=self.admin_user)

        # Access owned app
        response = self.client.get(f"{API_BASE}/applications/{self.owned_app.id}/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Access unowned app
        response = self.client.get(f"{API_BASE}/applications/{self.unowned_app.id}/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_owner_can_access_own_application(self):
        """App owner should be able to access their own application."""
        self.client.force_authenticate(user=self.app_owner)

        response = self.client.get(f"{API_BASE}/applications/{self.owned_app.id}/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_owner_cannot_access_other_application(self):
        """App owner should NOT be able to access other applications."""
        self.client.force_authenticate(user=self.app_owner)

        response = self.client.get(f"{API_BASE}/applications/{self.unowned_app.id}/")
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_regular_user_cannot_access_any_application(self):
        """Regular user should NOT be able to access applications they don't own."""
        self.client.force_authenticate(user=self.other_user)

        response = self.client.get(f"{API_BASE}/applications/{self.owned_app.id}/")
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

        response = self.client.get(f"{API_BASE}/applications/{self.unowned_app.id}/")
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_owner_can_update_own_application(self):
        """App owner should be able to update their own application."""
        self.client.force_authenticate(user=self.app_owner)

        response = self.client.patch(
            f"{API_BASE}/applications/{self.owned_app.id}/",
            {"description": "Updated description"},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_other_user_cannot_update_application(self):
        """Other user should NOT be able to update applications they don't own."""
        self.client.force_authenticate(user=self.other_user)

        response = self.client.patch(
            f"{API_BASE}/applications/{self.owned_app.id}/",
            {"description": "Hacked description"},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_other_user_cannot_delete_application(self):
        """Other user should NOT be able to delete applications they don't own."""
        self.client.force_authenticate(user=self.other_user)

        response = self.client.delete(f"{API_BASE}/applications/{self.owned_app.id}/")
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_unauthenticated_cannot_access_application(self):
        """Unauthenticated users should NOT be able to access applications."""
        response = self.client.get(f"{API_BASE}/applications/{self.owned_app.id}/")
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


class UserRoleAccessTests(TestCase):
    """Test UserRoleDetailView and UserRoleListCreateView access controls."""

    def setUp(self):
        """Create test users, applications, and roles."""
        # Create SSO admin
        self.admin_user = User.objects.create_user(
            email="admin@barge2rail.com",
            username="admin@barge2rail.com",
            password="adminpass123",  # pragma: allowlist secret
        )
        self.admin_user.is_sso_admin = True
        self.admin_user.save()

        # Create app owner
        self.app_owner = User.objects.create_user(
            email="owner@example.com",
            username="owner@example.com",
            password="ownerpass123",  # pragma: allowlist secret
        )

        # Create regular users
        self.user1 = User.objects.create_user(
            email="user1@example.com",
            username="user1@example.com",
            password="user1pass123",  # pragma: allowlist secret
        )

        self.user2 = User.objects.create_user(
            email="user2@example.com",
            username="user2@example.com",
            password="user2pass123",  # pragma: allowlist secret
        )

        # Create application owned by app_owner
        self.owned_app = Application.objects.create(
            name="Owner's App",
            slug="owner-app",
            user=self.app_owner,
        )

        # Create another application (not owned by app_owner)
        self.other_app = Application.objects.create(
            name="Other App",
            slug="other-app",
            user=None,
        )

        # Create roles
        self.user1_role_owned_app = UserRole.objects.create(
            user=self.user1,
            application=self.owned_app,
            role="user",
        )

        self.user2_role_other_app = UserRole.objects.create(
            user=self.user2,
            application=self.other_app,
            role="user",
        )

        self.client = APIClient()

    def test_admin_can_access_any_role(self):
        """SSO admin should be able to access any user role."""
        self.client.force_authenticate(user=self.admin_user)

        response = self.client.get(
            f"{API_BASE}/user-roles/{self.user1_role_owned_app.id}/"
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        response = self.client.get(
            f"{API_BASE}/user-roles/{self.user2_role_other_app.id}/"
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_app_owner_can_access_roles_for_their_app(self):
        """App owner should be able to access roles for their application."""
        self.client.force_authenticate(user=self.app_owner)

        response = self.client.get(
            f"{API_BASE}/user-roles/{self.user1_role_owned_app.id}/"
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_app_owner_cannot_access_roles_for_other_apps(self):
        """App owner should NOT be able to access roles for other applications."""
        self.client.force_authenticate(user=self.app_owner)

        response = self.client.get(
            f"{API_BASE}/user-roles/{self.user2_role_other_app.id}/"
        )
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_user_can_access_own_role(self):
        """User should be able to access their own role."""
        self.client.force_authenticate(user=self.user1)

        response = self.client.get(
            f"{API_BASE}/user-roles/{self.user1_role_owned_app.id}/"
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_user_cannot_access_other_user_role(self):
        """User should NOT be able to access another user's role."""
        self.client.force_authenticate(user=self.user1)

        response = self.client.get(
            f"{API_BASE}/user-roles/{self.user2_role_other_app.id}/"
        )
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_user_cannot_update_other_user_role(self):
        """User should NOT be able to update another user's role."""
        self.client.force_authenticate(user=self.user1)

        response = self.client.patch(
            f"{API_BASE}/user-roles/{self.user2_role_other_app.id}/",
            {"role": "admin"},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_user_cannot_delete_other_user_role(self):
        """User should NOT be able to delete another user's role."""
        self.client.force_authenticate(user=self.user1)

        response = self.client.delete(
            f"{API_BASE}/user-roles/{self.user2_role_other_app.id}/"
        )
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)


class UserRoleCreationTests(TestCase):
    """Test UserRoleListCreateView ownership validation on creation."""

    def setUp(self):
        """Create test users and applications."""
        # Create SSO admin
        self.admin_user = User.objects.create_user(
            email="admin@barge2rail.com",
            username="admin@barge2rail.com",
            password="adminpass123",  # pragma: allowlist secret
        )
        self.admin_user.is_sso_admin = True
        self.admin_user.save()

        # Create app owner
        self.app_owner = User.objects.create_user(
            email="owner@example.com",
            username="owner@example.com",
            password="ownerpass123",  # pragma: allowlist secret
        )

        # Create target user (who will be assigned roles)
        self.target_user = User.objects.create_user(
            email="target@example.com",
            username="target@example.com",
            password="targetpass123",  # pragma: allowlist secret
        )

        # Create attacker user
        self.attacker = User.objects.create_user(
            email="attacker@evil.com",
            username="attacker@evil.com",
            password="attackerpass123",  # pragma: allowlist secret
        )

        # Create application owned by app_owner
        self.owned_app = Application.objects.create(
            name="Owner's App",
            slug="owner-app",
            user=self.app_owner,
        )

        # Create another application
        self.other_app = Application.objects.create(
            name="Other App",
            slug="other-app",
            user=None,
        )

        self.client = APIClient()

    def test_admin_can_create_role_for_any_app(self):
        """SSO admin should be able to create roles for any application."""
        self.client.force_authenticate(user=self.admin_user)

        response = self.client.post(
            f"{API_BASE}/user-roles/",
            {
                "user": str(self.target_user.id),
                "application": str(self.owned_app.id),
                "role": "user",
            },
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

    def test_app_owner_can_create_role_for_their_app(self):
        """App owner should be able to create roles for their application."""
        self.client.force_authenticate(user=self.app_owner)

        response = self.client.post(
            f"{API_BASE}/user-roles/",
            {
                "user": str(self.target_user.id),
                "application": str(self.owned_app.id),
                "role": "user",
            },
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

    def test_app_owner_cannot_create_role_for_other_app(self):
        """App owner should NOT be able to create roles for other applications."""
        self.client.force_authenticate(user=self.app_owner)

        response = self.client.post(
            f"{API_BASE}/user-roles/",
            {
                "user": str(self.target_user.id),
                "application": str(self.other_app.id),
                "role": "admin",  # Trying to escalate privileges
            },
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_attacker_cannot_create_role_for_other_user(self):
        """Attacker should NOT be able to create roles for other users in apps they don't own."""
        self.client.force_authenticate(user=self.attacker)

        response = self.client.post(
            f"{API_BASE}/user-roles/",
            {
                "user": str(self.target_user.id),
                "application": str(self.owned_app.id),
                "role": "admin",
            },
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_user_can_create_role_for_themselves(self):
        """User should be able to create a role for themselves."""
        self.client.force_authenticate(user=self.target_user)

        response = self.client.post(
            f"{API_BASE}/user-roles/",
            {
                "user": str(self.target_user.id),
                "application": str(self.other_app.id),
                "role": "user",
            },
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)


class ApplicationListFilteringTests(TestCase):
    """Test ApplicationListCreateView returns only authorized applications."""

    def setUp(self):
        """Create test users and applications."""
        # Create SSO admin
        self.admin_user = User.objects.create_user(
            email="admin@barge2rail.com",
            username="admin@barge2rail.com",
            password="adminpass123",  # pragma: allowlist secret
        )
        self.admin_user.is_sso_admin = True
        self.admin_user.save()

        # Create app owner
        self.app_owner = User.objects.create_user(
            email="owner@example.com",
            username="owner@example.com",
            password="ownerpass123",  # pragma: allowlist secret
        )

        # Create other user with a role
        self.user_with_role = User.objects.create_user(
            email="withrole@example.com",
            username="withrole@example.com",
            password="withrolepass123",  # pragma: allowlist secret
        )

        # Create user without any roles
        self.user_without_role = User.objects.create_user(
            email="norole@example.com",
            username="norole@example.com",
            password="norolepass123",  # pragma: allowlist secret
        )

        # Create applications
        self.app1 = Application.objects.create(
            name="App 1",
            slug="app-1",
            user=self.app_owner,
        )

        self.app2 = Application.objects.create(
            name="App 2",
            slug="app-2",
            user=None,
        )

        self.app3 = Application.objects.create(
            name="App 3",
            slug="app-3",
            user=None,
        )

        # Give user_with_role a role in app2
        ApplicationRole.objects.create(
            user=self.user_with_role,
            application=self.app2,
            role="Client",
        )

        self.client = APIClient()

    def test_admin_sees_all_applications(self):
        """SSO admin should see all applications."""
        self.client.force_authenticate(user=self.admin_user)

        response = self.client.get(f"{API_BASE}/applications/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        app_names = [app["name"] for app in response.data]
        self.assertIn("App 1", app_names)
        self.assertIn("App 2", app_names)
        self.assertIn("App 3", app_names)

    def test_owner_sees_only_owned_apps(self):
        """App owner should only see applications they own."""
        self.client.force_authenticate(user=self.app_owner)

        response = self.client.get(f"{API_BASE}/applications/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        app_names = [app["name"] for app in response.data]
        self.assertIn("App 1", app_names)
        self.assertNotIn("App 2", app_names)
        self.assertNotIn("App 3", app_names)

    def test_user_with_role_sees_apps_with_roles(self):
        """User with role should see applications where they have roles."""
        self.client.force_authenticate(user=self.user_with_role)

        response = self.client.get(f"{API_BASE}/applications/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        app_names = [app["name"] for app in response.data]
        self.assertIn("App 2", app_names)
        self.assertNotIn("App 1", app_names)
        self.assertNotIn("App 3", app_names)

    def test_user_without_role_sees_nothing(self):
        """User without any roles should see no applications."""
        self.client.force_authenticate(user=self.user_without_role)

        response = self.client.get(f"{API_BASE}/applications/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        self.assertEqual(len(response.data), 0)

    def test_newly_created_app_associated_with_creator(self):
        """Newly created application should be associated with creating user."""
        self.client.force_authenticate(user=self.app_owner)

        response = self.client.post(
            f"{API_BASE}/applications/",
            {"name": "New App", "slug": "new-app"},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        # Verify app is associated with creator
        new_app = Application.objects.get(slug="new-app")
        self.assertEqual(new_app.user, self.app_owner)


try:
    # Only run OIDC tests if the module is available
    from oauth2_provider.contrib.oidc.claims import ScopeClaims  # noqa: F401

    OIDC_AVAILABLE = True
except ImportError:
    OIDC_AVAILABLE = False


class OIDCClaimsIsolationTests(TestCase):
    """Test OIDC claims only return roles for requesting application."""

    def setUp(self):
        """Create test users, applications, and roles."""
        if not OIDC_AVAILABLE:
            self.skipTest("oauth2_provider.contrib.oidc not available")

        self.user = User.objects.create_user(
            email="user@example.com",
            username="user@example.com",
            password="userpass123",  # pragma: allowlist secret
        )

        # Create two applications
        self.app1 = Application.objects.create(
            name="App 1",
            slug="app-1",
        )

        self.app2 = Application.objects.create(
            name="App 2",
            slug="app-2",
        )

        # User has Admin role in app1, Client role in app2
        self.role1 = ApplicationRole.objects.create(
            user=self.user,
            application=self.app1,
            role="Admin",
        )

        self.role2 = ApplicationRole.objects.create(
            user=self.user,
            application=self.app2,
            role="Client",
        )

    def test_oidc_claims_filter_by_application(self):
        """OIDC claims should only include roles for the requesting application."""
        if not OIDC_AVAILABLE:
            self.skipTest("oauth2_provider.contrib.oidc not available")

        from sso.oidc_claims import CustomScopeClaims

        # Mock the request/token context
        class MockRequest:
            def __init__(self, app):
                self.client = app

        # Test with app1 as requesting application
        claims_provider = CustomScopeClaims(
            user=self.user, request=MockRequest(self.app1)
        )
        claims = claims_provider.scope_profile()

        app_roles = claims.get("application_roles", {})

        # Should only have app1's role
        self.assertIn("app-1", app_roles)
        self.assertNotIn("app-2", app_roles)
        self.assertEqual(app_roles["app-1"]["role"], "Admin")

    def test_oidc_claims_different_app_different_roles(self):
        """Requesting from app2 should only show app2's role."""
        if not OIDC_AVAILABLE:
            self.skipTest("oauth2_provider.contrib.oidc not available")

        from sso.oidc_claims import CustomScopeClaims

        class MockRequest:
            def __init__(self, app):
                self.client = app

        # Test with app2 as requesting application
        claims_provider = CustomScopeClaims(
            user=self.user, request=MockRequest(self.app2)
        )
        claims = claims_provider.scope_profile()

        app_roles = claims.get("application_roles", {})

        # Should only have app2's role
        self.assertIn("app-2", app_roles)
        self.assertNotIn("app-1", app_roles)
        self.assertEqual(app_roles["app-2"]["role"], "Client")

    def test_oidc_claims_no_app_context_returns_empty(self):
        """Without application context, should return empty roles."""
        if not OIDC_AVAILABLE:
            self.skipTest("oauth2_provider.contrib.oidc not available")

        from sso.oidc_claims import CustomScopeClaims

        # Test with no request context
        claims_provider = CustomScopeClaims(user=self.user, request=None)
        claims = claims_provider.scope_profile()

        app_roles = claims.get("application_roles", {})

        # Should be empty - no roles leaked
        self.assertEqual(app_roles, {})
