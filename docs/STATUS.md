# barge2rail-auth — Project Status Report

Updated: 2025-10-31

## Executive summary
- Current: Live SSO/OIDC server for Barge2Rail apps (Django 4.2, DRF, django-oauth-toolkit, SimpleJWT). Supports Google OAuth, email/password, and anonymous PIN login; issues JWTs; exposes OAuth2 provider endpoints; includes admin OAuth for Django Admin; rate limiting, CSRF, secure session/cookie settings, CORS, health checks, and comprehensive logs.
- Stability: Production-ready and deployed (Render, Docker). Test suite present (README cites ~74% coverage). Multiple security hardening gates and docs included.
- Hot issues: Repo contains credentials.json/token.json (review/remove if secrets). requirements.txt duplicates django-oauth-toolkit. Two parallel OAuth view modules (auth_views.py and oauth_views.py) with overlapping logic—consider consolidating. Large vendored staticfiles inflate repo size.
- Immediate next steps: Secret hygiene (purge committed secrets, rotate), confirm OIDC RSA key configured, dedupe deps, consolidate OAuth views, prune staticfiles from VCS.

## Where we are (functional scope)
- Authentication flows
  - Google OAuth 2.0 sign-in with state/CSRF protection, code exchange, ID token verification, role loading, and optional admin login handoff.
  - Email/password login + registration.
  - Anonymous account creation and login (generated username + 12-digit PIN), JWT issuance with advisory message to save credentials.
- Tokens and sessions
  - JWTs via SimpleJWT (15m access, 7d refresh, rotation + blacklist). Token refresh/validate endpoints. RefreshToken model for tracking/rotation (SSO scope).
  - TokenExchangeSession for secure two-step exchange (UUID session_id, 60s expiry, single-use) to avoid exposing tokens in URLs.
  - LoginAttempt model for lockouts and security analytics; session hardening (short lifetimes, secure flags, SameSite handling for OAuth).
- OAuth2/OIDC provider
  - django-oauth-toolkit with custom Application model (UUID PK, slug, RS256 by default), OIDC claims, RS256 support via OIDC_RSA_PRIVATE_KEY, scopes (openid, profile, email, roles), configurable redirect URIs, trusted-app skip screen.
  - AuthorizationCode model (10m expiry, single-use), PKCE optional.
- Admin OAuth
  - Dedicated admin_oauth views; OAuthBackend integrates Google tokens into Django auth; admin whitelist + superuser whitelist support; permission assignment helpers.
- APIs and utilities
  - /api/auth endpoints: login, logout, refresh, validate, health, profile; Google config debug; SSO validation authentication class for downstream services.
  - Health and secure echo endpoints; CORS configured for prod and dev; rate limiting enabled in prod via cache.
- Ops
  - Dockerfile + docker-compose; WhiteNoise static; rotating file logs; environment validation for SECRET_KEY, ALLOWED_HOSTS, CSRF_TRUSTED_ORIGINS.

## Plans
- Immediate (today)
  - Secret hygiene: remove credentials.json and token.json from repo, rotate any exposed keys, add to .gitignore, scrub history if needed.
  - Verify OIDC RSA key configured (settings.OAUTH2_PROVIDER["OIDC_RSA_PRIVATE_KEY"]) in prod; confirm RS256 signing works end-to-end for ID tokens.
  - requirements.txt: remove duplicate django-oauth-toolkit line.
  - Consolidate sso/auth_views.py and sso/oauth_views.py to a single implementation; remove dead code/duplication.
  - Prune vendored staticfiles/ and rest_framework assets from VCS (use collectstatic at deploy) to reduce repo size.
- Short term (1–2 weeks)
  - Expand tests for admin OAuth flow, rate limiting, lockout edge cases, and token exchange session reuse/expiry. Add security regression tests.
  - Add admin UI for Application management and UserRole/ApplicationRole assignment; import/export roles.
  - Observability: structured JSON logs, request IDs, and alerting on auth anomalies.
  - Harden CORS/CSRF configs per environment and document operational runbooks.
- Later
  - Add optional providers (Okta/Azure AD) via python-social-auth or custom; add WebAuthn passkeys for privileged users; SAML bridge if needed.
  - Multi-tenant org model and delegated admin; audit log streaming endpoint.

## Current schema (key models and constraints)
- sso.User (custom, UUID PK)
  - email (unique, nullable for anonymous), phone, display_name, is_sso_admin, auth_type {email, google, anonymous}, auth_method {google, password}, google_id (unique), anonymous_username (unique), pin_code, is_anonymous; USERNAME_FIELD=email.
- sso.Application (extends DOT AbstractApplication)
  - id (UUID PK), slug (unique), name (unique), client_id (unique), client_secret, client_type, grant_type, redirect_uris, skip_authorization, algorithm default RS256, description, is_active, FK user (creator). Auto-generates client_id/secret.
- sso.AuthorizationCode
  - id (UUID), code (unique, indexed), FK user, FK application, redirect_uri, scope, state, created_at, expires_at, used; index (code, used).
- sso.UserRole
  - id (UUID), FK user, FK application, role {admin, manager, user, viewer}, permissions (JSON), created/updated; unique_together (user, application).
- sso.ApplicationRole
  - FK user, application {primetrade, database, repair, barge, admin}, role {admin, user, viewer, operator}, permissions (JSON), assigned_date, notes; unique_together (user, application).
- sso.RefreshToken
  - id (UUID), FK user, FK application, token (unique), expires_at, created_at.
- sso.TokenExchangeSession
  - session_id (UUID PK), access_token, refresh_token, user_email, created_at, expires_at, used; index (expires_at, used); is_valid() helper.
- sso.LoginAttempt
  - identifier (indexed), ip_address, attempted_at, success; indexes on (identifier, attempted_at) and (ip_address, attempted_at).
- common.SSOValidationAuthentication (DRF auth class)
  - Forwards Bearer token to SSO_VALIDATION_URL and returns lightweight user/roles.

## Current file list (project tree)
```
core/
  settings.py, urls.py, views.py, wsgi.py, asgi.py
sso/
  models.py, urls.py, auth_views.py, oauth_views.py, admin_oauth_views.py,
  backends.py, middleware.py, oauth_validators.py, oidc_claims.py,
  serializers.py, tokens.py, utils.py, utils/permissions.py, utils/session.py,
  management/commands/*.py, templates/{admin/login.html,sso/login.html}, tests/*
common/
  auth.py, permissions.py
dashboard/  (app shell + templates for demo/admin UI)
user/       (legacy/simple user app with forms and templates)
utilities/  (googlesheet, pdf_extractor)
templates/  (dashboard and login pages)
static/     (project static)
staticfiles/ and rest_framework/ (vendored/compiled assets — candidates to prune)
CincyBarge_Development/ (separate Django project, likely legacy/dev)
manage.py, docker-compose.yml, Dockerfile, requirements.txt
security-audit/ (security gate docs), ci/context_lint.py
tests/test_health_secure.py
```

## Notes and risks
- Secret handling: credentials.json/token.json exist in repo. Remove from VCS, rotate secrets, and scrub history if sensitive.
- Dependency hygiene: duplicate django-oauth-toolkit entry in requirements.txt; pin versions consistently; review for CVEs.
- View duplication: sso/auth_views.py and sso/oauth_views.py implement similar Google flows; consolidate to reduce drift.
- Repo size: large staticfiles/rest_framework assets; rely on collectstatic in CI/CD instead of committing.
- Configuration: ensure ALLOWED_HOSTS/CSRF_TRUSTED_ORIGINS set for prod; verify OIDC_RSA_PRIVATE_KEY present for RS256.
