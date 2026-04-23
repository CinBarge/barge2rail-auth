# Tenant Onboarding Runbook

Operational guide for provisioning a new tenant on `sso.barge2rail.com` using
the `provision_tenant` management command.

## v3 BREAKING CHANGE (April 2026)

The YAML schema no longer accepts a top-level `roles:` block. Roles must
already exist on the target Application before provisioning. Reference them
via each user's `role_code` field. Old v2 YAMLs containing `roles:` are
rejected with a v3-specific error message — rewrite them per the worked
examples below.

Per-user `role:` was renamed to `role_code:` to make the bind-to-existing
semantics explicit at the call site.

If you need a Role that doesn't exist yet on the target Application, create
it via `/cbrt-ops/` admin or the `setup_rbac` management command first.
`provision_tenant` is intentionally narrow: identity bindings only, no RBAC
schema mutations.

## What this command does — and doesn't

**Does:** creates the Tenant reference row, creates Users, and binds those
users to **existing** Roles via `UserAppRole` rows scoped by `tenant_code`.
Idempotent and transactional.

**Doesn't:** create OAuth Applications, Roles, Features, or
RoleFeaturePermissions. Register a new client app via `/cbrt-ops/`
(Django admin) first. Create new Roles via admin or the `setup_rbac`
management command.

Concretely: for a new MSP tenant on CBRTConnect, you do **not** create a new
"CBRTConnect - MSP" Application or new MSP-specific Roles. CBRTConnect uses
shared roles (`sacks_client`, `sacks_office`, `sacks_admin`) on the existing
`sacks` Application. Onboarding MSP means adding `UserAppRole` rows that bind
MSP users to those existing roles, with `tenant_code: MSP`.

Why the architecture works this way: CBRTConnect (and every other client app)
authenticates against one OAuth Application. The JWT only surfaces roles
bound to that Application. Per-tenant role copies would have zero
RoleFeaturePermissions and the user would log in and see nothing.

## Prerequisites

1. **The target OAuth Application already exists** in SSO. Check with:
   ```bash
   python manage.py shell -c "from sso.models import Application; print(list(Application.objects.values_list('slug', 'name')))"
   ```
   Current production slugs (as of April 2026): `sacks` (CBRTConnect),
   `primetrade`, `yifan`, `senco`, `cams`, `planner`, `cbrtconnect-dev`.
2. **The Roles you'll reference already exist** on that Application. Check with:
   ```bash
   python manage.py shell -c "from sso.models import Role; print(sorted(Role.objects.filter(application__slug='sacks').values_list('code', flat=True)))"
   ```
3. **You must have an SSO user** at `sso.barge2rail.com`. The command records
   you as `--actor` on every UserAppRole. If no user with your email exists,
   the command fails with a message telling you to create one via `/cbrt-ops/`.
4. **Repo checkout + activated venv**:
   `cd ~/Projects/barge2rail-auth && source venv/bin/activate`.
5. **Database access** for the environment you're provisioning against
   (usually dev first, then prod via `git push origin main` + remote shell).

## Step 1 — Fill in the YAML

Copy the template:

```bash
cp tenants/_template.yaml tenants/msp.yaml   # replace msp with the tenant_code
```

Edit `tenants/msp.yaml`:

- `tenant_code`: short uppercase code (1-10 chars). Must be unique across tenants.
- `display_name`: full tenant name (used for the `Tenant` reference row).
- `application_slug`: slug of the **existing** OAuth Application to bind to.
  For CBRTConnect tenants use `sacks`. For PrimeTrade tenants use `primetrade`.
- `users`: one entry per (user, role) binding. A user with multiple roles gets
  multiple entries. **Emails are normalized to lowercase** before any DB
  interaction — `Bjackson@domain.com` and `bjackson@domain.com` are treated as
  the same user, and the row is stored as `bjackson@domain.com`. If the DB
  already contains two rows that differ only by case (legacy data), the
  command refuses to run and tells you to deduplicate in `/cbrt-ops/` first.
  Each user has:
  - `role_code` — must match an **existing** `Role.code` on the target
    Application. Validation lists the existing role codes if yours doesn't
    match, so the fix is obvious.
  - `auth_type`:
    - `email` (default) — user will have an email + temp password. Use for
      tenant clients who are **not** on Google Workspace
      (e.g. `@marianshipping.com`). The command generates a 24-char
      cryptographic password per user and prints it once in the banner at
      end of run. Distribute privately; the user then changes it at
      `https://sso.barge2rail.com/change-password/` on first login.
    - `google` — user will sign in via Google OAuth. No password is stored.
      Use for `@barge2rail.com` staff.
    - `anonymous` — not supported by `provision_tenant`. Create via
      `/cbrt-ops/`.

**Do not commit the filled-in YAML.** `tenants/.gitignore` blocks everything except
`_template.yaml`. Keep the filled YAML locally or in 1Password — it contains user PII.

## Step 2 — Dry-run

```bash
python manage.py provision_tenant --config tenants/msp.yaml --dry-run
```

Expected output: a plan header naming the resolved Application, then `CREATE`
or `SKIP (exists)` lines for the Tenant, each User, and each UserAppRole
binding. Nothing is written to the database.

Common failures at this stage:

- **`No OAuth Application exists with slug 'X'. Existing slugs: ...`** — the
  `application_slug` in the YAML doesn't match any registered Application.
  The error lists the slugs that do exist; pick one, or register a new
  OAuth Application in `/cbrt-ops/` first if this is truly a new client app.
- **`One or more role_code values do not match any Role on Application slug='X': ...`** —
  one or more users reference a `role_code` that doesn't exist on the target
  Application. The error lists every offending user and the existing role
  codes you can choose from, so you can fix all of them before the next
  attempt instead of one at a time.
- **`'roles:' is no longer supported in provision_tenant YAML as of v3 ...`** —
  the YAML still uses the v2 schema. Remove the top-level `roles:` block and
  reference existing Role codes via each user's `role_code` field. See worked
  examples below.
- Validation errors (missing field, bad email, unknown YAML key) — each is
  reported with a specific field path. Fix the YAML and re-run.

## Step 3 — Real run

```bash
python manage.py provision_tenant \
  --config tenants/msp.yaml \
  --actor you@barge2rail.com
```

If successful, the command:

1. Writes all records in a single transaction.
2. Appends one JSON line to `logs/tenant_provisioning.jsonl` (no secrets).
3. If any `auth_type: email` users were created, prints a one-time credentials
   banner to stdout:

   ```
   ================================================================
   COPY THIS NOW - IT WILL NOT BE SHOWN AGAIN
   Email/password users bound to Application slug='sacks' (temp passwords - distribute privately):
   ================================================================
     briana@marianshipping.example.com   <24-char password>
   ================================================================
   ```

These temp passwords are stored hashed (Django `set_password()`), never written
to `logs/tenant_provisioning.jsonl`, and cannot be recovered — only reset via
the password-reset flow. **Distribute via 1Password share or another
end-to-end-encrypted channel; never Slack/email plaintext.**

Note: because this command doesn't create OAuth Applications, there is no
`client_secret` banner. If you need the existing app's secret, fetch it from
`/cbrt-ops/` or Coolify env vars.

## What to tell email/password users after provisioning

Send each email user:

1. Their login URL: `https://sso.barge2rail.com/`
2. Their email (the login identifier).
3. Their one-time temp password (via 1Password share, Signal, or in person).
4. Instructions: "On first login you'll land on the dashboard. Go to
   `https://sso.barge2rail.com/change-password/` and set your own password.
   If you forget it later, use `https://sso.barge2rail.com/forgot-password/`
   to request a reset email."

## Step 4 — Clean up

- **Filled YAML** → 1Password attachment, or a private local directory outside
  the repo. Do not email, Slack, or Drive it.

## Idempotency

Re-running the same YAML is safe. Existing rows are reported as
`SKIP (exists)`. The command exits 0 and still appends an audit line
(`bindings_created: 0` for a full no-op).

On re-run, existing email users are SKIP'd and no temp password is printed.
If a user lost theirs, they use `/forgot-password/` (or an admin resets via
`/cbrt-ops/`).

### auth_type mismatch

If a user email already exists in the DB with a different `auth_type` than
the YAML specifies, the command prints an `auth_type mismatch` warning on
the SKIP line (e.g. `yaml=email, db=google`) and **does not modify** the
existing user. This is informational — investigate whether the YAML or the
existing row is wrong; fix via `/cbrt-ops/` if the DB record should change.

### Tenant display_name mismatch

If a Tenant row already exists for the `tenant_code` with a different
`display_name`, the command prints a warning at the top of the plan and
**does not overwrite** the existing row. Reconcile via `/cbrt-ops/` if the
existing display name is wrong.

## If something goes wrong

- **`No OAuth Application exists with slug 'X'`**: register the Application
  in `/cbrt-ops/` first (or fix the slug in the YAML to match an existing one).
- **`One or more role_code values do not match any Role`**: create the missing
  Roles on the target Application via admin or `setup_rbac` first, then
  re-run. The error lists every missing code and every existing code so you
  can fix them all in one pass.
- **`'roles:' is no longer supported ... as of v3`**: rewrite the YAML to the
  v3 schema (no top-level `roles:`, per-user `role_code:` referencing existing
  Role codes). See worked examples below.
- **Validation error**: YAML field path is in the error message. Fix and re-run
  dry-run.
- **`Actor '<email>' has no SSO user`**: Create yourself via `/cbrt-ops/` first,
  then re-run.
- **Mid-transaction failure**: nothing is written (transactional). Fix the
  underlying cause (usually a DB constraint or a migration mismatch) and re-run.
- **Wrong bindings got created**: the command prints `application_slug` and
  user emails in the audit line. Open `/cbrt-ops/` and delete the
  UserAppRoles, Users, and Tenant manually. Leave the OAuth Application and
  Roles intact — this command never created them.

## Audit log

`logs/tenant_provisioning.jsonl` — one line per real run (dry-runs are NOT appended).
Each line: `ts`, `actor`, `tenant_code`, `application_id`, `application_name`,
`application_slug`, `users_created`, `bindings_created`, `dry_run`. Explicitly
contains no `client_secret`, no email/password user temp passwords, and no
`roles_created` (the v3 command doesn't create Roles).

Review with:

```bash
cat logs/tenant_provisioning.jsonl | jq .
```

## Verification checklist (post-run)

1. `/cbrt-ops/` → Applications → the target Application exists (unchanged).
2. `/cbrt-ops/` → Roles → existing Roles on that Application are unchanged
   (this command doesn't create or modify Roles).
3. `/cbrt-ops/` → Users → each YAML user exists with correct name and the
   `auth_type` specified in the YAML (`email` or `google`). Email users have
   a usable password; Google users do not.
4. `/cbrt-ops/` → UserAppRoles → each (user, role, tenant_code) binding is
   present, `is_active`, and the role belongs to the target Application.
5. `/cbrt-ops/` → Tenants → tenant row exists with correct code and display name.
6. For an email/password user: sign in at `https://sso.barge2rail.com/` with
   the temp password; confirm the change-password page is reachable at
   `/change-password/`.
7. For a CBRTConnect login: log in to CBRTConnect; the JWT should include
   `application_roles.<application_slug>.tenant_code == "<TENANT_CODE>"` and
   `application_roles.<application_slug>.role == "<legacy_role of the bound Role>"`.
8. For an existing Role with provisioned RoleFeaturePermissions, the user's
   "Effective Permissions" view in `/cbrt-ops/` should show the same
   permissions as any other user bound to the same Role on a different tenant.

## Worked examples

### Onboarding a new tenant on CBRTConnect (v3)

```yaml
tenant_code: MSP
display_name: "Marian Shipping Partners"
application_slug: sacks
users:
  - email: bjackson@marianshipping.com
    first_name: Briana
    last_name: Jackson
    role_code: sacks_client
    auth_type: email
```

This binds Briana to the existing `sacks_client` Role with `tenant_code='MSP'`,
giving her exactly the same effective permissions as a `sacks_client` user on
any other CBRTConnect tenant (MTLO, TRX, URC, HLR, ...).

### Onboarding a new tenant on PrimeTrade (v3)

```yaml
tenant_code: ACME
display_name: "Acme Trading Co."
application_slug: primetrade
users:
  - email: ops@acme.example.com
    first_name: Jane
    last_name: Ops
    role_code: primetrade_client
    auth_type: email
```

Confirm the actual `role_code` values on the `primetrade` Application before
using this literally; the command will tell you the existing codes if yours
doesn't match.

## Migration from v2

If you have a v2 YAML in 1Password or local-only file storage:

1. Delete the entire top-level `roles:` block.
2. For each user entry, rename `role:` → `role_code:`. Set its value to an
   **existing** Role code on the target Application (use the shell command in
   "Prerequisites" step 2 to list them).
3. Dry-run. If `role_code` doesn't match any existing Role, the command will
   tell you which codes are valid; create any genuinely-needed missing Roles
   via admin or `setup_rbac` before retrying.

## Related Docs

- Parent patterns: `../CLAUDE.md`
- PrimeTrade integration: `../django-primetrade/CLAUDE.md`
