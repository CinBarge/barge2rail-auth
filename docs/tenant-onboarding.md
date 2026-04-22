# Tenant Onboarding Runbook

Operational guide for provisioning a new tenant on `sso.barge2rail.com` using
the `provision_tenant` management command.

## What this command does — and doesn't

**Does:** creates tenant-scoped Roles on an **existing** OAuth Application,
creates Users, binds users to those Roles via `UserAppRole` rows scoped by
`tenant_code`. Idempotent and transactional.

**Doesn't:** create OAuth Applications. Register a new client app via
`/cbrt-ops/` (Django admin) first — that flow requires decisions about
redirect URIs, client type, and allowed scopes that belong in the UI.

Concretely: for a new MSP tenant on CBRTConnect, you do **not** create
"CBRTConnect - MSP" as a new Application. You bind MSP-scoped roles to the
existing `sacks` Application (CBRTConnect's OAuth app) using
`application_slug: sacks` in the YAML.

Why: CBRTConnect authenticates against one OAuth Application (slug `sacks`).
When a user logs in, the JWT only surfaces roles bound to that Application.
A role bound to a separate `msp` Application is invisible to CBRTConnect
and login will 403.

## Prerequisites

1. **The target OAuth Application already exists** in SSO. Check with:
   ```bash
   python manage.py shell -c "from sso.models import Application; print(list(Application.objects.values_list('slug', 'name')))"
   ```
   Current production slugs (as of April 2026): `sacks` (CBRTConnect),
   `primetrade`, `yifan`, `senco`, `cams`, `planner`, `cbrtconnect-dev`.
2. **You must have an SSO user** at `sso.barge2rail.com`. The command records
   you as `--actor` on every UserAppRole. If no user with your email exists,
   the command fails with a message telling you to create one via `/cbrt-ops/`.
3. **Repo checkout + activated venv**:
   `cd ~/Projects/barge2rail-auth && source venv/bin/activate`.
4. **Database access** for the environment you're provisioning against
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
  Get the list via the shell command above.
- `roles`: the roles this tenant will use. Convention is
  `<app_slug>_<tenant_code_lower>_<role>` (e.g. `sacks_msp_admin`).
  `legacy_role` is what client apps read from the JWT
  (`application_roles.<slug>.role`); use `Admin` / `Office` / `Client`
  to match CBRTConnect's expectations unless you know otherwise.
- `users`: one entry per (user, role) binding. A user with multiple roles gets
  multiple entries. **Emails are normalized to lowercase** before any DB
  interaction — `Bjackson@domain.com` and `bjackson@domain.com` are treated as
  the same user, and the row is stored as `bjackson@domain.com`. If the DB
  already contains two rows that differ only by case (legacy data), the
  command refuses to run and tells you to deduplicate in `/cbrt-ops/` first.
  Each user has an `auth_type`:
  - `email` (default) — user will have an email + temp password. Use for tenant
    clients who are **not** on Google Workspace (e.g. `@marianshipping.com`).
    The command generates a 24-char cryptographic password per user and prints
    it once in the banner at end of run. Distribute privately; the user then
    changes it at `https://sso.barge2rail.com/change-password/` on first login.
  - `google` — user will sign in via Google OAuth. No password is stored. Use
    for `@barge2rail.com` staff.
  - `anonymous` — not supported by `provision_tenant`. Create via `/cbrt-ops/`.

**Do not commit the filled-in YAML.** `tenants/.gitignore` blocks everything except
`_template.yaml`. Keep the filled YAML locally or in 1Password — it contains user PII.

## Step 2 — Dry-run

```bash
python manage.py provision_tenant --config tenants/msp.yaml --dry-run
```

Expected output: a plan header naming the resolved Application, then `CREATE`
or `SKIP (exists)` lines for the Tenant, each Role, each User, and each
UserAppRole binding. Nothing is written to the database.

Common failures at this stage:

- **`No OAuth Application exists with slug 'X'. Existing slugs: ...`** — the
  `application_slug` in the YAML doesn't match any registered Application.
  The error lists the slugs that do exist; pick one, or register a new
  OAuth Application in `/cbrt-ops/` first if this is truly a new client app.
- Validation errors (missing field, bad email, unknown role reference) —
  each is reported with a specific field path. Fix the YAML and re-run.

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

## If something goes wrong

- **`No OAuth Application exists with slug 'X'`**: register the Application
  in `/cbrt-ops/` first (or fix the slug in the YAML to match an existing one).
- **Validation error**: YAML field path is in the error message. Fix and re-run
  dry-run.
- **`Actor '<email>' has no SSO user`**: Create yourself via `/cbrt-ops/` first,
  then re-run.
- **Mid-transaction failure**: nothing is written (transactional). Fix the
  underlying cause (usually a DB constraint or a migration mismatch) and re-run.
- **Wrong roles got created**: the command prints `application_slug`, role
  codes, and user emails in the audit line. Open `/cbrt-ops/` and delete the
  Roles, UserAppRoles, Users, and Tenant manually. Leave the OAuth Application
  intact — this command never created it.

## Audit log

`logs/tenant_provisioning.jsonl` — one line per real run (dry-runs are NOT appended).
Each line: `ts`, `actor`, `tenant_code`, `application_id`, `application_name`,
`application_slug`, `roles_created`, `users_created`, `bindings_created`,
`dry_run`. Explicitly contains no `client_secret` and no email/password user
temp passwords.

Review with:

```bash
cat logs/tenant_provisioning.jsonl | jq .
```

## Verification checklist (post-run)

1. `/cbrt-ops/` → Applications → the target Application exists (unchanged).
2. `/cbrt-ops/` → Roles → new Roles are attached to the target Application,
   with correct `code`, `name`, `legacy_role`.
3. `/cbrt-ops/` → Users → each YAML user exists with correct name and the
   `auth_type` specified in the YAML (`email` or `google`). Email users have
   a usable password; Google users do not.
4. `/cbrt-ops/` → UserAppRoles → each (user, role, tenant_code) binding is
   present, `is_active`, and the role belongs to the target Application.
5. `/cbrt-ops/` → Tenants → tenant row exists with correct code and display name.
6. For an email/password user: sign in at `https://sso.barge2rail.com/` with
   the temp password; confirm the change-password page is reachable at
   `/change-password/`.
7. For a Google user: log in to the client app (e.g. CBRTConnect) via Google;
   the JWT should include `application_roles.<application_slug>.tenant_code == "<TENANT_CODE>"`
   and `application_roles.<application_slug>.role == "<legacy_role>"`.

## Worked examples

### Onboarding a new tenant on CBRTConnect

```yaml
tenant_code: MSP
display_name: "Marian Shipping Partners"
application_slug: sacks
roles:
  - code: sacks_msp_admin
    name: "Sacks MSP Admin"
    legacy_role: Admin
  - code: sacks_msp_office
    name: "Sacks MSP Office"
    legacy_role: Office
  - code: sacks_msp_client
    name: "Sacks MSP Client"
    legacy_role: Client
users:
  - email: bjackson@marianshipping.com
    first_name: Briana
    last_name: Jackson
    role: sacks_msp_client
```

### Onboarding a new tenant on PrimeTrade

```yaml
tenant_code: ACME
display_name: "Acme Trading Co."
application_slug: primetrade
roles:
  - code: primetrade_acme_admin
    name: "PrimeTrade Acme Admin"
    legacy_role: Admin
users:
  - email: ops@acme.example.com
    first_name: Jane
    last_name: Ops
    role: primetrade_acme_admin
    auth_type: email
```

## Related Docs

- Parent patterns: `../CLAUDE.md`
- PrimeTrade integration: `../django-primetrade/CLAUDE.md`
