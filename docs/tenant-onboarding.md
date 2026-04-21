# Tenant Onboarding Runbook

Operational guide for provisioning a new tenant on `sso.barge2rail.com` using
the `provision_tenant` management command.

This replaces the ~20-click flow through `/cbrt-ops/` (Django admin) with a
single YAML-driven command. Review the YAML, dry-run, run for real, capture the
`client_secret`. Done.

## Prerequisites

1. **You must have an SSO user** at `sso.barge2rail.com`. The command records
   you as the `--actor` on the Application and every UserAppRole. If no user
   with your email exists, the command fails with a message telling you to
   create one via `/cbrt-ops/` first.
2. **Repo checkout + activated venv**: `cd ~/Projects/barge2rail-auth && source venv/bin/activate`.
3. **Database access** for the environment you're provisioning against
   (usually dev first, then prod via `git push origin main` + remote shell).

## Step 1 — Fill in the YAML

Copy the template:

```bash
cp tenants/_template.yaml tenants/msp.yaml   # replace msp with the tenant_code
```

Edit `tenants/msp.yaml`:

- `tenant_code`: short uppercase code (1-10 chars). Must be unique across tenants.
- `display_name`: full tenant name (used for the `Tenant` reference row).
- `application.name`: unique across all SSO Applications — include the tenant code
  (e.g., `"CBRTConnect - MSP"`) to avoid collision.
- `application.redirect_uris`: OAuth redirect URIs as a list. Trailing slashes must
  match exactly what the client app sends (Oct 2025 lesson learned).
- `roles`: the roles this tenant will use. `legacy_role` is what client apps read
  from the JWT (`application_roles.<slug>.role`); use `Admin` / `Operator` / `Client`
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

The Application `slug` is auto-derived as `cbrtconnect-<tenant_code.lower()>`.

**Do not commit the filled-in YAML.** `tenants/.gitignore` blocks everything except
`_template.yaml`. Keep the filled YAML locally or in 1Password — it contains user PII.

## Step 2 — Dry-run

```bash
python manage.py provision_tenant --config tenants/msp.yaml --dry-run
```

Expected output: a plan listing `CREATE` or `SKIP (exists)` for the Tenant,
Application, each Role, each User, and each UserAppRole binding. Nothing is
written to the database. If validation fails (missing field, bad email, unknown
role reference, etc.), you'll get a specific error with a field path — fix the
YAML and re-run the dry-run.

## Step 3 — Real run

```bash
python manage.py provision_tenant \
  --config tenants/msp.yaml \
  --actor you@barge2rail.com
```

If successful, the command:

1. Writes all records in a single transaction.
2. Appends one JSON line to `logs/tenant_provisioning.jsonl` (no secrets in it).
3. Prints a one-time secret banner to stdout:

   ```
   ================================================================
   COPY THIS NOW - IT WILL NOT BE SHOWN AGAIN
   ================================================================
   client_id:     app_xxxxxxxxxxxxxxxx
   client_secret: <64 chars>
   ================================================================
   ```

**Copy `client_secret` to 1Password immediately.** It is NOT stored anywhere
else on disk and cannot be recovered later — only rotated (via `/cbrt-ops/`).

If the YAML included any `auth_type: email` users, a second banner follows
listing each new user's email and their one-time temp password:

```
================================================================
COPY THIS NOW - IT WILL NOT BE SHOWN AGAIN
Email/password users (temp passwords - distribute privately):
================================================================
  briana@marianshipping.example.com   <24-char password>
================================================================
```

These temp passwords are stored hashed (Django `set_password()`), never written
to `logs/tenant_provisioning.jsonl`, and cannot be recovered — only reset via
the password-reset flow. **Distribute via 1Password share or another
end-to-end-encrypted channel; never Slack/email plaintext.**

## What to tell email/password users after provisioning

Send each email user:

1. Their login URL: `https://sso.barge2rail.com/`
2. Their email (the login identifier).
3. Their one-time temp password (via 1Password share, Signal, or in person).
4. Instructions: "On first login you'll land on the dashboard. Go to
   `https://sso.barge2rail.com/change-password/` and set your own password.
   If you forget it later, use `https://sso.barge2rail.com/forgot-password/`
   to request a reset email."

Temp passwords pass Django's minimum-length validator (4 chars) — the user
is free to choose any password meeting that same minimum when they change it.

## Step 4 — Store and clean up

- **`client_secret`** → 1Password item named `SSO: <tenant_code> client secret`.
  Also store `client_id` alongside it (not secret, but needed to configure the
  client app).
- **Filled YAML** → 1Password attachment on the same item, or a private local
  directory outside the repo. Do not email, Slack, or Drive it.
- Share `client_id` + `client_secret` with the client app team via 1Password
  share link or password manager, never plaintext channels.

## Idempotency

Re-running the same YAML is safe. Existing rows are reported as
`SKIP (exists)`. The command exits 0 and still appends an audit line
(`application_skipped: true`, `bindings_created: 0` for a full no-op).

If the Application already exists, the secret banner is **not** reprinted —
the command can't retrieve the plaintext. If you lost it, rotate via
`/cbrt-ops/` and update the client app.

Same for email/password users: on re-run, existing users are SKIP'd and no
temp password is printed. If a user lost theirs, they use the
`/forgot-password/` flow (or an admin resets via `/cbrt-ops/`).

### auth_type mismatch

If a user email already exists in the DB with a different `auth_type` than
the YAML specifies, the command prints an `auth_type mismatch` warning on
the SKIP line (e.g. `yaml=email, db=google`) and **does not modify** the
existing user. This is informational — investigate whether the YAML or the
existing row is wrong; fix via `/cbrt-ops/` if the DB record should change.

## If something goes wrong

- **Validation error**: YAML field path is in the error message. Fix and re-run
  dry-run.
- **`Actor '<email>' has no SSO user`**: Create yourself via `/cbrt-ops/` first,
  then re-run.
- **Mid-transaction failure**: nothing is written (transactional). Fix the
  underlying cause (usually a DB constraint or a migration mismatch) and re-run.
- **Wrong data got created**: the command prints `application_id` + user emails
  in the audit line. Open `/cbrt-ops/`, delete the Application (cascades
  UserAppRoles and Roles), delete the Users and Tenant manually.

## Audit log

`logs/tenant_provisioning.jsonl` — one line per run (dry-runs are NOT appended).
Each line: `ts`, `actor`, `tenant_code`, `application_id`, `application_name`,
`application_skipped`, `roles_created`, `users_created`, `bindings_created`,
`dry_run`. Explicitly contains no `client_id`, no `client_secret`, and no
email/password user temp passwords.

Review with:

```bash
cat logs/tenant_provisioning.jsonl | jq .
```

## Verification checklist (post-run)

1. `/cbrt-ops/` → Applications → new Application exists with correct name, slug, redirect URIs.
2. `/cbrt-ops/` → Users → each YAML user exists with correct name and the
   `auth_type` specified in the YAML (`email` or `google`). Email users have
   a usable password; Google users do not.
3. `/cbrt-ops/` → UserAppRoles → each (user, role, tenant_code) binding is present and `is_active`.
4. `/cbrt-ops/` → Tenants → tenant row exists with correct code and display name.
5. For an email/password user: sign in at `https://sso.barge2rail.com/` with
   the temp password; confirm the change-password page is reachable at
   `/change-password/`.
6. For a Google user: log in to the client app (CBRTConnect) via Google; the
   JWT should include `application_roles.<slug>.tenant_code == "<TENANT_CODE>"`
   and `application_roles.<slug>.role == "<legacy_role>"`.
