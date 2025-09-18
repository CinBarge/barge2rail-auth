# CLAUDE CODE GENERATION RULES — MANDATORY FOR THIS REPO

## 1) Critical Security & Quality
1. Authorized scope only: change exactly what’s requested; no drive-by edits. Ask questions only for business rules.
2. Dependencies: when adding imports, update `requirements.txt`. Keep Django 4.2 compatible.
3. No placeholders in code: never commit example keys; use env vars. Update `.env.example` and docs when adding config.
4. Question vs. code: answer questions with analysis; modify code only on explicit change requests.
5. No guessing: if API/versions/paths are uncertain, stop and ask; do not invent.
6. Secrets: never in client/templates/static/logs/tests. Redact tokens/IDs. Don’t echo access/ID/refresh tokens.
7. Capability honesty: if a task needs infra you can’t access, say so.
8. Preserve behavior: fix bugs without changing requirements unless explicitly told.
9. Evidence-based: cite file/lines when claiming something exists; include code snippets.
10. No hardcoded examples in prod paths.
11. Logging: add useful INFO/WARN/ERROR; **no tokens/PII**; include context (request ID, user id) when available.

## 2) Django/OAuth Conventions
- SSL/Proxy: set `SECURE_PROXY_SSL_HEADER=('HTTP_X_FORWARDED_PROTO','https')`; enable `SECURE_SSL_REDIRECT` in prod; honor `X-Forwarded-Proto` on Render.
- CSRF: `CSRF_TRUSTED_ORIGINS = ['https://sso.barge2rail.com']` (no wildcards in prod).
- Redirect URI: build exact `.../auth/google/callback/` from `BASE_URL` helper; must match Google Console (trailing slash).
- Google OAuth: v2 authorize endpoint; token endpoint `https://oauth2.googleapis.com/token`; `access_type=offline`; use `prompt=consent` when needing refresh token; store refresh tokens server-side only.
- Templates/JS: never embed client IDs/secrets; consume server-provided config safely.
- Logging OAuth: never log raw tokens or ID token payloads; log error categories and correlation IDs.

## 3) Response/Workflow Protocols
- Deliverables: numbered unified diffs, exact shell commands (with working directory), and a one-line test plan.
- New config: update `.env.example` and README snippets.
- Tests/docs: add minimal tests/docs when touching security/auth paths.
- Unsure? STOP, ask, and wait.

## 4) Pre-PR Checklist (must tick)
- [ ] Only requested files changed; no unrelated edits
- [ ] New imports reflected in `requirements.txt`
- [ ] `.env.example` updated (no secrets); docs updated
- [ ] CSRF/SSL/OAuth conventions upheld
- [ ] Useful logging added/kept; no tokens/PII in logs
- [ ] Provide diffs + commands + 1-line test plan

## 5) Session Permissions Header (paste atop every AI prompt)
SESSION PERMISSIONS
- You may: read/clone repo, create feature branches, open PRs, write Dockerfile/render.yaml, edit server-only code, add tests/docs.
- You must not: expose secrets, change business logic, touch unrelated files, or merge PRs without explicit CTO approval.
- Ask ONLY if business rules are missing. Otherwise proceed.
- Output: numbered unified diffs, exact shell commands (with working directory), and a 1-line test plan.
