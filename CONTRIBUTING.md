# Contributing

## AI Code Workflow (Mandatory)
- All AI-generated changes must comply with **claude.md** (repo root).
- Use feature branches + PRs. **Do not** merge without CTO approval.
- **Never** expose secrets in code, templates, logs, tests, or screenshots.
- Update `requirements.txt` whenever new Python imports are added.
- Keep changes strictly scoped to the request—no drive-by edits.
- Provide numbered unified diffs, exact shell commands (with working directory), and a 1-line test plan.

## Branch & PR Conventions
- Branch: `feat/<topic>` / `fix/<topic>` / `chore/<topic>`.
- PR must include: scope summary, security notes, test commands, and checklist below.

## Pre-PR Checklist
- [ ] Only requested files changed; no unrelated edits
- [ ] New imports reflected in `requirements.txt`
- [ ] No secrets committed; `.env*` untracked; `.env.example` updated when needed
- [ ] Security: CSRF/SSL settings unchanged unless explicitly requested
- [ ] Added/updated docs and minimal tests (when applicable)
- [ ] Provided exact commands to verify and a 1-line test plan

## Local Verification
```bash
# Dir: /Users/cerion/Projects/barge2rail-auth
cd /Users/cerion/Projects/barge2rail-auth
source .venv/bin/activate
python -m pytest -q || true
python - <<'PY'
from decouple import config
print("BASE_URL:", config("BASE_URL", default="<unset>"))
print("GOOGLE_CLIENT_ID set?:", bool(config("GOOGLE_CLIENT_ID", default="")))
PY
```