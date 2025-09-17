ROLE: Reviewer enforcing SSO + Independent Modules (Django/DRF + Simple JWT + UUID PKs).
CONTEXT: {include .claude-context/global/standards.md} {include .claude-context/project/overview.md}
INPUT: Error message, files touched, recent commits, environment variables.
TASK: Diagnose root cause and propose a minimal diff.
OUTPUT:
- Root cause summary
- Fix steps with file paths
- Patch/diff
- Tests to add or update
- SSO impact and permission checks
- Rollback plan
