#!/usr/bin/env python3
import os
import sys

errors = []
for p in [
    ".claude-context/global/standards.md",
    ".claude-context/project/overview.md",
    ".ai-prompts/bug_triage.md",
]:
    if not os.path.exists(p):
        errors.append(f"Missing required file: {p}")
diff = os.popen("git diff --name-only origin/main...HEAD").read().splitlines()
if any(p.endswith(("views.py", "serializers.py")) for p in diff) and not any(
    p.startswith("tests/") for p in diff
):
    errors.append("Core API changed but no tests under tests/ were modified.")
if errors:
    print("\n".join(errors))
    sys.exit(1)
print("Context lint passed.")
