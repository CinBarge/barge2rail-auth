#!/usr/bin/env bash
set -euo pipefail
tmp="$(mktemp /tmp/b2r_context.XXXX.txt)"
if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  git -c color.ui=never log --oneline -15 > /tmp/b2r_commits.txt || true
  git status --porcelain > /tmp/b2r_status.txt || true
else
  : > /tmp/b2r_commits.txt
  : > /tmp/b2r_status.txt
fi
{
  [ -f .claude-context/global/standards.md ] && cat .claude-context/global/standards.md
  [ -f .claude-context/global/delegation_templates.md ] && cat .claude-context/global/delegation_templates.md
  [ -f .claude-context/project/overview.md ] && cat .claude-context/project/overview.md
  [ -f .claude-context/project/interfaces.md ] && cat .claude-context/project/interfaces.md
  [ -f .claude-context/feature/goals.md ] && cat .claude-context/feature/goals.md
  echo -e "\n## Recent commits\n"; cat /tmp/b2r_commits.txt
  echo -e "\n## Working tree\n"; cat /tmp/b2r_status.txt
} > "$tmp"
echo "$tmp"
