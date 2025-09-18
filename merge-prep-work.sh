#!/bin/bash
# Django SSO - Merge Prep Work Script
# Working Directory: /Users/cerion/Projects/barge2rail-auth

echo "=== Django SSO Prep Work Merge ==="
echo "Current directory: $(pwd)"

# Ensure we're on main branch
git checkout main
echo "✅ Switched to main branch"

# Merge render-setup branch (contains Dockerfile + render.yaml)
git merge render-setup --no-ff -m "Merge render-setup: Add Dockerfile and render.yaml for deployment"
echo "✅ Merged render-setup branch"

# Check if there are any other branches to merge
git branch -a | grep -E "(ai-contrib|ai-standards)" || echo "No additional branches to merge"

# Verify merge was successful
echo ""
echo "=== Verification ==="
git --no-pager log --oneline -3
echo ""
echo "=== Files ready for deployment ==="
ls -la | grep -E "(Dockerfile|render.yaml|claude.md|CONTRIBUTING.md)"

echo ""
echo "✅ Prep work merge complete. Ready for Render service creation."
