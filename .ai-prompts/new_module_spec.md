REQUIREMENT: {business requirement}
CONSTRAINTS:
- Independent Django project
- DRF + ViewSets, REST v1
- Simple JWT via central SSO (no local users)
- UUID PKs for user-facing models
DELIVERABLES:
- models.py, serializers.py, views.py (ViewSets), urls.py (versioned)
- SSO middleware or permission classes
- API tests (pytest) and integration tests for SSO
- /health/ endpoint
- README with setup and API usage
