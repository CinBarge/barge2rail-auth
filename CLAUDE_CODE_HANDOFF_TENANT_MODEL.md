# Claude Code Handoff: Add Tenant Model to SSO

## Objective
Add a simple Tenant model to SSO so the Bulk Role Assignment dropdown shows all available tenant codes, not just ones that happen to exist in User App Roles.

## Context
- Bulk Role Assignment page (`/admin/rbac/bulk-role-assignment/`) has a "Tenant Code" dropdown
- Currently populated from existing UserAppRole.tenant_code values (only shows GNP, TRX, YFN)
- Need to show ALL valid tenants (including HLR) even before any user is assigned to them

## Requirements

### 1. Create Tenant Model
Location: `rbac/models.py` (or new `rbac/tenant_models.py` if cleaner)

```python
class Tenant(models.Model):
    """
    Available tenant codes for role assignment.
    Simple reference table - Sacks/apps have their own full Tenant models.
    """
    code = models.CharField(max_length=10, unique=True, help_text="e.g., HLR, GNP, TRX")
    name = models.CharField(max_length=100, help_text="Display name, e.g., Hiller Carbon")
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['code']

    def __str__(self):
        return f"{self.code} - {self.name}"
```

### 2. Register in Admin
Location: `rbac/admin.py`

Simple admin with list display: code, name, is_active

### 3. Update Bulk Role Assignment View
Location: Find the view that renders `/admin/rbac/bulk-role-assignment/`

Change tenant dropdown choices from:
```python
# OLD: Pulling from existing UserAppRole values
tenant_codes = UserAppRole.objects.values_list('tenant_code', flat=True).distinct()
```

To:
```python
# NEW: Pull from Tenant model
from rbac.models import Tenant
tenants = Tenant.objects.filter(is_active=True).values_list('code', 'name')
```

Keep "No tenant (global)" as the first/default option.

### 4. Migration
Create and run migration for the new Tenant model.

### 5. Seed Initial Data
Create these tenants (can be done in migration or shell):
- GNP - GNP Commodities
- HLR - Hiller Carbon  
- TRX - Traxys
- YAS - Yasuda
- YFN - Yifan

## Files Likely Involved
- `rbac/models.py` - Add Tenant model
- `rbac/admin.py` - Register TenantAdmin
- `rbac/views.py` or wherever bulk assignment view lives
- `rbac/templates/...` - Template for bulk assignment (if dropdown logic is there)

## Testing
1. Run migration
2. Add tenants via admin
3. Go to Bulk Role Assignment
4. Verify dropdown shows all tenants including HLR
5. Assign a role with HLR tenant code
6. Verify UserAppRole created with tenant_code="HLR"

## Risk Level
LOW - Additive change only, no existing functionality modified except dropdown source.
