# Three-Role System Migration Guide
**Date:** November 7, 2025
**Status:** ✅ IMPLEMENTED & TESTED
**Risk Level:** MEDIUM (affects authentication system)

---

## Summary

Successfully implemented simplified three-role system in SSO with automatic permission assignment.

### Changes Made

**Before (4 roles with empty permissions):**
- Administrator
- Standard User
- Read Only
- Operator
- Permissions: `[]` (empty by default, manual configuration required)

**After (3 roles with auto-assigned permissions):**
- **Admin** → `['full_access']`
- **Office** → `['read', 'write', 'delete']`
- **Client** → `['read']`

---

## Implementation Details

### 1. Model Changes (sso/models.py)

**ApplicationRole model updated with:**

```python
ROLE_CHOICES = [
    ('Admin', 'Admin'),
    ('Office', 'Office'),
    ('Client', 'Client'),
]

ROLE_PERMISSIONS = {
    'Admin': ['full_access'],
    'Office': ['read', 'write', 'delete'],
    'Client': ['read'],
}

def save(self, *args, **kwargs):
    """Auto-assign permissions based on role if not explicitly set."""
    if not self.permissions:
        self.permissions = self.ROLE_PERMISSIONS.get(self.role, [])
    super().save(*args, **kwargs)

def has_permission(self, permission):
    """Check if role has a specific permission."""
    if 'full_access' in self.permissions:
        return True
    return permission in self.permissions
```

### 2. Database Migration

**Migration:** `sso/migrations/0014_three_role_system.py`

**Changes:**
- Updated `ApplicationRole.role` field choices
- Updated help text for `role` and `permissions` fields
- No data migration (existing roles preserved as-is)

**Applied:** ✅ Successfully applied to local database

---

## Testing Results

### ✅ All Tests Passed

**Test 1: Admin Role Auto-Assignment**
- Created ApplicationRole with role='Admin'
- Verified permissions = `['full_access']`
- ✓ PASS

**Test 2: Office Role Auto-Assignment**
- Created ApplicationRole with role='Office'
- Verified permissions = `['read', 'write', 'delete']`
- ✓ PASS

**Test 3: Client Role Auto-Assignment**
- Created ApplicationRole with role='Client'
- Verified permissions = `['read']`
- ✓ PASS

**Test 4: Manual Permission Override**
- Created ApplicationRole with role='Office', permissions=['read']
- Verified permissions = `['read']` (manual override respected)
- ✓ PASS

**Test 5: has_permission() Method**
- Admin.has_permission('write') → True (full_access grants all)
- Office.has_permission('write') → True
- Client.has_permission('write') → False
- Client.has_permission('read') → True
- ✓ ALL PASS

---

## Production Migration Strategy

### Option A: Manual Migration (RECOMMENDED)

**Why:** Safer for production authentication system. Allows verification at each step.

**Steps:**
1. Deploy code changes to production
2. Access Django admin: https://sso.barge2rail.com/admin/sso/applicationrole/
3. Manually update existing ApplicationRole records:
   - `admin` → `Admin`
   - `user` → `Office`
   - `viewer` → `Client`
   - `operator` → `Office`
4. Verify permissions auto-populate correctly
5. Test user authentication after each change

**Time Estimate:** 5-10 minutes (depends on number of existing roles)

### Option B: Data Migration (NOT RECOMMENDED)

**Why:** Risky for authentication system. Could affect existing user access.

**If needed:**
```python
# Django data migration (use with caution)
from django.db import migrations

def migrate_roles(apps, schema_editor):
    ApplicationRole = apps.get_model('sso', 'ApplicationRole')

    role_mapping = {
        'admin': 'Admin',
        'user': 'Office',
        'viewer': 'Client',
        'operator': 'Office',
    }

    for old_role, new_role in role_mapping.items():
        ApplicationRole.objects.filter(role=old_role).update(role=new_role)
```

---

## Current Production Data

### Known Users with Roles

**Adrian (test user):**
- Current role: `operator` (lowercase)
- Will need update to: `Office`
- Expected permissions after: `['read', 'write', 'delete']`

**Action:** Update Adrian's role via Django admin after deployment

---

## Django Admin Behavior

### Role Dropdown
- Shows only three choices: Admin, Office, Client
- Old role values (admin, user, viewer, operator) will display if still in database
- New roles selected from dropdown will use new values (Admin, Office, Client)

### Permissions Field
- Now in collapsed "Additional Details" section
- Auto-populates on save if empty
- Can still be manually edited for custom permissions
- Help text explains auto-assignment behavior

### Admin URL
- Local: http://127.0.0.1:8000/admin/sso/applicationrole/
- Production: https://sso.barge2rail.com/admin/sso/applicationrole/

---

## API/Code Impact

### No Breaking Changes

**Verified:**
- ✅ No hardcoded role value checks in code
- ✅ Views use `.role` field generically
- ✅ OAuth validators query by relationship, not role value
- ✅ OIDC claims work with any role value
- ✅ Frontend checks permissions array, not role name

### JWT Claims Example

```json
{
  "user_id": 123,
  "email": "user@example.com",
  "application_roles": {
    "primetrade": {
      "role": "Office",
      "permissions": ["read", "write", "delete"]
    }
  }
}
```

**Frontend should check:**
```javascript
// Good: Check permissions array
if (user.application_roles.primetrade.permissions.includes('write')) {
  // Allow editing
}

// Bad: Check role name (fragile)
if (user.application_roles.primetrade.role === 'Office') {
  // Don't do this
}
```

---

## Security Considerations

### Permissions Hierarchy

1. **Admin (full_access):**
   - Can do everything
   - User management
   - Admin dashboard access
   - Create, edit, delete all records

2. **Office (read, write, delete):**
   - Daily operations
   - Create, edit, delete BOLs and records
   - View all company data
   - NO user management

3. **Client (read):**
   - View only their own records
   - Client-filtering must be implemented in application code
   - Cannot create, edit, or delete

### Application-Level Filtering

**Important:** Client role requires additional filtering in application code:

```python
# Example: PrimeTrade view
if user.application_role.role == 'Client':
    # Filter to only their company's records
    queryset = BOL.objects.filter(customer=user.company)
else:
    # Office and Admin see all records
    queryset = BOL.objects.all()
```

---

## Deployment Checklist

### Pre-Deployment
- [x] Code changes implemented
- [x] Migration generated
- [x] All tests passing
- [x] No hardcoded role checks found
- [x] Admin configuration verified

### Deployment
- [ ] Deploy to staging first
- [ ] Apply migration: `python manage.py migrate`
- [ ] Test role creation in staging admin
- [ ] Verify auto-assignment works
- [ ] Test user authentication
- [ ] Deploy to production
- [ ] Monitor error logs

### Post-Deployment
- [ ] Update Adrian's role from `operator` to `Office`
- [ ] Verify his permissions = `['read', 'write', 'delete']`
- [ ] Test his PrimeTrade access
- [ ] Update any other existing roles
- [ ] Document role mapping in team docs

---

## Rollback Plan

**If issues occur:**

1. **Code Rollback:**
   ```bash
   git revert <commit-hash>
   git push
   ```

2. **Migration Rollback:**
   ```bash
   python manage.py migrate sso 0013_fix_empty_usernames
   ```

3. **Estimated Recovery Time:** 5 minutes

**Data Safety:**
- Migration only changes field definition, not data
- Existing role values preserved
- No user access disruption

---

## Future Enhancements

**Not in this release, but recommended:**

1. **Role-Based UI:**
   - Show/hide UI elements based on permissions
   - Dynamic menu generation

2. **Permission Inheritance:**
   - Allow applications to define custom permissions
   - Extend ROLE_PERMISSIONS per application

3. **Audit Logging:**
   - Log role changes
   - Track permission modifications
   - Alert on Admin role assignments

4. **Client Filtering:**
   - Implement in PrimeTrade
   - Implement in Customer Database
   - Add to other applications as needed

---

## Questions & Answers

**Q: What happens to existing roles in production?**
A: They remain unchanged until manually updated. Old role values (admin, user, viewer, operator) will display but can't be selected for new roles.

**Q: Can I still manually set custom permissions?**
A: Yes! Set permissions before saving, and the auto-assignment won't override.

**Q: How do I check if a user has a specific permission?**
A: Use `role.has_permission('write')` method.

**Q: What if I need more than three roles?**
A: Add new roles to ROLE_CHOICES and ROLE_PERMISSIONS in models.py, then create a migration.

**Q: Is this backward compatible?**
A: Yes for code (no hardcoded checks). Old role values in DB will need manual update.

---

## Success Criteria

✅ ApplicationRole model has three role choices
✅ ROLE_PERMISSIONS mapping implemented
✅ Auto-assignment works correctly
✅ Manual override works correctly
✅ has_permission() helper works
✅ Migration generated and applied
✅ All tests pass
✅ Django admin displays correctly
✅ No breaking changes to API/code

---

## Next Steps

1. **Commit and push changes**
2. **Deploy to staging**
3. **Test with real user accounts**
4. **Deploy to production**
5. **Update Adrian's test account**
6. **Update team documentation**

---

**Implementation Status:** ✅ COMPLETE
**Ready for Production:** ✅ YES
**Risk Mitigation:** Manual migration strategy for production data
