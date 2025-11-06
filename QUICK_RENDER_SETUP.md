# QUICK: Add SendGrid API Key to Render

**Time:** 2 minutes
**Status:** CRITICAL - Blocks Phase 1 email functionality

---

## What I Did

✅ Updated `render.yaml` with SendGrid configuration
✅ Prepared to commit and push changes
✅ Render will auto-sync most variables from render.yaml

## What You Need to Do Manually

**ONLY 1 variable needs manual entry (it's a secret):**

### Step 1: Go to Render Dashboard
1. Open: https://dashboard.render.com/
2. Click: `barge2rail-sso` service
3. Click: **Environment** tab (left sidebar)

### Step 2: Add SENDGRID_API_KEY
Click "Add Environment Variable":

```
Key: SENDGRID_API_KEY
Value: <Get from .env file - line 12: SENDGRID_API_KEY=SG.xxxx...>
```

⚠️ **IMPORTANT:** Copy the value from `/Users/cerion/Projects/barge2rail-auth/.env` line 12

### Step 3: Save
- Click "Save Changes"
- Render will auto-deploy (~2 min)
- Done!

---

## What Happens Automatically

When I push the updated `render.yaml`, Render will automatically set:

✅ `EMAIL_BACKEND` = sendgrid_backend.SendgridBackend
✅ `DEFAULT_FROM_EMAIL` = noreply@barge2rail.com
✅ `DEFAULT_FROM_NAME` = Barge2Rail SSO

Only `SENDGRID_API_KEY` needs manual entry (marked as `sync: false` in render.yaml because it's a secret).

---

## Test After Deploy

1. Go to: https://sso.barge2rail.com/auth/forgot-password/
2. Enter: test@example.com
3. Click: "Send Reset Link"
4. Check: SendGrid Activity Feed for sent email
5. Verify: Email received

---

## Ready to Proceed?

I'll commit the `render.yaml` changes now, then you just need to:
1. Add SENDGRID_API_KEY in Render dashboard
2. Wait for auto-deploy to complete
3. Test forgot password flow

**Proceeding with commit...**
