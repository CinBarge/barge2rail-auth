# URGENT: Add SendGrid Configuration to Render
**Status:** CRITICAL - Phase 1 deployed but email non-functional
**Time Required:** 5 minutes
**Service:** barge2rail-sso (srv-d3j532odl3ps73dl3itg)

---

## Problem
Phase 1 password management is deployed but forgot password emails are not sending because SendGrid environment variables are missing from Render.

---

## Solution: Add 5 Environment Variables to Render

### Step-by-Step Instructions

1. **Go to Render Dashboard**
   - URL: https://dashboard.render.com/
   - Navigate to: `barge2rail-sso` service
   - Click: **Environment** tab (left sidebar)

2. **Add These 5 Environment Variables**

   Click "Add Environment Variable" for each:

   **Variable 1: EMAIL_BACKEND**
   ```
   Key: EMAIL_BACKEND
   Value: sendgrid_backend.SendgridBackend
   ```

   **Variable 2: SENDGRID_API_KEY**
   ```
   Key: SENDGRID_API_KEY
   Value: <Copy from .env file line 12>
   ```
   ⚠️ **IMPORTANT:** Get the value from `/Users/cerion/Projects/barge2rail-auth/.env` line 12

   The value starts with `SG.` - copy the entire string after `SENDGRID_API_KEY=`

   **Variable 3: DEFAULT_FROM_EMAIL**
   ```
   Key: DEFAULT_FROM_EMAIL
   Value: noreply@barge2rail.com
   ```

   **Variable 4: DEFAULT_FROM_NAME**
   ```
   Key: DEFAULT_FROM_NAME
   Value: Barge2Rail SSO
   ```

   **Variable 5: CSRF_TRUSTED_ORIGINS** (UPDATE EXISTING)
   ```
   Key: CSRF_TRUSTED_ORIGINS
   Old Value: https://sso.barge2rail.com
   New Value: https://sso.barge2rail.com,https://barge2rail-sso.onrender.com
   ```
   ℹ️ This fixes 500 errors when accessing via Render domain

3. **Save and Deploy**
   - Click "Save Changes" at bottom of page
   - Render will automatically redeploy (~2 minutes)
   - Wait for deployment to complete (green checkmark)

---

## Verify It's Working

### Test 1: Access Forgot Password Page
1. Go to: https://sso.barge2rail.com/auth/forgot-password/
2. Should load without errors
3. Form should be visible and functional

### Test 2: Send Password Reset Email
1. Enter email: `test@example.com` (or your test user email)
2. Click "Send Reset Link"
3. Should see success page
4. Check SendGrid dashboard for email delivery
5. Check email inbox for reset email

### Test 3: Verify Render Domain Works
1. Go to: https://barge2rail-sso.onrender.com/auth/forgot-password/
2. Should load without 500 error (CSRF fix)
3. Form should work

---

## Current Configuration Status

### ✅ Already Configured in Render
- `SECRET_KEY` - Django secret key
- `DEBUG` - Set to False (production mode)
- `ALLOWED_HOSTS` - Includes both domains
- `GOOGLE_CLIENT_ID` - OAuth credentials
- `GOOGLE_CLIENT_SECRET` - OAuth credentials
- `BASE_URL` - Production URL
- `DATABASE_URL` - PostgreSQL connection

### ❌ MISSING (Need to Add)
- `EMAIL_BACKEND` - SendGrid backend class
- `SENDGRID_API_KEY` - SendGrid API key for email sending
- `DEFAULT_FROM_EMAIL` - From email address
- `DEFAULT_FROM_NAME` - From name for emails

### ⚠️ NEEDS UPDATE
- `CSRF_TRUSTED_ORIGINS` - Add Render domain to prevent 500 errors

---

## What Happens After Adding Variables

1. **Render Auto-Deploys**
   - Detects environment variable changes
   - Triggers automatic redeployment
   - Takes ~2 minutes to complete

2. **Django Loads New Settings**
   - `core/settings.py` reads environment variables
   - Since `DEBUG=False` in production:
     - Email backend switches from console to SendGrid SMTP
     - Emails will send via SendGrid
   - CSRF trusted origins updated

3. **Password Reset Emails Work**
   - Forgot password requests generate tokens
   - Emails sent via SendGrid SMTP
   - Users receive professional HTML emails
   - Reset links work correctly

---

## Troubleshooting

### If Emails Still Don't Send

**Check SendGrid Dashboard:**
1. Go to: https://app.sendgrid.com/
2. Navigate to: Activity Feed
3. Look for recent email attempts
4. Check for errors or blocks

**Verify API Key:**
- API key must be valid and not expired
- Check SendGrid account is active
- Verify API key has "Mail Send" permission

**Check Render Logs:**
1. Render Dashboard → Logs tab
2. Look for email-related errors
3. Check for SendGrid connection errors

### If 500 Errors Persist

**Check CSRF_TRUSTED_ORIGINS:**
- Must include both domains
- Must start with `https://`
- Comma-separated, no spaces

**Check Render Deployment:**
- Verify deployment completed successfully
- Check for any deployment errors
- Restart service if needed

---

## Expected Email Behavior

### Development (DEBUG=True)
- Emails print to console
- No actual emails sent
- Used for local testing

### Production (DEBUG=False)
- Emails sent via SendGrid SMTP
- Real emails delivered
- Professional HTML formatting

### Email Content
- **Subject:** Password Reset Request
- **From:** Barge2Rail SSO <noreply@barge2rail.com>
- **Format:** HTML + plain text fallback
- **Contains:**
  - User's email address
  - Password reset link (expires in 1 hour)
  - Professional branding
  - Security notice

---

## Next Steps After Configuration

1. **Test with Real Email**
   - Use your actual email address
   - Verify email is received
   - Click reset link to test full flow

2. **Test from Both Domains**
   - https://sso.barge2rail.com/auth/forgot-password/
   - https://barge2rail-sso.onrender.com/auth/forgot-password/
   - Both should work without errors

3. **Monitor SendGrid Activity**
   - Check Activity Feed for deliveries
   - Monitor bounce/spam rates
   - Verify emails not going to spam

4. **Client Testing**
   - Send reset link to client (lbryant@primetradeusa.com)
   - Verify she can receive and use reset link
   - Confirm full password reset flow works

---

## SendGrid Settings to Verify

### Domain Authentication (Optional but Recommended)
- Authenticates `barge2rail.com` domain
- Reduces spam likelihood
- Improves deliverability
- Setup at: SendGrid → Settings → Sender Authentication

### Sender Verification (Required)
- Verify `noreply@barge2rail.com` is authenticated
- Check: SendGrid → Settings → Sender Authentication
- If not verified, emails may not send

---

## Emergency Fallback

If SendGrid issues persist:

1. **Switch to Console Backend Temporarily**
   ```
   EMAIL_BACKEND=django.core.mail.backends.console.EmailBackend
   ```
   - Emails won't send but app won't crash
   - Logs email content to Render logs
   - Temporary solution only

2. **Manual Password Resets**
   ```bash
   python manage.py shell
   from sso.models import User
   user = User.objects.get(email='user@example.com')
   user.set_password('NewPassword123!')
   user.save()
   ```
   - Use for urgent client needs
   - Not sustainable long-term

---

## Completion Checklist

- [ ] All 5 environment variables added to Render
- [ ] CSRF_TRUSTED_ORIGINS updated with both domains
- [ ] Render deployment completed successfully
- [ ] Forgot password page loads without errors
- [ ] Test email sent via SendGrid
- [ ] Email received in inbox (not spam)
- [ ] Reset link works correctly
- [ ] Both domains accessible (sso + Render)
- [ ] Client can successfully reset password

---

**Time to Complete:** 5 minutes
**Priority:** CRITICAL
**Impact:** Unblocks Phase 1 password management in production

**Once complete, Phase 1 will be 100% functional in production!** 🚀
