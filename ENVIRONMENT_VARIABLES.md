# Environment Variables Setup for Render

## 🔴 REQUIRED - Must Set These in Render Dashboard

After deploying, go to Render Dashboard → Environment tab and add these:

### 1. DATABASE_URL (Neon PostgreSQL)
```
DATABASE_URL = postgresql://[your-neon-connection-string]
```
**⚠️ IMPORTANT:** Paste your complete Neon connection string here.
- Get it from: https://console.neon.tech → Your database → Connection Details
- Format: `postgresql://username:password@host/database?sslmode=require`

### 2. GOOGLE_CLIENT_ID
```
GOOGLE_CLIENT_ID = [your-google-client-id]
```
Get from: https://console.cloud.google.com → APIs & Services → Credentials

### 3. GOOGLE_CLIENT_SECRET  
```
GOOGLE_CLIENT_SECRET = [your-google-client-secret]
```
Get from: Same Google Cloud Console OAuth 2.0 Client

## 🟡 OPTIONAL - For Initial Setup

### 4. DJANGO_SUPERUSER_EMAIL (Optional)
```
DJANGO_SUPERUSER_EMAIL = admin@barge2rail.com
```
Only needed if you want auto-creation of admin user on first deploy

### 5. DJANGO_SUPERUSER_PASSWORD (Optional)
```
DJANGO_SUPERUSER_PASSWORD = [choose-strong-password]
```
Only needed with DJANGO_SUPERUSER_EMAIL

## ✅ AUTO-GENERATED - Don't Set These

These are automatically handled by Render:
- `SECRET_KEY` - Render generates this securely
- `PORT` - Render sets this
- `RENDER_EXTERNAL_URL` - Render provides this

## 📋 Quick Copy-Paste Template

Here's what to add in Render's Environment tab:

```
DATABASE_URL = [paste your Neon connection string here]
GOOGLE_CLIENT_ID = [paste your Google Client ID here]
GOOGLE_CLIENT_SECRET = [paste your Google Client Secret here]
```

## 🔍 How to Find Your Neon Connection String

1. Go to https://console.neon.tech
2. Select your database project
3. Click on your database
4. Go to "Connection Details" or "Dashboard"
5. Copy the connection string (choose "Connection string" format)
6. It should look like:
   ```
   postgresql://username:password@ep-something.region.aws.neon.tech/dbname?sslmode=require
   ```

## ⚠️ Important Notes

1. **SSL Mode:** Neon requires `sslmode=require` - this should already be in your connection string
2. **Pooling:** If you see connection issues, you might need the "Pooled connection" string from Neon
3. **Region:** Make sure your Neon database is in a region close to Ohio (Render's region) for best performance

## 🧪 Testing After Setup

Once you've added these environment variables:

1. Trigger a manual deploy in Render (or it will auto-deploy)
2. Check the logs for "Database is ready!"
3. Visit https://[your-app].onrender.com/api/auth/health/
4. Should return: `{"status": "healthy"}`

## 🚨 Troubleshooting

If deployment fails after adding DATABASE_URL:

1. **Check Connection String Format**
   - Must start with `postgresql://` (not `postgres://`)
   - Must include `?sslmode=require` at the end

2. **Check Neon Database Status**
   - Ensure database is active in Neon console
   - Check if you're within connection limits

3. **Try Pooled Connection**
   - In Neon, switch to "Pooled connection" if you see connection errors
   - This helps with connection limits

4. **Check Logs in Render**
   - Look for "psycopg2.OperationalError" - usually means connection string issue
   - Look for "Database is ready!" - means connection successful
