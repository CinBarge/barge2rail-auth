# 🚀 QUICK DEPLOYMENT GUIDE - NEON POSTGRESQL

## Step 1: Deploy to Render (2 minutes)

1. Go to https://dashboard.render.com
2. Click **"New +"** → **"Web Service"**
3. Connect GitHub repository: `CinBarge/barge2rail-auth`
4. Select branch: `sso-complete-implementation`
5. Render will auto-detect the `render.yaml`
6. Click **"Create Web Service"**

## Step 2: Configure Environment Variables (3 minutes)

In Render Dashboard → **Environment** tab, add these THREE variables:

### 1. DATABASE_URL (Your Neon Connection String)
```
DATABASE_URL = [paste your complete Neon connection string here]
```

**Example format:**
```
postgresql://username:password@ep-something.us-east-2.aws.neon.tech/neondb?sslmode=require
```

### 2. GOOGLE_CLIENT_ID
```
GOOGLE_CLIENT_ID = [your Google OAuth client ID]
```

### 3. GOOGLE_CLIENT_SECRET
```
GOOGLE_CLIENT_SECRET = [your Google OAuth client secret]
```

Click **"Save Changes"** - This will trigger a redeploy

## Step 3: Verify Deployment (2 minutes)

Watch the Render logs for these success messages:
- ✅ "Neon database connection successful!"
- ✅ "Running database migrations..."
- ✅ "Django SSO is starting on port"

Then test the health endpoint:
```
https://barge2rail-sso.onrender.com/api/auth/health/
```

Should return: `{"status": "healthy"}`

## Step 4: Configure Custom Domain (5 minutes)

1. In Render → Settings → Custom Domains
2. Add: `sso.barge2rail.com`
3. Update your DNS with the provided CNAME/A record
4. Wait for SSL certificate (usually ~10 minutes)

## 🎯 That's It! Your SSO is Live!

### Test Your Deployment:

1. **Health Check:**
   ```
   curl https://sso.barge2rail.com/api/auth/health/
   ```

2. **Google OAuth Config:**
   ```
   curl https://sso.barge2rail.com/api/auth/google/config/
   ```

3. **Login Page:**
   Visit: https://sso.barge2rail.com/login/

## 🔧 Troubleshooting

### If deployment fails:

**Database Connection Error?**
- Check your Neon connection string format
- Must include `?sslmode=require`
- Try using the "Pooled connection" string from Neon

**Google OAuth Not Working?**
- Verify GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET are set
- Check authorized redirect URIs in Google Console:
  - Add: `https://sso.barge2rail.com/auth/google/callback/`
  - Add: `https://barge2rail-sso.onrender.com/auth/google/callback/`

**Static Files Not Loading?**
- Check logs for "Collecting static files..."
- WhiteNoise should handle this automatically

## 📊 Monitor Your Deployment

- **Render Dashboard:** https://dashboard.render.com
- **Neon Console:** https://console.neon.tech
- **Application Logs:** Render → Logs tab

## ✅ Success Checklist

- [ ] Deployment shows "Live" in Render
- [ ] Health endpoint returns 200 OK
- [ ] Database migrations completed
- [ ] Google OAuth configured
- [ ] Custom domain working with SSL
- [ ] Can login with Google account
- [ ] Admin user created (optional)

## 🎉 Deployment Complete!

Your Django SSO is now:
- **Live** at https://sso.barge2rail.com
- **Secured** with SSL/TLS
- **Connected** to Neon PostgreSQL
- **Ready** for Google OAuth logins
- **Scalable** on Render's infrastructure

Total deployment time: ~10 minutes
