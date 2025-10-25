# Google OAuth Setup for Render Deployment

## 🔧 **Step 1: Google Cloud Console Configuration**

### 1.1 Go to Google Cloud Console
- Visit: https://console.cloud.google.com/
- Select your project or create a new one

### 1.2 Enable Google+ API
- Go to "APIs & Services" > "Library"
- Search for "Google+ API" and enable it
- Also enable "Google OAuth2 API"

### 1.3 Create OAuth 2.0 Credentials
- Go to "APIs & Services" > "Credentials"
- Click "Create Credentials" > "OAuth 2.0 Client IDs"
- Choose "Web application"
- Set the name: "EventCraft Pro"

### 1.4 Configure Authorized Redirect URIs
Add these URIs:
```
https://eventcraft-aysl.onrender.com/auth/google/callback
http://localhost:5000/auth/google/callback
```

### 1.5 Get Your Credentials
- Copy the **Client ID**
- Copy the **Client Secret**

## 🚀 **Step 2: Render Environment Variables**

### 2.1 Go to Render Dashboard
- Visit: https://dashboard.render.com/
- Find your EventCraft service
- Click on it

### 2.2 Add Environment Variables
Go to "Environment" tab and add:

```
GOOGLE_CLIENT_ID=your_client_id_here
GOOGLE_CLIENT_SECRET=your_client_secret_here
SESSION_SECRET=your_secure_session_secret_here
```

### 2.3 Example Values
```
GOOGLE_CLIENT_ID=your_actual_client_id_from_google_console
GOOGLE_CLIENT_SECRET=your_actual_client_secret_from_google_console
SESSION_SECRET=your_secure_session_secret_here
```

## 🔄 **Step 3: Redeploy Application**

### 3.1 Trigger Redeploy
- In Render dashboard, go to "Manual Deploy"
- Click "Deploy latest commit"
- Wait for deployment to complete

### 3.2 Test Google OAuth
- Visit: https://eventcraft-aysl.onrender.com/auth
- Click "Continue with Google"
- Should redirect to Google login
- After login, should redirect back to your app

## 🐛 **Troubleshooting**

### Common Issues:

#### 1. "400. That's an error."
- **Cause**: Redirect URI mismatch
- **Fix**: Ensure Google Console has: `https://eventcraft-aysl.onrender.com/auth/google/callback`

#### 2. "Invalid state parameter"
- **Cause**: Session issues
- **Fix**: Clear browser cookies and try again

#### 3. "Failed to get access token"
- **Cause**: Wrong client credentials
- **Fix**: Verify `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET` in Render

#### 4. "redirect_uri_mismatch"
- **Cause**: Google Console redirect URI doesn't match
- **Fix**: Add exact URL to Google Console

## ✅ **Verification Steps**

1. **Check Environment Variables**:
   - Go to Render > Your Service > Environment
   - Verify all variables are set

2. **Test OAuth Flow**:
   - Visit: https://eventcraft-aysl.onrender.com/auth
   - Click "Continue with Google"
   - Should work without errors

3. **Check Logs**:
   - Go to Render > Your Service > Logs
   - Look for any OAuth-related errors

## 🔐 **Security Notes**

- **Never** commit credentials to git
- **Always** use environment variables
- **Rotate** secrets regularly
- **Use** strong session secrets

## 📞 **Support**

If you still have issues:
1. Check Render logs for specific errors
2. Verify Google Console configuration
3. Test with a fresh browser session
4. Ensure all environment variables are set correctly
