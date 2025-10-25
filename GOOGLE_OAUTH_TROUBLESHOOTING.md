# Google OAuth Troubleshooting Guide

## 400 Error - Common Causes and Solutions

### 1. Missing Environment Variables
The 400 error usually occurs when Google OAuth credentials are not properly configured.

**Check your environment variables:**
```bash
# Required variables
GOOGLE_CLIENT_ID=your-client-id-here
GOOGLE_CLIENT_SECRET=your-client-secret-here
GOOGLE_REDIRECT_URI=http://localhost:5000/auth/google/callback
```

### 2. Google Cloud Console Setup

**Step 1: Create Google Cloud Project**
1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select existing one
3. Enable the Google+ API

**Step 2: Create OAuth 2.0 Credentials**
1. Go to "APIs & Services" → "Credentials"
2. Click "Create Credentials" → "OAuth 2.0 Client IDs"
3. Set application type to "Web application"
4. Add authorized redirect URIs:
   - For development: `http://localhost:5000/auth/google/callback`
   - For production: `https://yourdomain.com/auth/google/callback`

**Step 3: Configure OAuth Consent Screen**
1. Go to "OAuth consent screen"
2. Choose "External" user type
3. Fill in required fields:
   - App name: EventCraft Pro
   - User support email: your-email@domain.com
   - Developer contact: your-email@domain.com
4. Add scopes: `openid`, `email`, `profile`

### 3. Environment Configuration

**For Local Development:**
Create a `.env` file in your project root:
```env
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret
GOOGLE_REDIRECT_URI=http://localhost:5000/auth/google/callback
```

**For Production (Render/Heroku):**
Set environment variables in your hosting platform:
```bash
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret
GOOGLE_REDIRECT_URI=https://yourdomain.com/auth/google/callback
```

### 4. Common Issues and Solutions

**Issue: "redirect_uri_mismatch"**
- **Solution**: Ensure the redirect URI in your Google Console exactly matches your environment variable
- Check for trailing slashes, http vs https, port numbers

**Issue: "invalid_client"**
- **Solution**: Verify your CLIENT_ID and CLIENT_SECRET are correct
- Make sure there are no extra spaces or characters

**Issue: "access_denied"**
- **Solution**: Check OAuth consent screen configuration
- Ensure the app is published or add test users

**Issue: "invalid_request"**
- **Solution**: Check that all required parameters are present
- Verify the OAuth flow is properly implemented

### 5. Testing OAuth Configuration

**Check OAuth Status:**
Visit: `http://localhost:5000/oauth-status` (requires login)

This will show:
- Whether credentials are configured
- Redirect URI setting
- Credential lengths (for verification)

### 6. Debug Steps

1. **Check Environment Variables:**
   ```python
   print("Client ID:", app.config.get('GOOGLE_CLIENT_ID'))
   print("Client Secret:", bool(app.config.get('GOOGLE_CLIENT_SECRET')))
   print("Redirect URI:", app.config.get('GOOGLE_REDIRECT_URI'))
   ```

2. **Check Google Console:**
   - Verify OAuth 2.0 Client ID is created
   - Check redirect URIs match exactly
   - Ensure OAuth consent screen is configured

3. **Test OAuth Flow:**
   - Try the Google OAuth flow step by step
   - Check browser network tab for errors
   - Look at server logs for detailed error messages

### 7. Production Deployment

**For Render:**
1. Set environment variables in Render dashboard
2. Update redirect URI to your production domain
3. Ensure HTTPS is enabled

**For Heroku:**
```bash
heroku config:set GOOGLE_CLIENT_ID=your-client-id
heroku config:set GOOGLE_CLIENT_SECRET=your-client-secret
heroku config:set GOOGLE_REDIRECT_URI=https://yourapp.herokuapp.com/auth/google/callback
```

### 8. Security Notes

- Never commit credentials to version control
- Use environment variables for all sensitive data
- Regularly rotate OAuth credentials
- Monitor OAuth usage in Google Console

### 9. Quick Fix Checklist

- [ ] Google Cloud Console project created
- [ ] OAuth 2.0 Client ID created
- [ ] Redirect URI added to Google Console
- [ ] OAuth consent screen configured
- [ ] Environment variables set correctly
- [ ] Redirect URI matches exactly (no trailing slashes)
- [ ] Client ID and Secret are correct
- [ ] App is published or test users added

### 10. Still Having Issues?

1. Check server logs for detailed error messages
2. Verify all environment variables are set
3. Test with a simple OAuth flow
4. Check Google Console for any restrictions
5. Ensure your domain is verified (for production)

## Support

If you're still experiencing issues, check:
1. Server logs for specific error messages
2. Browser developer tools for network errors
3. Google Console for OAuth restrictions
4. Environment variable configuration
