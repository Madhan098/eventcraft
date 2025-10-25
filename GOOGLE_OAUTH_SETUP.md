# Google OAuth Setup Guide

## 1. Create Google OAuth Credentials

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select an existing one
3. Enable the Google+ API
4. Go to "Credentials" → "Create Credentials" → "OAuth 2.0 Client IDs"
5. Set application type to "Web application"
6. Add authorized redirect URIs:
   - For development: `http://localhost:5000/auth/google/callback`
   - For production: `https://yourdomain.com/auth/google/callback`

## 2. Environment Variables

Set these environment variables in your deployment platform:

```bash
GOOGLE_CLIENT_ID=your-google-client-id-here
GOOGLE_CLIENT_SECRET=your-google-client-secret-here
GOOGLE_REDIRECT_URI=http://localhost:5000/auth/google/callback
```

## 3. Local Development

For local development, create a `.env` file in your project root:

```env
GOOGLE_CLIENT_ID=your-google-client-id-here
GOOGLE_CLIENT_SECRET=your-google-client-secret-here
GOOGLE_REDIRECT_URI=http://localhost:5000/auth/google/callback
```

## 4. Features Added

✅ **Auto-redirect to dashboard after account creation**
- Users are automatically logged in after OTP verification
- No need to manually login after registration

✅ **Google OAuth Authentication**
- Users can sign in with Google
- Automatic account creation for new Google users
- Seamless integration with existing user system

## 5. Database Migration

The User model has been updated to include a `google_id` field. If you have an existing database, you may need to run a migration:

```python
# Add the google_id column to existing users table
ALTER TABLE users ADD COLUMN google_id VARCHAR(100) UNIQUE;
```

## 6. Testing

1. Start your Flask application
2. Go to the login page
3. Click "Continue with Google"
4. Complete the Google OAuth flow
5. You should be automatically logged in and redirected to the dashboard
