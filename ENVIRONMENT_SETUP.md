# Environment Setup Guide

## Google OAuth Configuration

To set up Google OAuth for EventCraft Pro, you need to configure the following environment variables:

### 1. Get Google OAuth Credentials

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select existing one
3. Enable Google+ API:
   - Go to "APIs & Services" → "Library"
   - Search for "Google+ API" and enable it
4. Create OAuth 2.0 Credentials:
   - Go to "APIs & Services" → "Credentials"
   - Click "Create Credentials" → "OAuth 2.0 Client IDs"
   - Set application type to "Web application"
   - Add authorized redirect URI: `http://localhost:5000/auth/google/callback`
5. Configure OAuth Consent Screen:
   - Go to "OAuth consent screen"
   - Choose "External" user type
   - Fill in required fields:
     - App name: EventCraft Pro
     - User support email: your-email@domain.com
     - Developer contact: your-email@domain.com
   - Add scopes: openid, email, profile

### 2. Set Environment Variables

Create a `.env` file in your project root with:

```env
# Google OAuth Configuration
GOOGLE_CLIENT_ID=your-google-client-id-here
GOOGLE_CLIENT_SECRET=your-google-client-secret-here
GOOGLE_REDIRECT_URI=http://localhost:5000/auth/google/callback

# Flask Configuration
FLASK_ENV=development
SESSION_SECRET=eventcraft-secret-key-2024

# Database Configuration
DATABASE_URL=sqlite:///database/eventcraft.db
```

### 3. For Production Deployment

Update the redirect URI to your production domain:

```env
GOOGLE_REDIRECT_URI=https://yourdomain.com/auth/google/callback
```

### 4. Testing

After setting up the environment variables:

1. Restart your Flask application
2. Visit: `http://localhost:5000/oauth-status` (to check configuration)
3. Test OAuth: `http://localhost:5000/auth/google`

## Security Notes

- Never commit your `.env` file to version control
- Use environment variables for all sensitive data
- Regularly rotate OAuth credentials
- Monitor OAuth usage in Google Console

## Troubleshooting

If you encounter issues:

1. Check that all environment variables are set correctly
2. Verify the redirect URI matches exactly in Google Console
3. Ensure OAuth consent screen is configured
4. Check server logs for detailed error messages

For more detailed troubleshooting, see `GOOGLE_OAUTH_TROUBLESHOOTING.md`.
