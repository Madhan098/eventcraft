# Gmail SMTP Setup Guide for EventCraft Pro

## Issue
OTP emails are not being sent due to Gmail authentication failures. The error shows:
```
535-5.7.8 Username and Password not accepted
```

## Solution

### Step 1: Enable 2-Factor Authentication
1. Go to [Google Account Security](https://myaccount.google.com/security)
2. Enable 2-Factor Authentication if not already enabled
3. This is required to generate app-specific passwords

### Step 2: Generate App Password
1. Go to [Google Account Security](https://myaccount.google.com/security)
2. Click on "2-Step Verification"
3. Scroll down to "App passwords"
4. Click "Select app" and choose "Mail"
5. Click "Select device" and choose "Other (custom name)"
6. Enter "EventCraft Pro" as the name
7. Click "Generate"
8. **Copy the 16-character password** (it will look like: `abcd efgh ijkl mnop`)

### Step 3: Set Environment Variables

#### For Local Development:
Create a `.env` file in your project root:
```env
SMTP_USERNAME=your-gmail@gmail.com
SMTP_PASSWORD=your-16-character-app-password
```

#### For Render Deployment:
1. Go to your Render dashboard
2. Select your EventCraft Pro service
3. Go to "Environment" tab
4. Add these environment variables:
   - `SMTP_USERNAME`: your-gmail@gmail.com
   - `SMTP_PASSWORD`: your-16-character-app-password

### Step 4: Test Email Configuration
The application will now use the environment variables for SMTP authentication.

## Important Notes

1. **Never use your regular Gmail password** - always use app-specific passwords
2. **App passwords expire** - you may need to regenerate them periodically
3. **Check spam folder** - OTP emails might be filtered as spam
4. **Use a dedicated Gmail account** for production applications

## Troubleshooting

If emails still don't work:

1. **Verify app password**: Make sure you're using the 16-character app password, not your regular password
2. **Check 2FA**: Ensure 2-Factor Authentication is enabled on your Google account
3. **Test with different email**: Try sending to a different email address
4. **Check Gmail security**: Go to [Gmail Security Checkup](https://myaccount.google.com/security-checkup)
5. **Review recent activity**: Check for any security alerts in your Google account

## Alternative Email Services

If Gmail continues to have issues, consider these alternatives:
- **SendGrid**: Professional email service with free tier
- **Mailgun**: Developer-friendly email API
- **Amazon SES**: AWS email service
- **Outlook/Hotmail**: Microsoft's email service

## Current Status
- ✅ Updated `utils.py` to use environment variables
- ✅ Added better error handling and troubleshooting
- ⏳ **Next**: Set up environment variables in Render dashboard
- ⏳ **Next**: Test OTP email functionality
