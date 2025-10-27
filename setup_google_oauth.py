#!/usr/bin/env python3
"""
Google OAuth Setup Helper Script

This script helps you set up Google OAuth for EventCraft Pro.
Follow these steps to configure Google OAuth:

1. Go to Google Cloud Console: https://console.cloud.google.com/
2. Create a new project or select an existing one
3. Enable the Google+ API
4. Go to "Credentials" and create OAuth 2.0 Client ID
5. Set the authorized redirect URI to: http://localhost:5000/auth/google/callback
6. Copy the Client ID and Client Secret

Then run this script to set up your environment variables.
"""

import os
import sys

def setup_google_oauth():
    print("Google OAuth Setup for EventCraft Pro")
    print("=" * 50)
    
    # Check if already configured
    client_id = os.environ.get('GOOGLE_CLIENT_ID')
    client_secret = os.environ.get('GOOGLE_CLIENT_SECRET')
    
    if client_id and client_secret:
        print("Google OAuth is already configured!")
        print(f"Client ID: {client_id[:10]}...")
        return True
    
    print("Google OAuth is not configured.")
    print("\nSetup Instructions:")
    print("1. Go to Google Cloud Console: https://console.cloud.google.com/")
    print("2. Create a new project or select an existing one")
    print("3. Enable the Google+ API")
    print("4. Go to 'Credentials' and create OAuth 2.0 Client ID")
    print("5. Set the authorized redirect URI to: http://localhost:5000/auth/google/callback")
    print("6. Copy the Client ID and Client Secret")
    
    print("\nEnter your Google OAuth credentials:")
    
    try:
        client_id = input("Client ID: ").strip()
        client_secret = input("Client Secret: ").strip()
        
        if not client_id or not client_secret:
            print("Both Client ID and Client Secret are required!")
            return False
        
        # Create .env file
        env_content = f"""# Google OAuth Configuration
GOOGLE_CLIENT_ID={client_id}
GOOGLE_CLIENT_SECRET={client_secret}
GOOGLE_REDIRECT_URI=http://localhost:5000/auth/google/callback

# Session Secret (change this in production)
SESSION_SECRET=eventcraft-secret-key-2024
"""
        
        with open('.env', 'w') as f:
            f.write(env_content)
        
        print("\nConfiguration saved to .env file!")
        print("To use these settings, run:")
        print("   source .env  # On Linux/Mac")
        print("   # Or set them manually in your environment")
        
        return True
        
    except KeyboardInterrupt:
        print("\nSetup cancelled.")
        return False
    except Exception as e:
        print(f"Error: {e}")
        return False

def check_configuration():
    """Check if Google OAuth is properly configured"""
    print("\nChecking Google OAuth Configuration...")
    
    # Try to import and check
    try:
        from app import app
        with app.app_context():
            client_id = app.config.get('GOOGLE_CLIENT_ID')
            client_secret = app.config.get('GOOGLE_CLIENT_SECRET')
            redirect_uri = app.config.get('GOOGLE_REDIRECT_URI')
            
            print(f"Client ID: {'Set' if client_id else 'Not set'}")
            print(f"Client Secret: {'Set' if client_secret else 'Not set'}")
            print(f"Redirect URI: {redirect_uri}")
            
            if client_id and client_secret:
                print("\nGoogle OAuth is properly configured!")
                return True
            else:
                print("\nGoogle OAuth is not properly configured!")
                return False
                
    except Exception as e:
        print(f"Error checking configuration: {e}")
        return False

if __name__ == "__main__":
    print("EventCraft Pro - Google OAuth Setup")
    print("=" * 40)
    
    if len(sys.argv) > 1 and sys.argv[1] == "check":
        check_configuration()
    else:
        setup_google_oauth()
        print("\n" + "=" * 50)
        check_configuration()
