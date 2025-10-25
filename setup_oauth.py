#!/usr/bin/env python3
"""
Google OAuth Setup Script for EventCraft Pro
This script helps you set up Google OAuth for both local development and production deployment.
"""

import os
import sys

def setup_local_oauth():
    """Set up OAuth for local development"""
    print("🔧 Setting up Google OAuth for Local Development")
    print("=" * 50)
    
    # Get credentials from user
    client_id = input("Enter your Google Client ID: ").strip()
    client_secret = input("Enter your Google Client Secret: ").strip()
    
    if not client_id or not client_secret:
        print("❌ Error: Both Client ID and Client Secret are required!")
        return False
    
    # Create .env file
    env_content = f"""# Google OAuth Configuration
GOOGLE_CLIENT_ID={client_id}
GOOGLE_CLIENT_SECRET={client_secret}
GOOGLE_REDIRECT_URI=http://localhost:5000/auth/google/callback
SESSION_SECRET=eventcraft-secret-key-2024-secure-random-string
"""
    
    with open('.env', 'w') as f:
        f.write(env_content)
    
    print("✅ Created .env file with your OAuth credentials")
    print("📝 Make sure to add .env to your .gitignore file!")
    
    return True

def setup_render_oauth():
    """Instructions for setting up OAuth on Render"""
    print("\n🚀 Setting up Google OAuth for Render Deployment")
    print("=" * 50)
    
    print("""
1. Go to your Render dashboard: https://dashboard.render.com/
2. Find your EventCraft service and click on it
3. Go to the "Environment" tab
4. Add these environment variables:

   GOOGLE_CLIENT_ID=your_client_id_here
   GOOGLE_CLIENT_SECRET=your_client_secret_here
   SESSION_SECRET=your_secure_session_secret_here

5. Make sure your Google Cloud Console has this redirect URI:
   https://eventcraft-aysl.onrender.com/auth/google/callback

6. Redeploy your application
""")

def main():
    print("🎉 EventCraft Pro - Google OAuth Setup")
    print("=" * 50)
    
    while True:
        print("\nChoose an option:")
        print("1. Set up for local development")
        print("2. Get instructions for Render deployment")
        print("3. Exit")
        
        choice = input("\nEnter your choice (1-3): ").strip()
        
        if choice == '1':
            if setup_local_oauth():
                print("\n✅ Local OAuth setup complete!")
                print("🚀 You can now run: python main.py")
        elif choice == '2':
            setup_render_oauth()
        elif choice == '3':
            print("👋 Goodbye!")
            break
        else:
            print("❌ Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
