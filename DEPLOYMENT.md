# Deployment Guide for Render

## Prerequisites
- A Render account
- Your code pushed to a Git repository (GitHub, GitLab, etc.)

## Deployment Steps

### 1. Connect to Render
1. Go to [render.com](https://render.com) and sign up/login
2. Click "New +" and select "Web Service"
3. Connect your Git repository

### 2. Configure the Web Service
- **Name**: v1craft (or your preferred name)
- **Environment**: Python 3
- **Build Command**: `pip install -r requirements.txt`
- **Start Command**: `gunicorn main:app`
- **Plan**: Free (or choose your preferred plan)

### 3. Environment Variables
Set the following environment variables in Render dashboard:

```
SESSION_SECRET=your-secure-secret-key-here
DATABASE_URL=postgresql://username:password@host:port/database_name
FLASK_ENV=production
```

### 4. Database Setup
1. Create a new PostgreSQL database in Render
2. Copy the connection string and set it as `DATABASE_URL`
3. The database will be automatically created when the app starts

### 5. Deploy
Click "Create Web Service" and wait for the deployment to complete.

## Alternative: Using render.yaml
If you prefer, you can use the included `render.yaml` file:
1. Push your code to Git
2. In Render, select "Blueprint" instead of "Web Service"
3. Connect your repository
4. Render will automatically create the service and database

## Important Notes
- The app uses PostgreSQL in production (configured in render.yaml)
- File uploads are stored in the `/uploads` directory
- Make sure your `SESSION_SECRET` is secure and unique
- The app runs on the port provided by Render's `PORT` environment variable

## Troubleshooting
- Check the logs in Render dashboard if deployment fails
- Ensure all dependencies are listed in `requirements.txt`
- Verify environment variables are set correctly
- Make sure the database connection string is valid
