# Database Migration Guide

## Problem
If you see the error message: **"Database schema needs updating. Please contact administrator."**, it means your database is missing some required columns or tables.

## Solution
Run the migration script to update your database schema.

## Steps to Run Migration

### Option 1: Using Python directly (Recommended)

1. **SSH into your server** (if using Render, use the Shell feature in the Render dashboard)

2. **Navigate to your project directory**
   ```bash
   cd /path/to/your/project
   ```

3. **Run the migration script**
   ```bash
   python add_missing_columns.py
   ```

4. **Verify the output**
   You should see messages like:
   ```
   ============================================================
   Step 1: Checking invitations table columns...
   ============================================================
   ✓ Column enable_personal_messages already exists
   ✓ Successfully added enable_voice_message
   ...
   ============================================================
   ✓ Database schema update complete!
   ============================================================
   ```

### Option 2: Using Flask Shell

1. **SSH into your server**

2. **Start Flask shell**
   ```bash
   flask shell
   ```

3. **Run the migration function**
   ```python
   from add_missing_columns import add_missing_columns
   add_missing_columns()
   ```

### Option 3: Using Python REPL

1. **SSH into your server**

2. **Start Python**
   ```bash
   python
   ```

3. **Run the migration**
   ```python
   from app import app
   from add_missing_columns import add_missing_columns
   with app.app_context():
       add_missing_columns()
   ```

## What the Migration Does

The migration script will:

1. **Add missing columns to `invitations` table:**
   - `enable_personal_messages` (BOOLEAN)
   - `enable_countdown` (BOOLEAN)
   - `countdown_mystery_mode` (BOOLEAN)
   - `enable_voice_message` (BOOLEAN)
   - `voice_message_url` (VARCHAR)
   - `voice_message_duration` (INTEGER)

2. **Create `memories` table** (if it doesn't exist):
   - Stores guest memories/photos for invitations
   - Includes fields: id, invitation_id, guest_name, guest_email, photo_url, memory_text, uploaded_at, approved, likes

3. **Create `personal_messages` table** (if it doesn't exist):
   - Stores personalized messages for guests
   - Includes fields: id, invitation_id, guest_email, guest_name, message_template, generated_message, viewed_at, created_at
   - Creates an index on (invitation_id, guest_email) for faster lookups

## Database Compatibility

The script automatically detects whether you're using:
- **SQLite** (local development)
- **PostgreSQL** (production/Render)

And uses the appropriate SQL syntax for each.

## Troubleshooting

### Error: "Table 'invitations' does not exist"
- Run `db.create_all()` first to create all base tables
- Then run the migration script

### Error: "Column already exists"
- This is normal if the column was already added
- The script will skip existing columns

### Error: "Permission denied"
- Make sure you have write permissions to the database
- Check your database connection string in environment variables

### Still seeing the error after migration?
- Clear your browser cache
- Restart your Flask application
- Check application logs for specific database errors

## Safety

- The script is **safe to run multiple times** - it checks if columns/tables exist before creating them
- It **does not delete or modify existing data**
- It only **adds** missing columns and tables

## Need Help?

If you continue to see errors after running the migration:
1. Check the application logs for detailed error messages
2. Verify your database connection is working
3. Ensure all environment variables are set correctly
4. Contact support with the error logs

