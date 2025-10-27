#!/usr/bin/env python3
"""
Database migration script to add indexes and optimize performance
"""

from extensions import db
from models import Invitation, User
from app import create_app
import sqlite3

def add_database_indexes():
    """Add database indexes for better performance"""
    app = create_app()
    
    with app.app_context():
        # Get the database connection
        conn = sqlite3.connect('database/eventcraft.db')
        cursor = conn.cursor()
        
        try:
            # Add indexes for better performance
            indexes = [
                "CREATE INDEX IF NOT EXISTS idx_invitations_share_url ON invitations(share_url)",
                "CREATE INDEX IF NOT EXISTS idx_invitations_user_id ON invitations(user_id)",
                "CREATE INDEX IF NOT EXISTS idx_invitations_expires_at ON invitations(expires_at)",
                "CREATE INDEX IF NOT EXISTS idx_invitations_is_active ON invitations(is_active)",
                "CREATE INDEX IF NOT EXISTS idx_invitations_event_type ON invitations(event_type)",
                "CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)",
                "CREATE INDEX IF NOT EXISTS idx_users_google_id ON users(google_id)",
            ]
            
            for index_sql in indexes:
                cursor.execute(index_sql)
                print(f"Created index: {index_sql}")
            
            conn.commit()
            print("All indexes created successfully!")
            
        except Exception as e:
            print(f"Error creating indexes: {e}")
            conn.rollback()
        finally:
            conn.close()

def update_existing_invitations():
    """Update existing invitations to have expiration dates"""
    app = create_app()
    
    with app.app_context():
        try:
            from datetime import datetime, timedelta
            
            # Update invitations that don't have expiration dates
            invitations = Invitation.query.filter(Invitation.expires_at.is_(None)).all()
            
            for invitation in invitations:
                invitation.expires_at = invitation.created_at + timedelta(days=365)
            
            db.session.commit()
            print(f"Updated {len(invitations)} invitations with expiration dates")
            
        except Exception as e:
            print(f"Error updating invitations: {e}")
            db.session.rollback()

if __name__ == "__main__":
    print("Starting database migration...")
    add_database_indexes()
    update_existing_invitations()
    print("Database migration completed!")
