"""
Script to add missing columns and tables to the database.
Run this script to update your database schema.
"""
import os
from app import app, db
from sqlalchemy import text, inspect

def add_missing_columns():
    """Add missing columns to invitations table and create missing tables if they don't exist."""
    with app.app_context():
        try:
            # Check which database we're using
            db_url = app.config['SQLALCHEMY_DATABASE_URI']
            is_sqlite = 'sqlite' in db_url.lower()
            
            inspector = db.inspect(db.engine)
            existing_tables = inspector.get_table_names()
            
            # Step 1: Add missing columns to invitations table
            print("=" * 60)
            print("Step 1: Checking invitations table columns...")
            print("=" * 60)
            
            if 'invitations' in existing_tables:
                if is_sqlite:
                    # SQLite syntax
                    columns_to_add = [
                        ('enable_personal_messages', 'BOOLEAN DEFAULT 0'),
                        ('enable_countdown', 'BOOLEAN DEFAULT 1'),
                        ('countdown_mystery_mode', 'BOOLEAN DEFAULT 0'),
                        ('enable_voice_message', 'BOOLEAN DEFAULT 0'),
                        ('voice_message_url', 'VARCHAR(500)'),
                        ('voice_message_duration', 'INTEGER')
                    ]
                else:
                    # PostgreSQL syntax
                    columns_to_add = [
                        ('enable_personal_messages', 'BOOLEAN DEFAULT FALSE'),
                        ('enable_countdown', 'BOOLEAN DEFAULT TRUE'),
                        ('countdown_mystery_mode', 'BOOLEAN DEFAULT FALSE'),
                        ('enable_voice_message', 'BOOLEAN DEFAULT FALSE'),
                        ('voice_message_url', 'VARCHAR(500)'),
                        ('voice_message_duration', 'INTEGER')
                    ]
                
                # Check if columns exist and add them if they don't
                existing_columns = [col['name'] for col in inspector.get_columns('invitations')]
                
                for column_name, column_type in columns_to_add:
                    if column_name not in existing_columns:
                        print(f"Adding column: {column_name}")
                        try:
                            with db.engine.connect() as conn:
                                conn.execute(text(f"ALTER TABLE invitations ADD COLUMN {column_name} {column_type}"))
                                conn.commit()
                            print(f"✓ Successfully added {column_name}")
                        except Exception as e:
                            print(f"✗ Error adding {column_name}: {e}")
                    else:
                        print(f"✓ Column {column_name} already exists")
            else:
                print("⚠️  invitations table does not exist. Run db.create_all() first.")
            
            # Step 2: Create memories table if it doesn't exist
            print("\n" + "=" * 60)
            print("Step 2: Checking memories table...")
            print("=" * 60)
            
            if 'memories' not in existing_tables:
                print("Creating memories table...")
                try:
                    if is_sqlite:
                        create_memories_sql = """
                        CREATE TABLE memories (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            invitation_id INTEGER NOT NULL,
                            guest_name VARCHAR(100) NOT NULL,
                            guest_email VARCHAR(120),
                            photo_url VARCHAR(500) NOT NULL,
                            memory_text TEXT NOT NULL,
                            uploaded_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                            approved BOOLEAN DEFAULT 1,
                            likes INTEGER DEFAULT 0,
                            FOREIGN KEY (invitation_id) REFERENCES invitations(id) ON DELETE CASCADE
                        )
                        """
                    else:
                        create_memories_sql = """
                        CREATE TABLE memories (
                            id SERIAL PRIMARY KEY,
                            invitation_id INTEGER NOT NULL,
                            guest_name VARCHAR(100) NOT NULL,
                            guest_email VARCHAR(120),
                            photo_url VARCHAR(500) NOT NULL,
                            memory_text TEXT NOT NULL,
                            uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                            approved BOOLEAN DEFAULT TRUE,
                            likes INTEGER DEFAULT 0,
                            FOREIGN KEY (invitation_id) REFERENCES invitations(id) ON DELETE CASCADE
                        )
                        """
                    
                    with db.engine.connect() as conn:
                        conn.execute(text(create_memories_sql))
                        conn.commit()
                    print("✓ Successfully created memories table")
                except Exception as e:
                    print(f"✗ Error creating memories table: {e}")
            else:
                print("✓ memories table already exists")
            
            # Step 3: Create personal_messages table if it doesn't exist
            print("\n" + "=" * 60)
            print("Step 3: Checking personal_messages table...")
            print("=" * 60)
            
            if 'personal_messages' not in existing_tables:
                print("Creating personal_messages table...")
                try:
                    if is_sqlite:
                        create_personal_messages_sql = """
                        CREATE TABLE personal_messages (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            invitation_id INTEGER NOT NULL,
                            guest_email VARCHAR(120) NOT NULL,
                            guest_name VARCHAR(100) NOT NULL,
                            message_template VARCHAR(50),
                            generated_message TEXT NOT NULL,
                            viewed_at DATETIME,
                            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                            FOREIGN KEY (invitation_id) REFERENCES invitations(id) ON DELETE CASCADE
                        )
                        """
                        # SQLite doesn't support CREATE INDEX in the same statement
                        create_index_sql = """
                        CREATE INDEX idx_invitation_guest ON personal_messages(invitation_id, guest_email)
                        """
                    else:
                        create_personal_messages_sql = """
                        CREATE TABLE personal_messages (
                            id SERIAL PRIMARY KEY,
                            invitation_id INTEGER NOT NULL,
                            guest_email VARCHAR(120) NOT NULL,
                            guest_name VARCHAR(100) NOT NULL,
                            message_template VARCHAR(50),
                            generated_message TEXT NOT NULL,
                            viewed_at TIMESTAMP,
                            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                            FOREIGN KEY (invitation_id) REFERENCES invitations(id) ON DELETE CASCADE
                        )
                        """
                        create_index_sql = """
                        CREATE INDEX idx_invitation_guest ON personal_messages(invitation_id, guest_email)
                        """
                    
                    with db.engine.connect() as conn:
                        conn.execute(text(create_personal_messages_sql))
                        conn.commit()
                        # Create index separately (works for both SQLite and PostgreSQL)
                        try:
                            conn.execute(text(create_index_sql))
                            conn.commit()
                        except Exception as idx_error:
                            # Index might already exist, which is fine
                            if 'already exists' not in str(idx_error).lower() and 'duplicate' not in str(idx_error).lower():
                                print(f"⚠️  Warning: Could not create index: {idx_error}")
                    print("✓ Successfully created personal_messages table")
                except Exception as e:
                    print(f"✗ Error creating personal_messages table: {e}")
            else:
                print("✓ personal_messages table already exists")
            
            print("\n" + "=" * 60)
            print("✓ Database schema update complete!")
            print("=" * 60)
            
        except Exception as e:
            print(f"\n✗ Error updating database schema: {e}")
            import traceback
            traceback.print_exc()

if __name__ == '__main__':
    add_missing_columns()

