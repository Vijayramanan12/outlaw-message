
#!/usr/bin/env python3

import sqlite3
import os

def migrate_database():
    """Add new columns for Zero-Knowledge and blockchain features"""
    db_path = 'instance/messenger.db'
    
    # Create instance directory if it doesn't exist
    os.makedirs('instance', exist_ok=True)
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    try:
        # Check if columns exist before adding them
        cursor.execute("PRAGMA table_info(user)")
        user_columns = [column[1] for column in cursor.fetchall()]
        
        # Add missing user columns
        if 'public_key' not in user_columns:
            cursor.execute("ALTER TABLE user ADD COLUMN public_key TEXT")
            print("Added public_key column to user table")
            
        if 'private_key_encrypted' not in user_columns:
            cursor.execute("ALTER TABLE user ADD COLUMN private_key_encrypted TEXT")
            print("Added private_key_encrypted column to user table")
        
        # Check message table
        cursor.execute("PRAGMA table_info(message)")
        message_columns = [column[1] for column in cursor.fetchall()]
        
        # Add missing message columns
        if 'blockchain_hash' not in message_columns:
            cursor.execute("ALTER TABLE message ADD COLUMN blockchain_hash VARCHAR(64)")
            print("Added blockchain_hash column to message table")
            
        if 'blockchain_block_id' not in message_columns:
            cursor.execute("ALTER TABLE message ADD COLUMN blockchain_block_id VARCHAR(64)")
            print("Added blockchain_block_id column to message table")
            
        if 'encrypted_for_recipients' not in message_columns:
            cursor.execute("ALTER TABLE message ADD COLUMN encrypted_for_recipients TEXT")
            print("Added encrypted_for_recipients column to message table")
        
        conn.commit()
        print("Database migration completed successfully!")
        
    except Exception as e:
        print(f"Migration error: {e}")
        conn.rollback()
    finally:
        conn.close()

if __name__ == "__main__":
    migrate_database()
