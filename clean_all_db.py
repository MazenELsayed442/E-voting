import sqlite3
import os
## immportant, this file deletes the pending cancel requests and other
# Connect to the SQLite database
db_path = 'db.sqlite3'  # Adjust this path if your database is located elsewhere
conn = sqlite3.connect(db_path)
cursor = conn.cursor()

try:
    # First, let's see what tables exist in the database
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = cursor.fetchall()
    print("Available tables in the database:")
    for table in tables:
        print(f"- {table[0]}")

    # List of tables to clean
    tables_to_clean = [
        'voting_candidate',  # Main candidate table
        'voting_poolcancellationrequest',  # Pool cancellation requests table
    ]
    
    # Delete data from each table
    for table in tables_to_clean:
        try:
            cursor.execute(f"DELETE FROM {table}")
            deleted_count = cursor.rowcount
            print(f"Deleted {deleted_count} records from {table}")
        except Exception as e:
            print(f"Error cleaning table {table}: {e}")
    
    # Commit the changes
    conn.commit()
    print("\nDatabase completely cleaned of all voting data.")

except Exception as e:
    print(f"An error occurred: {e}")
    conn.rollback()

finally:
    # Close the connection
    conn.close() 