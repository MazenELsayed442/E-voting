import os
import django

# Setup Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'eVoting.settings')
django.setup()

# Import the Candidate model and any other relevant models
from voting.models import Candidate
from django.core.cache import cache
from django.db import connection

# Clear all candidates
candidate_count = Candidate.objects.all().delete()[0]
print(f"Deleted all {candidate_count} candidates from the database")

# Clear any cached blockchain data
cache_keys = [
    'last_blockchain_block',
    'active_pools', 
    'pool_categories',
    'blockchain_data'
]
            
for key in cache_keys:
    cache.delete(key)
print("Cleared all blockchain-related cache entries")

# Execute raw SQL to ensure tables are completely clean
# This is needed because some databases might have related tables or constraints
with connection.cursor() as cursor:
    # List tables you want to clean (be cautious with this approach)
    tables_to_clean = [
        'voting_candidate',  # Main candidate table
    ]
    
    for table in tables_to_clean:
        try:
            # Use TRUNCATE or DELETE depending on database type
            cursor.execute(f"DELETE FROM {table}")
            print(f"Cleaned table {table}")
        except Exception as e:
            print(f"Error cleaning table {table}: {e}")

print("\nDatabase completely cleaned of all voting data.")
print("Please restart the application to ensure all caches are reset.") 