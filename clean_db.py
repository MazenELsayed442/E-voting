import os
import django

# Setup Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'eVoting.settings')
django.setup()

# Import the Candidate model
from voting.models import Candidate

# List of old hardcoded categories we want to remove
old_categories = ["President", "Vice President", "Secretary", "test"]

# Delete all candidates with these categories
deleted_count = Candidate.objects.filter(category__in=old_categories).delete()[0]

print(f"Deleted {deleted_count} candidates with old hardcoded categories")

# You can uncomment this if you want to see what's left in the database
remaining = Candidate.objects.all()
print(f"\nRemaining candidates in database: {remaining.count()}")
for candidate in remaining:
    print(f" - {candidate.name} (Category: {candidate.category})") 