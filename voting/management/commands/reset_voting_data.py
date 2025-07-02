from django.core.management.base import BaseCommand
from django.core.cache import cache
from django.db import connection
from voting.models import Candidate, Category, PoolCancellationRequest, AdminReplacementRequest


class Command(BaseCommand):
    help = 'Resets all voting data while preserving user accounts - Production safe version'

    def add_arguments(self, parser):
        parser.add_argument(
            '--force',
            action='store_true',
            help='Force execution without confirmation prompt',
        )

    def handle(self, *args, **options):
        self.stdout.write(self.style.WARNING('===== E-Voting Data Reset ====='))
        
        # In production (Render), we skip the confirmation unless --force is used
        if not options['force']:
            self.stdout.write(
                self.style.ERROR(
                    'This command will delete all voting data. '
                    'Use --force flag to confirm execution.'
                )
            )
            return

        self.stdout.write('Starting data reset process...')

        # Clear cached data first
        self.clear_cache()
        
        # Delete all voting data
        self.delete_voting_data()
        
        # Clean tables with raw SQL if needed
        self.clean_tables_raw()
        
        self.stdout.write(
            self.style.SUCCESS('✅ Data reset completed successfully!')
        )
        self.stdout.write(
            self.style.WARNING('Note: User accounts were preserved.')
        )

    def clear_cache(self):
        """Clear all cached blockchain data"""
        cache_keys = [
            'last_blockchain_block',
            'active_pools', 
            'pool_categories',
            'blockchain_data'
        ]
        
        for key in cache_keys:
            cache.delete(key)
        
        self.stdout.write('✅ Cleared cached data')

    def delete_voting_data(self):
        """Delete all voting-related data using Django ORM"""
        
        # Delete all Candidates
        try:
            candidate_count, _ = Candidate.objects.all().delete()
            self.stdout.write(f'✅ Deleted {candidate_count} Candidate objects')
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'❌ Error deleting Candidates: {e}')
            )

        # Delete all Categories
        try:
            category_count, _ = Category.objects.all().delete()
            self.stdout.write(f'✅ Deleted {category_count} Category objects')
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'❌ Error deleting Categories: {e}')
            )
            
        # Delete all Pool Cancellation Requests
        try:
            pool_req_count, _ = PoolCancellationRequest.objects.all().delete()
            self.stdout.write(f'✅ Deleted {pool_req_count} PoolCancellationRequest objects')
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'❌ Error deleting PoolCancellationRequests: {e}')
            )
            
        # Delete all Admin Replacement Requests
        try:
            admin_req_count, _ = AdminReplacementRequest.objects.all().delete()
            self.stdout.write(f'✅ Deleted {admin_req_count} AdminReplacementRequest objects')
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'❌ Error deleting AdminReplacementRequests: {e}')
            )

    def clean_tables_raw(self):
        """Clean tables using raw SQL as a backup measure"""
        tables_to_clean = [
            'voting_candidate',
            'voting_category', 
            'voting_poolcancellationrequest',
            'voting_adminreplacementrequest'
        ]
        
        with connection.cursor() as cursor:
            for table in tables_to_clean:
                try:
                    cursor.execute(f"DELETE FROM {table}")
                    self.stdout.write(f'✅ Cleaned table {table}')
                except Exception as e:
                    self.stdout.write(
                        self.style.WARNING(f'⚠️  Could not clean table {table}: {e}')
                    ) 