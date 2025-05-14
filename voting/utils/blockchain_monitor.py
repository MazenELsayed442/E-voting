import os
import json
from pathlib import Path
from django.db import transaction
from django.core.cache import cache

from voting.models import Candidate


class BlockchainMonitor:
    """
    Utility class to monitor blockchain status and handle restarts
    """
    LAST_BLOCK_KEY = 'last_blockchain_block'  # Cache key for storing block number
    
    @classmethod
    def check_blockchain_reset(cls, web3):
        """
        Check if the blockchain has been reset (restarted)
        Returns True if a reset is detected, False otherwise
        """
        if not web3.is_connected():
            return False
            
        try:
            # Get current block number
            current_block = web3.eth.block_number
            
            # Get last known block number from cache
            last_block = cache.get(cls.LAST_BLOCK_KEY)
            
            # If we've never checked before, store current block and return False
            if last_block is None:
                cache.set(cls.LAST_BLOCK_KEY, current_block)
                return False
                
            # If current block is lower than last known block, blockchain was reset
            reset_detected = current_block < last_block
            
            # Store new block number
            cache.set(cls.LAST_BLOCK_KEY, current_block)
            
            return reset_detected
            
        except Exception as e:
            print(f"Error checking blockchain reset: {e}")
            return False
    
    @classmethod
    def handle_blockchain_reset(cls):
        """
        Handle blockchain reset by cleaning the database
        """
        with transaction.atomic():
            # Clear all candidates completely - this will remove all categories too
            # since categories are attached to candidates
            deleted_count = Candidate.objects.all().delete()[0]
            
            # Clear any cache related to blockchain data
            cache_keys = [
                'active_pools', 
                'pool_categories',
                'blockchain_data'
            ]
            
            for key in cache_keys:
                cache.delete(key)
                
            print(f"Blockchain reset detected: Deleted {deleted_count} candidates and cleared all categories")
            return deleted_count
    
    @classmethod
    def process_blockchain_connection(cls, web3):
        """
        Main method to process blockchain connection status
        Returns a tuple (reset_detected, deleted_count)
        """
        if cls.check_blockchain_reset(web3):
            deleted_count = cls.handle_blockchain_reset()
            return True, deleted_count
        return False, 0 