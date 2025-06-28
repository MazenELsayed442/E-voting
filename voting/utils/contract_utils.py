from web3 import Web3
import json
import os
import logging
import glob
from django.conf import settings # Import Django settings

# Get logger
logger = logging.getLogger(__name__)

# Configuration - These should be configurable
# You can override these with environment variables if needed
NODE_URL = os.environ.get("WEB3_NODE_URL", "https://polygon-mainnet.infura.io/v3/982333c3771f4b48adb4f518098a444b")  # Default to Polygon Mainnet

# Contract addresses - loaded from environment variables, with file-based fallback for local dev
VOTING_CONTRACT_ADDRESS = os.environ.get("VOTING_CONTRACT_ADDRESS")
ADMIN_CONTRACT_ADDRESS = os.environ.get("ADMIN_CONTRACT_ADDRESS")

# --- New, simplified ABI paths ---
# We assume the ABI files are located in 'voting/abi/' relative to the project's BASE_DIR
VOTING_ABI_PATH = os.path.join(settings.BASE_DIR, 'voting', 'abi', 'Voting.json')
ADMIN_ABI_PATH = os.path.join(settings.BASE_DIR, 'voting', 'abi', 'VotingAdmin.json')

# Print the contract addresses for debugging
print(f"Using Voting Contract Address: {VOTING_CONTRACT_ADDRESS}")
print(f"Using Admin Contract Address: {ADMIN_CONTRACT_ADDRESS}")

# Default to use for functions
CONTRACT_ADDRESS = VOTING_CONTRACT_ADDRESS

def update_contract_addresses():
    """Try to find and update the latest contract addresses from deployment artifacts"""
    global VOTING_CONTRACT_ADDRESS, ADMIN_CONTRACT_ADDRESS

    latest_json_path = os.path.join('blockchain', 'deployment_logs', 'latest.json')

    if os.path.exists(latest_json_path):
        try:
            with open(latest_json_path, 'r') as f:
                deployment_info = json.load(f)
                VOTING_CONTRACT_ADDRESS = deployment_info['contracts']['Voting']
                ADMIN_CONTRACT_ADDRESS = deployment_info['contracts']['VotingAdmin']
                print(f"Updated contract addresses from {latest_json_path}")
                print(f"  Voting Contract: {VOTING_CONTRACT_ADDRESS}")
                print(f"  Admin Contract: {ADMIN_CONTRACT_ADDRESS}")
                return VOTING_CONTRACT_ADDRESS, ADMIN_CONTRACT_ADDRESS
        except Exception as e:
            print(f"Error reading {latest_json_path}: {e}")

    # Fallback to searching all deployment logs if latest.json is not available
    deployment_logs = []
    possible_paths = [
        'blockchain/deployment_logs/*.json',
        'deployment_logs/*.json',
    ]
    
    for path_pattern in possible_paths:
        logs = glob.glob(path_pattern)
        if logs:
            deployment_logs.extend(logs)

    if deployment_logs:
        # Sort by modification time to get the latest one
        latest_log = sorted(deployment_logs, key=os.path.getmtime, reverse=True)[0]
        if latest_log.endswith('latest.json'): # dont re-read if we checked it
            if len(deployment_logs) > 1:
                latest_log = sorted([l for l in deployment_logs if not l.endswith('latest.json')], key=os.path.getmtime, reverse=True)[0]
            else:
                latest_log = None

        if latest_log:
            try:
                with open(latest_log, 'r') as f:
                    deployment_info = json.load(f)
                    VOTING_CONTRACT_ADDRESS = deployment_info['contracts']['Voting']
                    ADMIN_CONTRACT_ADDRESS = deployment_info['contracts']['VotingAdmin']
                    print(f"Updated contract addresses from latest log: {latest_log}")
                    print(f"  Voting Contract: {VOTING_CONTRACT_ADDRESS}")
                    print(f"  Admin Contract: {ADMIN_CONTRACT_ADDRESS}")
                    return VOTING_CONTRACT_ADDRESS, ADMIN_CONTRACT_ADDRESS
            except Exception as e:
                print(f"Error reading deployment log {latest_log}: {e}")

    # The rest of the function (cache fallback) can remain as a last resort
    # ... but for polygon deployment, we rely on the json files.

    return VOTING_CONTRACT_ADDRESS, ADMIN_CONTRACT_ADDRESS

def get_web3():
    """Get Web3 connection to the Ethereum node"""
    global VOTING_CONTRACT_ADDRESS, ADMIN_CONTRACT_ADDRESS

    # --- Environment-aware Address Loading ---
    # On Render (or any platform that sets these env vars), we trust the env vars exclusively.
    # For local development, if the env vars aren't set, we fall back to reading the deployment file.
    is_production_env = VOTING_CONTRACT_ADDRESS and ADMIN_CONTRACT_ADDRESS

    if not is_production_env:
        print("Production contract addresses not found in environment, trying file-based lookup for local development...")
        # update_contract_addresses will read from latest.json and update the global vars
        updated_voting_addr, updated_admin_addr = update_contract_addresses()
        VOTING_CONTRACT_ADDRESS = updated_voting_addr
        ADMIN_CONTRACT_ADDRESS = updated_admin_addr

    try:
        # Use the configured node URL
        print(f"Connecting to Ethereum node at: {NODE_URL}")
        web3 = Web3(Web3.HTTPProvider(NODE_URL))
        
        # Test the connection by checking if it's connected
        if not web3.is_connected():
            print(f"WARNING: Web3 provider is not connected at {NODE_URL}. Check if Hardhat is running.")
        else:
            # Get network info for debugging
            try:
                chain_id = web3.eth.chain_id
                block_number = web3.eth.block_number
                print(f"Connected to chain ID: {chain_id}, latest block: {block_number}")
            except Exception as e:
                print(f"Connected but couldn't get chain info: {e}")
        
        return web3
    except Exception as e:
        print(f"ERROR connecting to Web3: {e}")
        # Return a disconnected Web3 instance rather than raising an exception
        return Web3(Web3.HTTPProvider(NODE_URL))

def load_abi(abi_path):
    """Load ABI from the specified file path."""
    try:
        with open(abi_path, "r") as f:
            # The ABI is the value of the 'abi' key in the JSON file.
            abi = json.load(f)["abi"]
            print(f"Successfully loaded ABI from: {abi_path}")
            return abi
    except FileNotFoundError:
        logger.error(f"FATAL: ABI file not found at {abi_path}. The application cannot function without it.")
        # In a production environment, you might want to raise an exception
        # to prevent the app from running in a broken state.
        raise
    except (KeyError, json.JSONDecodeError) as e:
        logger.error(f"FATAL: Error reading or parsing ABI file at {abi_path}: {e}")
        # This also indicates a critical problem.
        raise

def get_minimal_abi():
    """Return a minimal ABI with common functions"""
    return [
        {
            "inputs": [],
            "name": "getPoolCount",
            "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}],
            "stateMutability": "view",
            "type": "function"
        },
        {
            "inputs": [
                {"internalType": "uint256", "name": "_poolId", "type": "uint256"},
                {"internalType": "string", "name": "_candidate", "type": "string"}
            ],
            "name": "getVotes",
            "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}],
            "stateMutability": "view",
            "type": "function"
        },
        {
            "inputs": [{"internalType": "uint256", "name": "_poolId", "type": "uint256"}],
            "name": "getPoolDetails",
            "outputs": [
                {"internalType": "uint256", "name": "id", "type": "uint256"},
                {"internalType": "string", "name": "category", "type": "string"},
                {"internalType": "string[]", "name": "candidates", "type": "string[]"},
                {"internalType": "uint256", "name": "startTime", "type": "uint256"},
                {"internalType": "uint256", "name": "endTime", "type": "uint256"},
                {"internalType": "uint8", "name": "status", "type": "uint8"}
            ],
            "stateMutability": "view",
            "type": "function"
        }
    ]

def get_contract(contract_type='voting'):
    """Get contract instance with loaded ABI
    
    Args:
        contract_type: Either 'voting' or 'admin' to specify which contract to load
    """
    if contract_type.lower() == 'admin':
        address = ADMIN_CONTRACT_ADDRESS
        abi_path = ADMIN_ABI_PATH
    else:  # Default to voting contract
        address = VOTING_CONTRACT_ADDRESS
        abi_path = VOTING_ABI_PATH
    
    print(f"Getting {contract_type} contract at address: {address}")
    
    abi = load_abi(abi_path)
    web3 = get_web3()
    return web3.eth.contract(address=address, abi=abi)

def get_voting_contract():
    """Get the voting contract specifically"""
    return get_contract('voting')

def get_admin_contract():
    """Get the admin contract specifically"""
    return get_contract('admin')

def get_vote_count(candidate, pool_id=0):
    """Get vote count for a candidate in a specific pool"""
    contract = get_voting_contract()
    print(f"Getting vote count for candidate '{candidate}' in pool {pool_id}")
    return contract.functions.getVotes(pool_id, candidate).call()

def submit_vote(candidate, private_key, pool_id=0):
    """Submit a vote transaction to the blockchain"""
    web3 = get_web3()
    contract = get_voting_contract()
    account = web3.eth.account.from_key(private_key)
    print(f"Submitting vote from {account.address} for '{candidate}' in pool {pool_id}")
    
    nonce = web3.eth.get_transaction_count(account.address)
    
    try:
        chain_id = web3.eth.chain_id
    except:
        chain_id = 31337  # Default Hardhat chain ID
    
    txn = contract.functions.vote(pool_id, candidate).build_transaction({
        'chainId': chain_id,
        'gas': 1000000,
        'gasPrice': web3.eth.gas_price,
        'nonce': nonce,
    })
    
    signed_txn = web3.eth.account.sign_transaction(txn, private_key)
    txn_hash = web3.eth.send_raw_transaction(signed_txn.rawTransaction)
    return txn_hash.hex()

def get_pool_details(pool_id):
    """Get detailed information about a voting pool"""
    contract = get_voting_contract()
    print(f"Getting details for pool {pool_id}")
    return contract.functions.getPoolDetails(pool_id).call()

def get_pool_count():
    """Get the total number of voting pools"""
    contract = get_voting_contract()
    print("Getting total pool count")
    try:
        count = contract.functions.getPoolCount().call()
        print(f"Pool count from blockchain: {count}")
        return count
    except Exception as e:
        print(f"Error getting pool count: {e}")
        return 0

def get_voting_contract_address():
    """Return the voting contract address"""
    update_contract_addresses()  # Try to update before returning
    return VOTING_CONTRACT_ADDRESS

def get_admin_contract_address():
    """Return the admin contract address"""
    update_contract_addresses()  # Try to update before returning
    return ADMIN_CONTRACT_ADDRESS