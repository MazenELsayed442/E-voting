from web3 import Web3
import json
import os
import logging
import glob

# Get logger
logger = logging.getLogger(__name__)

# Configuration - These should be configurable
# You can override these with environment variables if needed
NODE_URL = os.environ.get("WEB3_NODE_URL", "http://127.0.0.1:8545")  # Default Hardhat port

# Contract addresses - separate admin and voting contracts
# Correct default for voting contract
VOTING_CONTRACT_ADDRESS = os.environ.get("VOTING_CONTRACT_ADDRESS", "0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512")
# Default for admin contract (change this to your actual admin contract address)
ADMIN_CONTRACT_ADDRESS = os.environ.get("ADMIN_CONTRACT_ADDRESS", "0x5FbDB2315678afecb367f032d93F642f64180aa3")

# ABI paths for different contracts
VOTING_ABI_PATH = "artifacts/contracts/Voting.sol/Voting.json"
ADMIN_ABI_PATH = "artifacts/contracts/VotingAdmin.sol/VotingAdmin.json"

# Print the contract addresses for debugging
print(f"Using Voting Contract Address: {VOTING_CONTRACT_ADDRESS}")
print(f"Using Admin Contract Address: {ADMIN_CONTRACT_ADDRESS}")

# Default to use for functions
CONTRACT_ADDRESS = VOTING_CONTRACT_ADDRESS

def update_contract_addresses():
    """Try to find and update the latest contract addresses from deployment artifacts"""
    global VOTING_CONTRACT_ADDRESS, ADMIN_CONTRACT_ADDRESS
    
    # Look for deployment log files
    deployment_logs = []
    # Check multiple potential locations where logs might be stored
    possible_paths = [
        'blockchain/deployment_logs/*.json',
        'deployment_logs/*.json',
        'blockchain/*.log',
        'logs/*.json',
        'blockchain/logs/*.json'
    ]
    
    # Check if there's a deployment flag file from the batch script
    if os.path.exists("deployment_complete.flag"):
        print("Found deployment flag file, contracts should be deployed")
    
    for path_pattern in possible_paths:
        logs = glob.glob(path_pattern)
        if logs:
            deployment_logs.extend(logs)
    
    if not deployment_logs:
        # If no deployment logs found, try to read from hardhat cache
        cache_paths = [
            'blockchain/artifacts/build-info/*.json',
            'artifacts/build-info/*.json'
        ]
        for path_pattern in cache_paths:
            cache_files = glob.glob(path_pattern)
            if cache_files:
                # Sort by modification time to get the latest one
                latest_cache = sorted(cache_files, key=os.path.getmtime, reverse=True)[0]
                try:
                    with open(latest_cache, 'r') as f:
                        cache_data = json.load(f)
                        if 'deployedAddresses' in cache_data:
                            addresses = cache_data['deployedAddresses']
                            for contract_name, address in addresses.items():
                                if 'Voting.sol:Voting' in contract_name:
                                    VOTING_CONTRACT_ADDRESS = address
                                    print(f"Updated Voting contract address from cache: {address}")
                                elif 'VotingAdmin.sol:VotingAdmin' in contract_name:
                                    ADMIN_CONTRACT_ADDRESS = address
                                    print(f"Updated Admin contract address from cache: {address}")
                except Exception as e:
                    print(f"Error reading cache file: {e}")
    
    return VOTING_CONTRACT_ADDRESS, ADMIN_CONTRACT_ADDRESS

def get_web3():
    """Get Web3 connection to Hardhat local node"""
    try:
        # Update contract addresses before connecting
        update_contract_addresses()
        
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
    """Load ABI from file or use fallback minimal ABI"""
    # Try multiple potential locations for the ABI file
    possible_paths = [
        abi_path,
        f"blockchain/{abi_path}",
        os.path.join("blockchain", "artifacts", "contracts", abi_path.split("/")[-2], abi_path.split("/")[-1]),
        os.path.join("artifacts", "contracts", abi_path.split("/")[-2], abi_path.split("/")[-1])
    ]
    
    for path in possible_paths:
        try:
            with open(path, "r") as f:
                abi = json.load(f)["abi"]
                print(f"Loaded ABI from: {path}")
                return abi
        except (FileNotFoundError, KeyError) as e:
            continue
    
    # If we've tried all paths and still don't have the ABI, use the minimal ABI
    print(f"WARNING: Could not find ABI file {abi_path} in any expected location. Using minimal ABI.")
    return get_minimal_abi()

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

def create_pool(category, candidates, start_time, end_time, admin_private_key):
    """Create a new voting pool on the blockchain
    
    Args:
        category: The name/category of the voting pool
        candidates: List of candidate names
        start_time: Unix timestamp for start time
        end_time: Unix timestamp for end time
        admin_private_key: Private key of the admin creating the pool
        
    Returns:
        Transaction hash if successful, None if failed
    """
    web3 = get_web3()
    contract = get_voting_contract()
    account = web3.eth.account.from_key(admin_private_key)
    print(f"Creating pool '{category}' with {len(candidates)} candidates from {account.address}")
    
    nonce = web3.eth.get_transaction_count(account.address)
    
    try:
        chain_id = web3.eth.chain_id
    except:
        chain_id = 31337  # Default Hardhat chain ID
    
    # Build the transaction
    txn = contract.functions.createPool(
        category,
        candidates,
        start_time,
        end_time
    ).build_transaction({
        'chainId': chain_id,
        'gas': 3000000,  # Higher gas limit for contract creation
        'gasPrice': web3.eth.gas_price,
        'nonce': nonce,
    })
    
    # Sign and send the transaction
    try:
        signed_txn = web3.eth.account.sign_transaction(txn, admin_private_key)
        txn_hash = web3.eth.send_raw_transaction(signed_txn.rawTransaction)
        return txn_hash.hex()
    except Exception as e:
        print(f"Error creating pool: {e}")
        return None