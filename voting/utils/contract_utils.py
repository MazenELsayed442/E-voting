from web3 import Web3
import json
import os
import logging
from django.conf import settings

logger = logging.getLogger(__name__)

# --- Configuration ---
# The node URL and contract addresses should be set as environment variables in production.
NODE_URL = os.environ.get("WEB3_NODE_URL", "https://polygon-mainnet.infura.io/v3/982333c3771f4b48adb4f518098a444b")
VOTING_CONTRACT_ADDRESS = os.environ.get("VOTING_CONTRACT_ADDRESS")
ADMIN_CONTRACT_ADDRESS = os.environ.get("ADMIN_CONTRACT_ADDRESS")

# --- ABI Paths ---
# We assume the ABI files are located in 'voting/abi/' relative to the project's BASE_DIR
VOTING_ABI_PATH = os.path.join(settings.BASE_DIR, 'voting', 'abi', 'Voting.json')
ADMIN_ABI_PATH = os.path.join(settings.BASE_DIR, 'voting', 'abi', 'VotingAdmin.json')


def get_web3():
    """Get Web3 connection to the Ethereum node."""
    # This check ensures that the application will fail fast in production if the addresses are not set.
    if not VOTING_CONTRACT_ADDRESS or not ADMIN_CONTRACT_ADDRESS:
        logger.critical("FATAL: VOTING_CONTRACT_ADDRESS and ADMIN_CONTRACT_ADDRESS must be set in the environment.")
        # The connection will likely fail anyway, but this makes the reason clear.

    try:
        logger.info(f"Connecting to Ethereum node at: {NODE_URL}")
        web3 = Web3(Web3.HTTPProvider(NODE_URL))
        
        if not web3.is_connected():
            logger.warning(f"Web3 provider is not connected at {NODE_URL}. Check node provider or network.")
        else:
            try:
                chain_id = web3.eth.chain_id
                block_number = web3.eth.block_number
                logger.info(f"Successfully connected to chain ID: {chain_id}, latest block: {block_number}")
            except Exception as e:
                logger.warning(f"Connected, but could not retrieve chain info: {e}")
        
        return web3
    except Exception as e:
        logger.error(f"Error connecting to Web3: {e}")
        # Return a disconnected Web3 instance to avoid crashing the app entirely on startup
        return Web3(Web3.HTTPProvider(NODE_URL))


def load_abi(abi_path):
    """Load ABI from the specified file path."""
    try:
        with open(abi_path, "r") as f:
            abi = json.load(f)["abi"]
            logger.info(f"Successfully loaded ABI from: {abi_path}")
            return abi
    except FileNotFoundError:
        logger.critical(f"FATAL: ABI file not found at {abi_path}. The application cannot function without it.")
        raise
    except (KeyError, json.JSONDecodeError) as e:
        logger.critical(f"FATAL: Error reading or parsing ABI file at {abi_path}: {e}")
        raise


def get_contract(contract_type='voting'):
    """
    Get a contract instance with a loaded ABI.
    
    Args:
        contract_type (str): Either 'voting' or 'admin' to specify which contract to load.
    """
    if contract_type.lower() == 'admin':
        address = ADMIN_CONTRACT_ADDRESS
        abi_path = ADMIN_ABI_PATH
    else:  # Default to voting contract
        address = VOTING_CONTRACT_ADDRESS
        abi_path = VOTING_ABI_PATH
    
    if not address:
        logger.error(f"Contract address for '{contract_type}' is not configured.")
        return None # Return None to indicate failure
    
    logger.debug(f"Getting {contract_type} contract instance at address: {address}")
    
    abi = load_abi(abi_path)
    web3 = get_web3()
    return web3.eth.contract(address=address, abi=abi)


def get_voting_contract():
    """Get the voting contract specifically."""
    return get_contract('voting')


def get_admin_contract():
    """Get the admin contract specifically."""
    return get_contract('admin')


def get_vote_count(candidate, pool_id=0):
    """Get vote count for a candidate in a specific pool."""
    contract = get_voting_contract()
    logger.debug(f"Getting vote count for candidate '{candidate}' in pool {pool_id}")
    return contract.functions.getVotes(pool_id, candidate).call()


def get_pool_details(pool_id):
    """Get detailed information about a voting pool."""
    contract = get_voting_contract()
    logger.debug(f"Getting details for pool {pool_id}")
    return contract.functions.getPoolDetails(pool_id).call()


def get_pool_count():
    """Get the total number of voting pools."""
    contract = get_voting_contract()
    logger.debug("Getting total pool count")
    try:
        return contract.functions.getPoolCount().call()
    except Exception as e:
        logger.error(f"Could not get pool count from contract: {e}")
        return 0


def get_voting_contract_address():
    """Returns the configured Voting contract address."""
    return VOTING_CONTRACT_ADDRESS


def get_admin_contract_address():
    """Returns the configured VotingAdmin contract address."""
    return ADMIN_CONTRACT_ADDRESS