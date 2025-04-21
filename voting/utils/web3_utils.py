import json
from web3 import Web3

# Path to Voting.json (update this path based on your project structure)
VOTING_CONTRACT_PATH = "artifacts/contracts/Voting.sol/Voting.json"
CONTRACT_ADDRESS = "0x5FbDB2315678afecb367f032d93F642f64180aa3"  # Replace with your deployed address

def get_web3():
    return Web3(Web3.HTTPProvider("http://127.0.0.1:8545"))

def get_contract():
    # Load ABI from Voting.json
    with open(VOTING_CONTRACT_PATH, "r") as f:
        contract_data = json.load(f)
    abi = contract_data["abi"]
    
    # Initialize contract
    web3 = get_web3()
    return web3.eth.contract(address=CONTRACT_ADDRESS, abi=abi)