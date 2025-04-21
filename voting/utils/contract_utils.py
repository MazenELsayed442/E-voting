from web3 import Web3
import json

# Configuration
CONTRACT_ADDRESS = "0x5FbDB2315678afecb367f032d93F642f64180aa3"  # Replace with your address
ABI_PATH = "artifacts/contracts/Voting.sol/Voting.json"

def get_web3():
    return Web3(Web3.HTTPProvider("http://127.0.0.1:8545"))

def get_contract():
    with open(ABI_PATH, "r") as f:
        abi = json.load(f)["abi"]
    return get_web3().eth.contract(address=CONTRACT_ADDRESS, abi=abi)

def get_vote_count(candidate):
    contract = get_contract()
    return contract.functions.getVotes(candidate).call()

def submit_vote(candidate, private_key):
    web3 = get_web3()
    contract = get_contract()
    account = web3.eth.account.from_key(private_key)
    nonce = web3.eth.get_transaction_count(account.address)
    
    txn = contract.functions.vote(candidate).build_transaction({
        'chainId': 31337,
        'gas': 1000000,
        'gasPrice': web3.eth.gas_price,
        'nonce': nonce,
    })
    
    signed_txn = web3.eth.account.sign_transaction(txn, private_key)
    txn_hash = web3.eth.send_raw_transaction(signed_txn.rawTransaction)
    return txn_hash.hex()