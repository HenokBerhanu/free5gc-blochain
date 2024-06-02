import web3
from eth_account import Account
from eth_account.messages import encode_defunct
import config

# Set up Web3 provider
w3 = web3.Web3(web3.HTTPProvider('http://127.0.0.1:7545'))  # Adjust the provider URL as necessary

# Import ABI and Bytecode from config.py
abi = config.abi
bytecode = config.bytecode

# Example data for testing
availableUEs = [1, 2, 3, 4, 5, 6]
salts = [1, 2, 3, 4, 5, 6]
banUEs = [4, 5, 6]

def chain_deploy():
    # Set the default account for transactions
    w3.eth.default_account = w3.eth.accounts[0]

    # Deploy the contract
    Guard = w3.eth.contract(abi=abi, bytecode=bytecode)
    tx_hash = Guard.constructor().transact()
    tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    contract_address = tx_receipt.contractAddress
    print("Contract Address: ", contract_address)
    return contract_address, abi

def chain_banUser(addrs, contract):
    tx_hash = contract.functions.banUsers(addrs).transact()
    tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)

def chain_getUDMstatus(contract):
    return contract.functions.getUDMStatus().call()

def chain_getStatus(addrs, contract):
    return contract.functions.getSaltStatuses(addrs).call()

def chain_putUE(addrs, salt, contract):
    tx_hash = contract.functions.updateSalts(addrs, salt).transact()
    tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)

def chain_changeUDMstatus(contract):
    tx_hash = contract.functions.changeUDMStatus().transact()
    tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)

# Deploy the contract and get its instance
contract_address, abi = chain_deploy()
contract = w3.eth.contract(address=contract_address, abi=abi)

# Example interactions with the deployed contract
chain_changeUDMstatus(contract)
chain_putUE(availableUEs, salts, contract)  # Setup the UEs
chain_banUser(banUEs, contract)  # Ban some UEs
print(chain_getUDMstatus(contract))
print(chain_getStatus(availableUEs, contract))  # See the result confirming it is working