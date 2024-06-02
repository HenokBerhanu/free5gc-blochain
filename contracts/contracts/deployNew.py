import web3
from eth_account import Account
from eth_account.messages import encode_defunct
import config

# Config Part
w3 = web3.Web3(web3.HTTPProvider('http://172.18.0.2:8545'))
bytecode = config.bytecode
abi = config.abi

availableUEs = ["0x9F2f46c24fF6F7dB5FB371E736B58CD3835a6d78", "0x2FC53e4F6788e85045e019FA9D75930c4804cA39"]
salts = [1, 1]
banUEs = ["0x9F2f46c24fF6F7dB5FB371E736B58CD3835a6d78"]

# Example private keys from Ganache
private_key_good = '0x993ffe8ff6cf47825b907c2590fe6576d653c9e009503b33dfa8ed5376cff121'
private_key_bad = '0xcf92e7a8e29276d6574d889a26258605a14f3cbe7ac68b5226d00927f1f09b7d'


def generate_signature(message, private_key):
    message_hash = w3.keccak(text=message)
    signed_message = Account.sign_message(encode_defunct(message_hash), private_key=private_key)
    return signed_message.signature.hex()

def chain_deploy():
    # This is the Home Network which is the owner of the contract
    w3.eth.default_account = w3.eth.accounts[0]

    # Deployment
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

contract_address, abi = chain_deploy()
contract = w3.eth.contract(address=contract_address, abi=abi)

chain_changeUDMstatus(contract)
chain_putUE(availableUEs, salts, contract) # setup the UEs
chain_banUser(banUEs, contract) # ban some UEs
print(chain_getUDMstatus(contract))
print(chain_getStatus(availableUEs, contract)) # See the result confirming it is working

# Generate signatures
example_message = "hello"
good_signature = generate_signature(example_message, private_key_good)
bad_signature = generate_signature(example_message, private_key_bad)

print("Good Signature:", good_signature)
print("Bad Signature:", bad_signature)
