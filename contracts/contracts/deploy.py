import web3
from eth_account import Account
from eth_account.messages import encode_defunct
import config

# Config Part
w3 = web3.Web3(web3.HTTPProvider('http://172.19.0.2:7545'))
bytecode = config.bytecode
abi = config.abi

availableUEs = ["0x74503A514bA1710FaB05BF1652785Fb08FBA5007", "0x82d9Adf8a8529e2464E347EE0CaD9320eeF4E411"]
salts = [1,1]
banUEs = ["0x74503A514bA1710FaB05BF1652785Fb08FBA5007"]

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
