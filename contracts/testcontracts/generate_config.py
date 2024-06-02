import json

# Paths to the ABI and BIN files
abi_file_path = "/home/henok/free5gc-blochain/contracts/testcontracts/build/test.abi"
bin_file_path = "/home/henok/free5gc-blochain/contracts/testcontracts/build/test.bin"

# Read the ABI file
with open(abi_file_path, "r") as abi_file:
    abi = json.load(abi_file)

# Read the BIN file
with open(bin_file_path, "r") as bin_file:
    bytecode = bin_file.read()

# Create the config.py content
config_content = f"""
abi = {json.dumps(abi, indent=4)}

bytecode = "{bytecode}"
"""

# Write to config.py
with open("config.py", "w") as config_file:
    config_file.write(config_content)

print("config.py file has been generated.")