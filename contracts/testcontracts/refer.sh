# Install silidity compiler
npm install -g solc
npm config get prefix
nano ~/.bashrc
export PATH=$PATH:/home/henok/.nvm/versions/node/v20.13.1/bin
source ~/.bashrc
solc --version
# sudo snap install solc


# Compile the contract
solcjs --abi --bin -o build test.sol