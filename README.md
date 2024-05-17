### How to run:

1. Run Ganache

2. deploy the smart contract using `contracts/contracts/deploy.py`. Configure which address you want to ban, which address are available

3. After having the smart contract address. Change `web3url` and `contractAddr` in `base/free5gc/NFs/amf/internal/sbi/consumer/ue_authentication.go`.

4. `./compile.sh`

5. `docker compose up -d`

6. Change the Ganache server to the `web3url` that AMF can access.

7. `./run.sh`