# Decentralized OAuth 2.0 in 5G Core with Hyperledger Fabric

This repository contains the reference implementation developed under the **LF Decentralized Trust (LFDT) Mentorship Program** for:

> **Decentralized OAuth 2.0 authorization in a 5G Core (free5GC) using Hyperledger Fabric as a decentralized trust and audit layer.**

The project demonstrates how to:
- Offload **OAuth 2.0 access token issuance and validation** from the 5G **Network Repository Function (NRF)** to **Hyperledger Fabric**.
- Persist **NF registrations**, **OAuth token metadata**, and **revocations** on-chain.
- Use a **Gateway Pattern** to bridge 3GPP SBA (HTTP/2, JSON) with Fabric (gRPC, deterministic chaincode).

---

## Repository Structure

```text
LFDT/
├── free5gc/           # free5GC source – used as 5G Core reference stack
├── nrf-fabric-cc/     # NRF–Fabric integration:
│   ├── chaincode/     # External chaincode (NRFContract) for NF + token management
│   ├── server/        # NRF–Fabric Gateway (Go microservice)
│   ├── packaging/     # connection.json + metadata.json + packaged CC
│   ├── docker-compose-chaincode.yaml
│   ├── chaincode-org1.env
│   ├── chaincode-org2.env
│   ├── nrf_private.key
│   ├── nrf_cert.pem   # though not required
└── README.md          # This file
```







-----

## High-Level Architecture

The solution uses a Gateway + External Chaincode architecture.
1. free5GC NRF (5G Core)
  * Mostly unmodified.
	*	Instead of generating OAuth tokens itself, it sends registration and token requests to the Gateway.
2. NRF–Fabric Gateway (Go)
	*	Exposes HTTP endpoints:
	*	/nf-operations – NF register/update/delete
	*	/nf-query – NF queries
	*	/oauth/token – token issuance
	*	/token/validate – token validation
	*	/token/revoke – token revocation
	*	/public-key – NRF JWT public key
	*	Talks to Fabric via the Fabric Gateway SDK using an Org1 user identity.
	*	Signs JWT access tokens with an NRF private key (RS512).
	*	Stores token metadata on-chain via Fabric.
3.	Hyperledger Fabric Network
	*	Based on fabric-samples/test-network (2 orgs, 1 channel: mychannel).
	*	Runs external chaincode (nrf_management) via Docker containers (nrf-chaincode.org1.example.com, nrf-chaincode.org2.example.com).
	*	Chaincode functions include:
	*	RegisterNF, UpdateNF, DeleteNF, RetrieveNF, RetrieveAllNFs, RetrieveNFsByType
	*	GenerateOAuthToken (store metadata), RetrieveToken
	*	CheckTokenValidity, CheckTokenExpired, RevokeToken
	*	GetPublicKey

The core idea: JWT generation is off-chain (Gateway), token state is on-chain (Fabric) to respect Fabric determinism while achieving decentralized trust.

-----

## Prerequisites

On the machine where you run this project:
	*	Ubuntu 20.04/22.04 (or similar)
	*	Docker + Docker Compose
	*	Go ≥ 1.21
	*	Node.js + Yarn (only needed if you rebuild free5GC WebConsole)
	*	jq CLI for JSON parsing
	*	Hyperledger Fabric binaries and samples (this repo assumes something like):

> After cloning the repository, copy the nrf-fabric-cc to the fabric-samples directory of the hyperledger fabric i.e. /home/ubuntu/fabric/fabric-samples/nrf-fabric-cc

If you already have fabric-samples cloned elsewhere, adjust paths accordingly in the commands below.

---
> For enabling chaincode make the necessary changes in the *fabric-samples/config/core.yaml* and *fabric-samples/test-network/compose/docker/docker-compose-test-net.yaml* file too. **THIS IS ONE OF THE MOST IMPORTANT STEP TO ENABLE EXTERNAL CHAINCODE** . [Refer here](https://github.com/hyperledger/fabric-samples/tree/main/asset-transfer-basic/chaincode-external#setting-up-the-external-builder-and-launcher)

-----

0. Path & Naming Assumptions

The instructions assume:

```
FABRIC_SAMPLES=/home/ubuntu/fabric/fabric-samples
PROJECT_ROOT=$FABRIC_SAMPLES/nrf-fabric-cc   # this repo's nrf-fabric-cc directory
CHANNEL_NAME=mychannel
CHAINCODE_NAME=nrf_management
```

*Change these if your layout differs.* 

-----

1. Start the Fabric Test Network

From the Fabric test-network:
```
cd $FABRIC_SAMPLES/test-network
```
Clean up any existing network
```
./network.sh down
```
Bring up a 2-org network with CA, CouchDB, and channel "mychannel"

```
./network.sh up createChannel -ca -s couchdb -c $CHANNEL_NAME
```

Confirm that the Docker network used by Fabric exists
```docker network ls | grep fabric_test```

You should see a network named fabric_test.

-----

2. Build the NRF External Chaincode Image

The chaincode is implemented as an external chaincode service (CCaaS) running in Docker.

```cd $PROJECT_ROOT```

Build the external chaincode Docker image
docker build -t nrf-chaincode:1.0 .

Verify:

```docker images | grep nrf-chaincode```


-----

3. Package the External Chaincode

The packaging/ directory contains the connection.json and metadata.json needed for external chaincode.

From inside nrf-fabric-cc:
```
cd $PROJECT_ROOT/packaging
```

Clean any previous artifacts

```rm -f code.tar.gz nrf-chaincode.tgz```
a. Package connection.json into code.tar.gz
```tar czf code.tar.gz connection.json```

b. Package code.tar.gz + metadata.json into the final chaincode package
```
tar czf nrf-chaincode.tgz code.tar.gz metadata.json

ls
```
 -> code.tar.gz, metadata.json, nrf-chaincode.tgz

The metadata.json should look like:
```
{
  "type": "ccaas",
  "label": "nrf_management_1.0"
}
```
The connection.json points to the external chaincode container:
```
{
  "address": "nrf-chaincode.org1.example.com:9999",
  "dial_timeout": "10s",
  "tls_required": false
}
```

-----

4. Install Chaincode on Both Organizations

From test-network:
```
cd $FABRIC_SAMPLES/test-network

export PATH=${PWD}/../bin:$PATH
export FABRIC_CFG_PATH=${PWD}/../config/
```

<!-- *Or you can also use the script(created for my own ease) available by using the command ```. ./peercmd.sh``` for org1 and ```. ./peercmd2.sh``` for org2.* -->

# Helper functions (setGlobals)
. ./scripts/envVar.sh

> LFDT/nrf-fabric-cc

4.1 Install on Org1

```setGlobals 1  # peer0.org1.example.com```

```peer lifecycle chaincode install ../nrf-fabric-cc/packaging/nrf-chaincode.tgz```

4.2 Install on Org2

```setGlobals 2  # peer0.org2.example.com```
> One important point, in the connection.json file, ```nrf-chaincode.org1.example.com:9999``` must be changed for another peer (peer 2). Meaning while creating the tar file, change that part of connection.json to ```nrf-chaincode.org2.example.com:9999``` while creating tar tp install on peer 2, you can also chhange the name of output file for less confusion. If not done properly, an error of *chaincode not being deployed on enough peers* will come up. 

``` 
cd ../nrf-fabric-cc/packaging
vim connection.json #make changes, change nrf-chaincode.org1.example.com:9999 to nrf-chaincode.org2.example.com:9999
tar cfz code.tar.gz connection.json
tar cfz nrf-chaincode.tgz metadata.json code.tar.gz #or nrf-chaincode2.tgz for understanadbility
```


```peer lifecycle chaincode install ../nrf-fabric-cc/packaging/nrf-chaincode.tgz```

4.3 Capture the Package ID

```
setGlobals 1

peer lifecycle chaincode queryinstalled

# Look for:
# Package ID: nrf_management_1.0:<HASH>, Label: nrf_management_1.0
export CC_PACKAGE_ID=nrf_management_1.0:<HASH>  # replace <HASH> with actual value
```

-----

5. Configure and Start External Chaincode Containers

The external chaincode is started via docker-compose-chaincode.yaml.
It runs two containers, one per org, connected to the fabric_test network.

5.1 Environment Files

In nrf-fabric-cc/ you have:

chaincode-org1.env
```
CHAINCODE_ID=nrf_management_1.0:REPLACE_AFTER_INSTALL
CHAINCODE_SERVER_ADDRESS=0.0.0.0:9999
NRF_PRIVATE_KEY_PATH=/root/nrf_private.key
CORE_PEER_LOCALMSPID=Org1MSP
FABRIC_LOGGING_SPEC=INFO
CORE_CHAINCODE_LOGGING_LEVEL=INFO
CORE_CHAINCODE_LOGGING_SHIM=INFO
```
chaincode-org2.env
```
CHAINCODE_ID=nrf_management_1.0:REPLACE_AFTER_INSTALL
CHAINCODE_SERVER_ADDRESS=0.0.0.0:9999
NRF_PRIVATE_KEY_PATH=/root/nrf_private.key
CORE_PEER_LOCALMSPID=Org2MSP
FABRIC_LOGGING_SPEC=INFO
CORE_CHAINCODE_LOGGING_LEVEL=INFO
CORE_CHAINCODE_LOGGING_SHIM=INFO
```
After the queryinstalled step, update both:

> Both the CHAINCODE_ID must be different from each other

5.2 Docker Compose for External Chaincode

docker-compose-chaincode.yaml (simplified):
```
version: '3.7'

networks:
  fabric_test:
    external: true
    name: fabric_test

services:
  nrf-chaincode.org1.example.com:
    build: .
    container_name: nrf-chaincode.org1.example.com
    hostname: nrf-chaincode.org1.example.com
    image: nrf-chaincode:1.0
    volumes:
      - ./nrf.key:/root/nrf.key:ro #private key
      - ./nrf.pem:/root/nrf.pem:ro #Cert
    #   - ./nrf_public.key:/root/nrf_public.key:ro
    env_file:
      - chaincode1.env
    networks:
      fabric_test:
        aliases:
          - nrf-chaincode
    ports:
      - "9999:9999"
    restart: unless-stopped
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"

  nrf-chaincode.org2.example.com:
    build: .
    container_name: nrf-chaincode.org2.example.com
    hostname: nrf-chaincode.org2.example.com
    image: nrf-chaincode:1.0
    volumes:
      - ./nrf.key:/root/nrf.key:ro #private key
      - ./nrf.pem:/root/nrf.pem:ro #Cert
    env_file:
      - chaincode2.env
    networks:
      fabric_test:
    ports:
      - "9998:9999"
    restart: unless-stopped
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"
```
The keys nrf.key  are your NRF JWT keys.

5.3 Start the Chaincode Containers
```
cd $PROJECT_ROOT

docker-compose -f docker-compose-chaincode.yaml up -d

docker-compose -f docker-compose-chaincode.yaml ps
docker logs nrf-chaincode.org1.example.com
docker logs nrf-chaincode.org2.example.com
```
You should see logs indicating the chaincode server started and the NRF keys were loaded.

-----

6. Approve and Commit Chaincode Definition

Back to test-network:
```
cd $FABRIC_SAMPLES/test-network
. ./scripts/envVar.sh
```
6.1 Approve for Org1
```
setGlobals 1

peer lifecycle chaincode approveformyorg \
  -o localhost:7050 \
  --ordererTLSHostnameOverride orderer.example.com \
  --tls \
  --cafile "${PWD}/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem" \
  --channelID $CHANNEL_NAME \
  --name $CHAINCODE_NAME \
  --version 1.0 \
  --package-id $CC_PACKAGE_ID \
  --sequence 1
```
6.2 Approve for Org2
```
setGlobals 2

peer lifecycle chaincode approveformyorg \
  -o localhost:7050 \
  --ordererTLSHostnameOverride orderer.example.com \
  --tls \
  --cafile "${PWD}/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem" \
  --channelID $CHANNEL_NAME \
  --name $CHAINCODE_NAME \
  --version 1.0 \
  --package-id $CC_PACKAGE_ID \
  --sequence 1
```
6.3 Commit
```
setGlobals 1

peer lifecycle chaincode commit \
  -o localhost:7050 \
  --ordererTLSHostnameOverride orderer.example.com \
  --tls \
  --cafile "${PWD}/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem" \
  --channelID $CHANNEL_NAME \
  --name $CHAINCODE_NAME \
  --version 1.0 \
  --sequence 1 \
  --peerAddresses localhost:7051 \
  --tlsRootCertFiles "${PWD}/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt" \
  --peerAddresses localhost:9051 \
  --tlsRootCertFiles "${PWD}/organizations/peerOrganizations/org2.example.com/peers/peer0.org2.example.com/tls/ca.crt"
```
Verify:

```peer lifecycle chaincode querycommitted --channelID $CHANNEL_NAME --name $CHAINCODE_NAME```

You should see Version: 1.0, Sequence: 1 with approvals from both orgs.

-----

7. Run the NRF–Fabric Gateway Server

The Gateway lives in nrf-fabric-cc/server/. 
```
cd fabric-samples/nrf-fabric-cc/server

# adjust base path if your layout is slightly different
BASE=/home/ubuntu/fabric/fabric-samples/test-network/organizations/peerOrganizations/org1.example.com/users/User1@org1.example.com/msp

export MSP_ID=Org1MSP
export CHANNEL_NAME=mychannel
export CHAINCODE_NAME=nrf_management
export PEER_ENDPOINT=localhost:7051

export CERT_PATH="$BASE/signcerts/cert.pem"
export KEY_PATH="$(ls $BASE/keystore/*)"   # keystore file has a random name

export HTTP_PORT=8080

```
You should see logs like:
*	NRF Fabric Gateway Server Starting...
*	NRF JWT keys loaded successfully
*	Connected to channel: mychannel, chaincode: nrf_management
*	A list of registered HTTP endpoints.

-----

8. Quick Functional Tests

8.1 Health Check

```curl -s http://localhost:8080/health | jq '.'```


-----

8.2 NF Registration via Gateway → Fabric

```curl -s -X POST http://localhost:8080/nf-operations \
  -H "Content-Type: application/json" \
  -d '{
    "operation": "register",
    "nfProfile": {
      "nfInstanceId": "test-gw-nf-001",
      "nfType": "TESTNF",
      "nfStatus": "REGISTERED",
      "ipv4Addresses": ["127.0.0.60"],
      "priority": 10,
      "capacity": 50,
      "heartBeatTimer": 30,
      "nfServices": [
        {
          "serviceInstanceId": "testnf-svc-002",
          "serviceName": "nstd-test-service",
          "versions": [
            {
              "apiVersionInUri": "v1",
              "apiFullVersion": "1.0.0"
            }
          ],
          "scheme": "http",
          "nfServiceStatus": "REGISTERED",
          "apiPrefix": "http://127.0.0.60:9000"
        }
      ]
    }
  }' | jq '.'
  ```

Query all NFs:

```curl -s "http://localhost:8080/nf-query" | jq '.'```
`

-----

8.3 OAuth Token Issuance and Validation

Generate a token:
```
cd $PROJECT_ROOT

TOKEN_RESP=$(curl -s -X POST http://localhost:8080/oauth/token \
  -H "Content-Type: application/json" \
  -d '{
    "nrfInstanceId": "nrf-001",
    "nfInstanceId": "smf-001",
    "nfType": "SMF",
    "targetNfInstanceId": "upf-001",
    "targetNfType": "UPF",
    "scope": "nupf-pdu-session",
    "grantType": "client_credentials"
  }')

echo "$TOKEN_RESP" | jq '.'

ACCESS_TOKEN=$(echo "$TOKEN_RESP" | jq -r '.access_token')
```

Validate the token:
```
curl -s -X POST http://localhost:8080/token/validate \
  -H "Content-Type: application/json" \
  -d "{\"access_token\": \"$ACCESS_TOKEN\"}" | jq '.'

You should see valid: true with issuer (iss), subject (sub), audience (aud), scope and expiry.
```
-----


9. Monitoring Fabric with Prometheus & Grafana (Optional)

To monitor Fabric performance (peers, orderer, CouchDB, etc.) you can enable the built-in Prometheus + Grafana stack from fabric-samples:

```cd $FABRIC_SAMPLES/test-network/prometheus-grafana```

# Start Prometheus + Grafana stack

```
cd fabric-samples/test-network/prometheus-grafana
docker compose up -d
```
Then:
	*	Prometheus: http://localhost:9090
	*	Grafana: http://localhost:3000
	*	Default login: admin / admin (you may be prompted to set a new password)
	*	Import or use the provided Fabric dashboards to track:
	*	Peer and orderer CPU / memory
	*	Block and transaction rates
	*	gRPC latency and chaincode execution metrics

When you are done monitoring:
```
cd fabric-samples/test-network/prometheus-grafana
docker compose down
```

-----

10. Starting the free5GC Core

Open separate terminals and start free5GC from its root directory:
```
cd free5gc
./run.sh
```
This will:
-	Launch all free5GC Network Functions
-	Start the WebConsole so you can register subscribers / devices

To stop all running free5GC processes, use:
```
cd free5gc
./force_kill.sh
```

-----

11. Complete Tear-Down

When you are finished with the experiment, shut everything down in this order:

1. Stop external chaincode containers
```
cd $PROJECT_ROOT
docker-compose -f docker-compose-chaincode.yaml down
```
2. Stop the Fabric test network
```
cd fabric-samples/test-network
./network.sh down
```

4. Stop free5GC core processes

```
cd free5gc
./force_kill.sh
```

This returns the environment to a clean state for the next run.


-----

Troubleshooting Notes
*	Endorsement timeout / not installed errors
*	Ensure:
*	CC_PACKAGE_ID in both chaincode-org*.env should be different, queryinstalled.
*	External chaincode containers are running and attached to fabric_test.
*	JWT validation failures inside chaincode
*	Check that:
  1.	NRF_PRIVATE_KEY_PATH is set correctly in chaincode env.
  2.	The same key is used by the Gateway (NRF_PRIVATE_KEY_PATH or NRF_PRIVATE_KEY).
  3.	Algorithm is RS512 on both sides.
  4.	Fabric network does not start cleanly
*	Use ./network.sh down and docker volume prune -f to clear old state if required.

-----

### Credits & Acknowledgements

This work was carried out under the Linux Foundation Decentralized Trust (LFDT) Mentorship Program, integrating:
	*	free5GC as the 5G Core reference implementation.
	*	Hyperledger Fabric as the decentralized trust and audit layer.
	*	A custom NRF–Fabric Gateway to bridge telecom and blockchain systems.

It serves as a starting point for further research into Zero-Trust, DID-based identity, and Post-Quantum secure OAuth in telecom networks.

Feel free to open issues or pull requests if you extend this work to new 5G stacks, DID registries, or PQC algorithms.

