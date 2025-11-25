// // chaincode/main.go - NO CHANGES NEEDED
// package main

// import (
// 	"fmt"
// 	"log"
// 	"os"

// 	"github.com/hyperledger/fabric-contract-api-go/contractapi"
// 	"nrf-fabric-chaincode/chaincode"
// 	"nrf-fabric-chaincode/utils"
// )

// func main() {
// 	// Load NRF private key for JWT signing
// 	err := utils.InitializeKeys() // Use InitializeKeys instead
// 	if err != nil {
// 		log.Fatalf("Failed to load NRF private key: %v", err)
// 	}
// 	log.Println("NRF private key loaded successfully")

// 	// Create chaincode
// 	nrfChaincode, err := contractapi.NewChaincode(&chaincode.NRFContract{})
// 	if err != nil {
// 		log.Fatalf("Error creating NRF chaincode: %v", err)
// 	}

// 	// Get chaincode server parameters from environment
// 	ccid := os.Getenv("CHAINCODE_ID")
// 	address := os.Getenv("CHAINCODE_SERVER_ADDRESS")
	
// 	if ccid == "" || address == "" {
// 		log.Fatal("CHAINCODE_ID and CHAINCODE_SERVER_ADDRESS must be set")
// 	}

// 	// Create chaincode server
// 	server := &contractapi.ChaincodeServer{
// 		CCID:    ccid,
// 		Address: address,
// 		CC:      nrfChaincode,
// 		TLSProps: contractapi.TLSProperties{
// 			Disabled: true, // Set to false and configure for production
// 		},
// 	}

// 	log.Printf("Starting NRF chaincode server at %s with CCID: %s", address, ccid)

// 	// Start the chaincode server
// 	if err := server.Start(); err != nil {
// 		log.Fatalf("Error starting NRF chaincode server: %v", err)
// 	}

// 	fmt.Println("NRF chaincode server started successfully")
// }









package main

import (
	"fmt"
	"log"
	"os"

	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/hyperledger/fabric-contract-api-go/contractapi"
	// "nrf-fabric-chaincode/chaincode"
	"github.com/Rudrakshrawal/nrf-fabric-cc/utils"
)

func main() {
	log.Println("========================================")
	log.Println("NRF External Chaincode Starting...")
	log.Println("========================================")
	
	// Load NRF private key for JWT signing
	err := utils.InitializeKeys()
	if err != nil {
		log.Fatalf("[FATAL] Failed to load NRF private key: %v", err)
	}
	log.Println("[Init] : NRF private key loaded successfully")

	// Create chaincode with NRFContract
	nrfChaincode, err := contractapi.NewChaincode(&NRFContract{})
	if err != nil {
		log.Fatalf("[FATAL] Error creating NRF chaincode: %v", err)
	}

	// Get chaincode server parameters from environment
	ccid := os.Getenv("CHAINCODE_ID")
	address := os.Getenv("CHAINCODE_SERVER_ADDRESS")
	
	if ccid == "" {
		log.Fatal("[FATAL] CHAINCODE_ID environment variable must be set")
	}
	if address == "" {
		address = "0.0.0.0:9999"
		log.Printf("[WARNING] CHAINCODE_SERVER_ADDRESS not set, using default: %s", address)
	}

	// Create external chaincode server using shim
	server := &shim.ChaincodeServer{
		CCID:    ccid,
		Address: address,
		CC:      nrfChaincode,
		TLSProps: shim.TLSProperties{
			Disabled: true, // Set to false and configure TLS for production
		},
	}

	log.Println("========================================")
	log.Printf("[Server] Address: %s", address)
	log.Printf("[Server] Chaincode ID: %s", ccid)
	log.Println("========================================")

	// Start the chaincode server
	log.Println("[Server] Starting chaincode server...")
	if err := server.Start(); err != nil {
		log.Fatalf("[FATAL] Error starting chaincode server: %v", err)
	}

	fmt.Println("[Server] ✓ NRF chaincode server started successfully")
}
