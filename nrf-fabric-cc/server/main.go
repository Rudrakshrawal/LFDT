package main

import (
	// "bytes"
	// "context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/hyperledger/fabric-gateway/pkg/client"
	"github.com/hyperledger/fabric-gateway/pkg/identity"
	"google.golang.org/grpc"
	// "google.golang.org/grpc/credentials/insecure"

	"crypto/x509"
    "google.golang.org/grpc/credentials"


	"github.com/Rudrakshrawal/nrf-fabric-cc/models"
    "github.com/Rudrakshrawal/nrf-fabric-cc/utils"
)

// FabricClient handles interactions with Hyperledger Fabric chaincode
type FabricClient struct {
	contract *client.Contract
}

// NewFabricClient creates a new Fabric client connection
func NewFabricClient() (*FabricClient, error) {
	// Read environment variables
	mspID := os.Getenv("MSP_ID")
	if mspID == "" {
		mspID = "Org1MSP"
	}

	channelName := os.Getenv("CHANNEL_NAME")
	if channelName == "" {
		channelName = "mychannel"
	}

	chaincodeName := os.Getenv("CHAINCODE_NAME")
	if chaincodeName == "" {
		chaincodeName = "nrf_management"
	}

	peerEndpoint := os.Getenv("PEER_ENDPOINT")
	if peerEndpoint == "" {
		peerEndpoint = "localhost:7051"
	}

	certPath := os.Getenv("CERT_PATH")
	if certPath == "" {
		certPath = "/opt/gopath/src/github.com/hyperledger/fabric/peer/crypto/peerOrganizations/org1.example.com/users/User1@org1.example.com/msp/signcerts/cert.pem"
	}

	keyPath := os.Getenv("KEY_PATH")
	if keyPath == "" {
		keyPath = "/opt/gopath/src/github.com/hyperledger/fabric/peer/crypto/peerOrganizations/org1.example.com/users/User1@org1.example.com/msp/keystore/priv_sk"
	}











	// Create gRPC connection(tls)

	tlsCertPath := os.Getenv("PEER_TLS_CERT_PATH")
	if tlsCertPath == "" {
		tlsCertPath = "/home/ubuntu/fabric/fabric-samples/test-network/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt"
	}

	tlsCert, err := os.ReadFile(tlsCertPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read peer TLS cert: %w", err)
	}

	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(tlsCert) {
		return nil, fmt.Errorf("failed to add peer TLS cert to pool")
	}

	serverName := os.Getenv("PEER_HOST_OVERRIDE")
	if serverName == "" {
		serverName = "peer0.org1.example.com"
	}

	transportCredentials := credentials.NewClientTLSFromCert(certPool, serverName)

	clientConnection, err := grpc.Dial(
		peerEndpoint,
		grpc.WithTransportCredentials(transportCredentials),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create gRPC connection: %w", err)
	}












	// Create identity
	id, err := newIdentity(certPath, mspID)
	if err != nil {
		clientConnection.Close()
		return nil, fmt.Errorf("failed to create identity: %w", err)
	}

	// Create signing identity
	sign, err := newSign(keyPath)
	if err != nil {
		clientConnection.Close()
		return nil, fmt.Errorf("failed to create signer: %w", err)
	}

	// Create gateway connection
	gw, err := client.Connect(
		id,
		client.WithSign(sign),
		client.WithClientConnection(clientConnection),
		client.WithEvaluateTimeout(5*time.Second),
		client.WithEndorseTimeout(15*time.Second),
		client.WithSubmitTimeout(5*time.Second),
		client.WithCommitStatusTimeout(1*time.Minute),
	)
	if err != nil {
		clientConnection.Close()
		return nil, fmt.Errorf("failed to connect to gateway: %w", err)
	}

	// Get network and contract
	network := gw.GetNetwork(channelName)
	contract := network.GetContract(chaincodeName)

	log.Printf("[Fabric Client] Connected to channel: %s, chaincode: %s", channelName, chaincodeName)

	return &FabricClient{
		contract: contract,
	}, nil
}

// InvokeChaincode invokes a chaincode function (writes to ledger)
// InvokeChaincode invokes a chaincode function (writes to ledger)
func (fc *FabricClient) InvokeChaincode(function string, args ...string) (string, error) {
	log.Printf("[Fabric] Invoking function: %s with %d args", function, len(args))

	// Submit transaction directly with string args
	result, err := fc.contract.SubmitTransaction(function, args...)
	if err != nil {
		return "", fmt.Errorf("failed to submit transaction: %w", err)
	}

	log.Printf("[Fabric] Transaction successful: %s", function)
	return string(result), nil
}

// QueryChaincode queries a chaincode function (reads from ledger)
func (fc *FabricClient) QueryChaincode(function string, args ...string) (string, error) {
	log.Printf("[Fabric] Querying function: %s with %d args", function, len(args))

	// Evaluate transaction directly with string args
	result, err := fc.contract.EvaluateTransaction(function, args...)
	if err != nil {
		return "", fmt.Errorf("failed to evaluate transaction: %w", err)
	}

	log.Printf("[Fabric] Query successful: %s", function)
	return string(result), nil
}


// HTTP Handlers
type HTTPHandlers struct {
	fabricClient *FabricClient
}

func NewHTTPHandlers(fc *FabricClient) *HTTPHandlers {
	return &HTTPHandlers{
		fabricClient: fc,
	}
}

// HandleNFOperations handles NF registration, update, and deletion
func (h *HTTPHandlers) HandleNFOperations(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	var payload map[string]interface{}
	err = json.Unmarshal(body, &payload)
	if err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	operation, ok := payload["operation"].(string)
	if !ok {
		http.Error(w, "Missing operation field", http.StatusBadRequest)
		return
	}

	var result string
	var statusCode int

	switch operation {
	case "register":
		nfProfileJSON, _ := json.Marshal(payload["nfProfile"])
		result, err = h.fabricClient.InvokeChaincode("RegisterNF", string(nfProfileJSON))
		if err == nil {
			statusCode = http.StatusCreated
		}

	case "update":
		nfProfile, ok := payload["nfProfile"].(map[string]interface{})
		if !ok {
			http.Error(w, "Invalid nfProfile format", http.StatusBadRequest)
			return
		}
		nfInstanceId, ok := nfProfile["nfInstanceId"].(string)
		if !ok {
			http.Error(w, "Missing nfInstanceId", http.StatusBadRequest)
			return
		}
		updatesJSON, _ := json.Marshal(nfProfile)
		result, err = h.fabricClient.InvokeChaincode("UpdateNF", nfInstanceId, string(updatesJSON))
		statusCode = http.StatusOK

	case "delete":
		nfInstanceId, ok := payload["nfInstanceId"].(string)
		if !ok {
			http.Error(w, "Missing nfInstanceId", http.StatusBadRequest)
			return
		}
		result, err = h.fabricClient.InvokeChaincode("DeleteNF", nfInstanceId)
		statusCode = http.StatusNoContent

	default:
		http.Error(w, "Unknown operation", http.StatusBadRequest)
		return
	}

	if err != nil {
		log.Printf("[Error] Chaincode operation failed: %v", err)
		http.Error(w, fmt.Sprintf("Chaincode error: %v", err), http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"success":   true,
		"operation": operation,
		"result":    result,
		"timestamp": time.Now().UTC(),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(response)
}

// HandleOAuthToken handles OAuth token generation
func (h *HTTPHandlers) HandleOAuthToken(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }

    body, err := io.ReadAll(r.Body)
    if err != nil {
        http.Error(w, "Failed to read request body", http.StatusBadRequest)
        return
    }
    defer r.Body.Close()

    log.Printf("[OAuth] Received token request: %s", string(body))

    // 1) Parse incoming NRF to Fabric token request
    var tokenReq models.TokenRequest
    if err := json.Unmarshal(body, &tokenReq); err != nil {
        log.Printf("[OAuth] Invalid token request JSON: %v", err)
        http.Error(w, "Invalid token request", http.StatusBadRequest)
        return
    }

    // Basic validation (you can tighten this as needed)
    if tokenReq.NrfInstanceId == "" || tokenReq.NfInstanceId == "" ||
        tokenReq.TargetNfInstanceId == "" || tokenReq.Scope == "" {
        http.Error(w, "Missing required token request fields", http.StatusBadRequest)
        return
    }

    // 2) Decide expiry
    expiresIn := tokenReq.ExpiresIn
    if expiresIn <= 0 {
        expiresIn = 3600 //1 hour default
    }

    // 3) Generate token ID (gateway-side)
    tokenID, err := utils.GenerateTokenID()
    if err != nil {
        log.Printf("[OAuth] Failed to generate token ID: %v", err)
        http.Error(w, "Failed to generate token", http.StatusInternalServerError)
        return
    }

    // 4) Generate signed JWT using RS512 (gateway-side)
    accessToken, err := utils.GenerateOAuthToken(
        tokenReq.NrfInstanceId,       // iss
        tokenReq.NfInstanceId,        // sub
        tokenReq.TargetNfInstanceId,  // aud
        tokenReq.Scope,               // scope
        expiresIn,
    )
    if err != nil {
        log.Printf("[OAuth] Failed to sign JWT: %v", err)
        http.Error(w, "Failed to generate token", http.StatusInternalServerError)
        return
    }

    now := time.Now().UTC()
    expiresAt := now.Add(time.Duration(expiresIn) * time.Second)

    // //store hash instead of full token in Fabric
    // tokenHash, err := utils.ComputeHash(accessToken)
    // if err != nil {
    //     log.Printf("[OAuth] Failed to hash access token: %v", err)
    //     http.Error(w, "Failed to generate token", http.StatusInternalServerError)
    //     return
    // }

    // 5) Build metadata to send to Fabric chaincode
    tokenMeta := models.OAuthToken{
        TokenId:            tokenID,
        AccessToken:        accessToken, //or tokenHash if we want to store the hashon chain
        TokenType:          "Bearer",
        ExpiresIn:          expiresIn,
        Scope:              tokenReq.Scope,
        NfInstanceId:       tokenReq.NfInstanceId,
        NfType:             tokenReq.NfType,
        TargetNfInstanceId: tokenReq.TargetNfInstanceId,
        TargetNfType:       tokenReq.TargetNfType,
        GrantType:          tokenReq.GrantType,
        Issuer:             tokenReq.NrfInstanceId,
        IssuedAt:           now,
        ExpiresAt:          expiresAt,
        Revoked:            false,
    }

    metaJSON, err := json.Marshal(tokenMeta)
    if err != nil {
        log.Printf("[OAuth] Failed to marshal token metadata: %v", err)
        http.Error(w, "Failed to generate token", http.StatusInternalServerError)
        return
    }

    // 6) Ask Fabric to store token metadata
    ccResult, err := h.fabricClient.InvokeChaincode("GenerateOAuthToken", string(metaJSON))
    if err != nil {
        log.Printf("[OAuth] Chaincode store failed: %v", err)
        errorResponse := map[string]string{
            "error":             "server_error",
            "error_description": "failed to persist token metadata",
        }
        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(http.StatusInternalServerError)
        json.NewEncoder(w).Encode(errorResponse)
        return
    }
    log.Printf("[OAuth] Token metadata stored in Fabric: %s", ccResult)

    // 7) Return OAuth response back to NRF (free5GC)
    resp := map[string]interface{}{
        "access_token": accessToken,
        "token_type":   "Bearer",
        "expires_in":   expiresIn,
        "scope":        tokenReq.Scope,
        "token_id":     tokenID,
    }

    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(http.StatusOK)
    json.NewEncoder(w).Encode(resp)
}

// HandleNFQuery handles NF retrieval queries
func (h *HTTPHandlers) HandleNFQuery(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	query := r.URL.Query()
	nfInstanceId := query.Get("nfInstanceId")
	nfType := query.Get("nfType")

	var result string
	var err error

	if nfInstanceId != "" {
		log.Printf("[Query] Retrieving NF: %s", nfInstanceId)
		result, err = h.fabricClient.QueryChaincode("RetrieveNF", nfInstanceId)
	} else if nfType != "" {
		log.Printf("[Query] Retrieving NFs by type: %s", nfType)
		result, err = h.fabricClient.QueryChaincode("RetrieveNFsByType", nfType)
	} else {
		log.Printf("[Query] Retrieving all NFs")
		result, err = h.fabricClient.QueryChaincode("RetrieveAllNFs")
	}

	if err != nil {
		log.Printf("[Error] Query failed: %v", err)
		http.Error(w, fmt.Sprintf("Query error: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(result))
}

// HandleTokenValidation handles token validity checks
func (h *HTTPHandlers) HandleTokenValidation(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var payload struct {
		AccessToken string `json:"access_token"`
	}

	err := json.NewDecoder(r.Body).Decode(&payload)
	if err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	log.Printf("[Validation] Checking token validity")

	result, err := h.fabricClient.QueryChaincode("CheckTokenValidity", payload.AccessToken)
	if err != nil {
		log.Printf("[Error] Token validation failed: %v", err)
		http.Error(w, fmt.Sprintf("Validation error: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(result))
}

// HandlePublicKey returns the NRF public key for NFs
func (h *HTTPHandlers) HandlePublicKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	log.Printf("[Query] Retrieving public key")

	result, err := h.fabricClient.QueryChaincode("GetPublicKey")
	if err != nil {
		log.Printf("[Error] Failed to get public key: %v", err)
		http.Error(w, fmt.Sprintf("Error getting public key: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(result))
}

// HandleRevokeToken handles token revocation
func (h *HTTPHandlers) HandleRevokeToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var payload struct {
		TokenID string `json:"token_id"`
		Reason  string `json:"reason"`
	}

	err := json.NewDecoder(r.Body).Decode(&payload)
	if err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	if payload.TokenID == "" {
		http.Error(w, "Missing token_id", http.StatusBadRequest)
		return
	}

	if payload.Reason == "" {
		payload.Reason = "MANUAL_REVOCATION"
	}

	log.Printf("[Revoke] Revoking token: %s", payload.TokenID)

	_, err = h.fabricClient.InvokeChaincode("RevokeToken", payload.TokenID, payload.Reason)
	if err != nil {
		log.Printf("[Error] Token revocation failed: %v", err)
		http.Error(w, fmt.Sprintf("Revocation error: %v", err), http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"success":   true,
		"token_id":  payload.TokenID,
		"message":   "Token revoked successfully",
		"timestamp": time.Now().UTC(),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// Health check endpoint
func HandleHealthCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	response := map[string]interface{}{
		"status":    "healthy",
		"service":   "nrf-fabric-gateway",
		"timestamp": time.Now().UTC(),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// Helper functions for identity and signing
func newIdentity(certPath, mspID string) (*identity.X509Identity, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate: %w", err)
	}

	cert, err := identity.CertificateFromPEM(certPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	id, err := identity.NewX509Identity(mspID, cert)
	if err != nil {
		return nil, fmt.Errorf("failed to create identity: %w", err)
	}

	return id, nil
}

func newSign(keyPath string) (identity.Sign, error) {
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key: %w", err)
	}

	privateKey, err := identity.PrivateKeyFromPEM(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	sign, err := identity.NewPrivateKeySign(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create signer: %w", err)
	}

	return sign, nil
}

// CORS middleware
func corsMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next(w, r)
	}
}

// Logging middleware
func loggingMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		log.Printf("[Request] %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)
		next(w, r)
		log.Printf("[Response] %s %s completed in %v", r.Method, r.URL.Path, time.Since(start))
	}
}

func main() {
	log.Println("========================================")
	log.Println("NRF Fabric Gateway Server Starting...")
	log.Println("========================================")

    // Load NRF private key for JWT
    if err := utils.InitializeKeys(); err != nil {
        log.Fatalf("[Fatal] Failed to initialize NRF JWT keys: %v", err)
    }
    log.Println("[Init] NRF JWT keys loaded successfully")
	
	
	// Get port from environment
	port := os.Getenv("HTTP_PORT")
	if port == "" {
		port = "8080"
	}

	// Initialize Fabric client
	log.Println("[Init] Connecting to Hyperledger Fabric...")
	fabricClient, err := NewFabricClient()
	if err != nil {
		log.Fatalf("[Fatal] Failed to create Fabric client: %v", err)
	}
	log.Println("[Init] Successfully connected to Fabric network")

	// Create handlers
	handlers := NewHTTPHandlers(fabricClient)

	// Register routes with middleware
	http.HandleFunc("/health", loggingMiddleware(corsMiddleware(HandleHealthCheck)))
	http.HandleFunc("/nf-operations", loggingMiddleware(corsMiddleware(handlers.HandleNFOperations)))
	http.HandleFunc("/oauth/token", loggingMiddleware(corsMiddleware(handlers.HandleOAuthToken)))
	http.HandleFunc("/nf-query", loggingMiddleware(corsMiddleware(handlers.HandleNFQuery)))
	http.HandleFunc("/token/validate", loggingMiddleware(corsMiddleware(handlers.HandleTokenValidation)))
	http.HandleFunc("/token/revoke", loggingMiddleware(corsMiddleware(handlers.HandleRevokeToken)))
	http.HandleFunc("/public-key", loggingMiddleware(corsMiddleware(handlers.HandlePublicKey)))

	log.Println("========================================")
	log.Println("Registered Endpoints:")
	log.Println("  GET  /health")
	log.Println("  POST /nf-operations")
	log.Println("  POST /oauth/token")
	log.Println("  GET  /nf-query")
	log.Println("  POST /token/validate")
	log.Println("  POST /token/revoke")
	log.Println("  GET  /public-key")
	log.Println("========================================")
	log.Printf("HTTP server listening on port %s", port)
	log.Println("========================================")

	// Start server
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatalf("[Fatal] Server failed to start: %v", err)
	}
}
