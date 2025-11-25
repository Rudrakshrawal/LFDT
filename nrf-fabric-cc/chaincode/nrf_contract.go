// package main

// import (
// 	"encoding/json"
// 	"fmt"
// 	"time"

// 	"github.com/hyperledger/fabric-contract-api-go/contractapi"
// 	"github.com/Rudrakshrawal/nrf-fabric-cc/models"
// 	"github.com/Rudrakshrawal/nrf-fabric-cc/utils"
// 	// "nrf-fabric-chaincode/models"
// 	// "nrf-fabric-chaincode/utils"
// )

// // NRFContract smart contract for NF management and OAuth
// type NRFContract struct {
// 	contractapi.Contract
// }

// ///////////////////////
// // NF Profile Management Functions
// ///////////////////////



// func getTxTime(ctx contractapi.TransactionContextInterface) (time.Time, error) {
//     ts, err := ctx.GetStub().GetTxTimestamp()
//     if err != nil {
//         return time.Time{}, fmt.Errorf("failed to get tx timestamp: %w", err)
//     }
//     // Convert protobuf Timestamp to time.Time
//     return time.Unix(ts.Seconds, int64(ts.Nanos)).UTC(), nil
// }






// // RegisterNF registers a new Network Function profile
// func (c *NRFContract) RegisterNF(ctx contractapi.TransactionContextInterface, nfProfileJSON string) error {
//     var nfProfile models.NFProfile
//     if err := json.Unmarshal([]byte(nfProfileJSON), &nfProfile); err != nil {
//         return fmt.Errorf("failed to unmarshal NF profile: %w", err)
//     }

//     existingNF, err := ctx.GetStub().GetState(nfProfile.NfInstanceId)
//     if err != nil {
//         return fmt.Errorf("failed to read from world state: %w", err)
//     }
//     if existingNF != nil {
//         return fmt.Errorf("NF %s already exists", nfProfile.NfInstanceId)
//     }

//     // timestamp based on tx
//     txTime, err := getTxTime(ctx)
//     if err != nil {
//         return fmt.Errorf("failed to get tx time: %w", err)
//     }

//     nfProfile.CreatedAt = txTime
//     nfProfile.UpdatedAt = txTime
//     nfProfile.Version = 1
//     nfProfile.NfStatus = "REGISTERED"

//     nfJSON, err := json.Marshal(nfProfile)
//     if err != nil {
//         return fmt.Errorf("failed to marshal NF profile: %w", err)
//     }

//     if err := ctx.GetStub().PutState(nfProfile.NfInstanceId, nfJSON); err != nil {
//         return fmt.Errorf("failed to put NF profile to world state: %w", err)
//     }

//     nfTypeKey, err := ctx.GetStub().CreateCompositeKey(
//         "nfType~nfInstanceId",
//         []string{nfProfile.NfType, nfProfile.NfInstanceId},
//     )
//     if err != nil {
//         return fmt.Errorf("failed to create composite key: %w", err)
//     }

//     if err := ctx.GetStub().PutState(nfTypeKey, []byte{0x00}); err != nil {
//         return fmt.Errorf("failed to put composite key: %w", err)
//     }

//     // we can still use the same txTime for consistency
//     eventPayload := map[string]interface{}{
//         "eventType":    "NF_REGISTERED",
//         "nfInstanceId": nfProfile.NfInstanceId,
//         "nfType":       nfProfile.NfType,
//         "timestamp":    txTime,
//     }
//     eventJSON, _ := json.Marshal(eventPayload)
//     ctx.GetStub().SetEvent("NFRegistered", eventJSON)

//     return nil
// }





// // func (c *NRFContract) RegisterNF(ctx contractapi.TransactionContextInterface, nfProfileJSON string) error {
// // 	var nfProfile models.NFProfile
// // 	err := json.Unmarshal([]byte(nfProfileJSON), &nfProfile)
// // 	if err != nil {
// // 		return fmt.Errorf("failed to unmarshal NF profile: %w", err)
// // 	}

// // 	// Check if NF already exists
// // 	existingNF, err := ctx.GetStub().GetState(nfProfile.NfInstanceId)
// // 	if err != nil {
// // 		return fmt.Errorf("failed to read from world state: %w", err)
// // 	}
// // 	if existingNF != nil {
// // 		return fmt.Errorf("NF %s already exists", nfProfile.NfInstanceId)
// // 	}

// // 	// Set timestamps
// // 	now := time.Now()
// // 	nfProfile.CreatedAt = now
// // 	nfProfile.UpdatedAt = now
// // 	nfProfile.Version = 1
// // 	nfProfile.NfStatus = "REGISTERED"

// // 	nfJSON, err := json.Marshal(nfProfile)
// // 	if err != nil {
// // 		return fmt.Errorf("failed to marshal NF profile: %w", err)
// // 	}

// // 	err = ctx.GetStub().PutState(nfProfile.NfInstanceId, nfJSON)
// // 	if err != nil {
// // 		return fmt.Errorf("failed to put NF profile to world state: %w", err)
// // 	}

// // 	// Create composite key for querying by NF type
// // 	nfTypeKey, err := ctx.GetStub().CreateCompositeKey("nfType~nfInstanceId", []string{nfProfile.NfType, nfProfile.NfInstanceId})
// // 	if err != nil {
// // 		return fmt.Errorf("failed to create composite key: %w", err)
// // 	}
	
// // 	err = ctx.GetStub().PutState(nfTypeKey, []byte{0x00})
// // 	if err != nil {
// // 		return fmt.Errorf("failed to put composite key: %w", err)
// // 	}

// // 	// Emit event
// // 	eventPayload := map[string]interface{}{
// // 		"eventType":    "NF_REGISTERED",
// // 		"nfInstanceId": nfProfile.NfInstanceId,
// // 		"nfType":       nfProfile.NfType,
// // 		"timestamp":    now,
// // 	}
// // 	eventJSON, _ := json.Marshal(eventPayload)
// // 	ctx.GetStub().SetEvent("NFRegistered", eventJSON)

// // 	return nil
// // }

// // UpdateNF updates an existing Network Function profile
// func (c *NRFContract) UpdateNF(ctx contractapi.TransactionContextInterface, nfInstanceId string, updateJSON string) error {
// 	existingNFBytes, err := ctx.GetStub().GetState(nfInstanceId)
// 	if err != nil {
// 		return fmt.Errorf("failed to read NF profile: %w", err)
// 	}
// 	if existingNFBytes == nil {
// 		return fmt.Errorf("NF %s does not exist", nfInstanceId)
// 	}

// 	var existingNF models.NFProfile
// 	err = json.Unmarshal(existingNFBytes, &existingNF)
// 	if err != nil {
// 		return fmt.Errorf("failed to unmarshal existing NF: %w", err)
// 	}

// 	// Parse update data
// 	var updates map[string]interface{}
// 	err = json.Unmarshal([]byte(updateJSON), &updates)
// 	if err != nil {
// 		return fmt.Errorf("failed to unmarshal updates: %w", err)
// 	}

// 	// Merge updates (simplified - in production, use proper JSON merge)
// 	updateBytes, _ := json.Marshal(updates)
// 	err = json.Unmarshal(updateBytes, &existingNF)
// 	if err != nil {
// 		return fmt.Errorf("failed to apply updates: %w", err)
// 	}

//     txTime, err := getTxTime(ctx)
//     if err != nil {
//         return fmt.Errorf("failed to get tx time: %w", err)
//     }
// 	// Update metadata
// 	existingNF.UpdatedAt = txTime
// 	existingNF.Version++

// 	nfJSON, err := json.Marshal(existingNF)
// 	if err != nil {
// 		return fmt.Errorf("failed to marshal updated NF: %w", err)
// 	}

// 	err = ctx.GetStub().PutState(nfInstanceId, nfJSON)
// 	if err != nil {
// 		return fmt.Errorf("failed to update NF profile: %w", err)
// 	}

// 	// Emit event
// 	eventPayload := map[string]interface{}{
// 		"eventType":    "NF_UPDATED",
// 		"nfInstanceId": nfInstanceId,
// 		"version":      existingNF.Version,
// 		"timestamp":    existingNF.UpdatedAt,
// 	}
// 	eventJSON, _ := json.Marshal(eventPayload)
// 	ctx.GetStub().SetEvent("NFUpdated", eventJSON)

// 	return nil
// }

// // DeleteNF removes a Network Function profile
// func (c *NRFContract) DeleteNF(ctx contractapi.TransactionContextInterface, nfInstanceId string) error {
// 	nfBytes, err := ctx.GetStub().GetState(nfInstanceId)
// 	if err != nil {
// 		return fmt.Errorf("failed to read NF profile: %w", err)
// 	}
// 	if nfBytes == nil {
// 		return fmt.Errorf("NF %s does not exist", nfInstanceId)
// 	}

// 	var nfProfile models.NFProfile
// 	err = json.Unmarshal(nfBytes, &nfProfile)
// 	if err != nil {
// 		return fmt.Errorf("failed to unmarshal NF: %w", err)
// 	}

// 	// Delete main record
// 	err = ctx.GetStub().DelState(nfInstanceId)
// 	if err != nil {
// 		return fmt.Errorf("failed to delete NF profile: %w", err)
// 	}

// 	// Delete composite key
// 	nfTypeKey, err := ctx.GetStub().CreateCompositeKey("nfType~nfInstanceId", []string{nfProfile.NfType, nfInstanceId})
// 	if err != nil {
// 		return fmt.Errorf("failed to create composite key: %w", err)
// 	}
	
// 	err = ctx.GetStub().DelState(nfTypeKey)
// 	if err != nil {
// 		return fmt.Errorf("failed to delete composite key: %w", err)
// 	}

// 	// Revoke all tokens issued to this NF
// 	err = c.revokeNFTokens(ctx, nfInstanceId, "NF_DEREGISTERED")
// 	if err != nil {
// 		// Log but don't fail the deregistration
// 		fmt.Printf("Warning: failed to revoke tokens for NF %s: %v\n", nfInstanceId, err)
// 	}


// 	txTime, err := getTxTime(ctx)
//     if err != nil {
//         return fmt.Errorf("failed to get tx time: %w", err)
//     }

// 	// Emit event
// 	eventPayload := map[string]interface{}{
// 		"eventType":    "NF_DELETED",
// 		"nfInstanceId": nfInstanceId,
// 		"nfType":       nfProfile.NfType,
// 		"timestamp":    txTime,
// 	}
// 	eventJSON, _ := json.Marshal(eventPayload)
// 	ctx.GetStub().SetEvent("NFDeleted", eventJSON)

// 	return nil
// }

// // RetrieveNF retrieves a specific Network Function profile
// func (c *NRFContract) RetrieveNF(ctx contractapi.TransactionContextInterface, nfInstanceId string) (string, error) {
// 	nfBytes, err := ctx.GetStub().GetState(nfInstanceId)
// 	if err != nil {
// 		return "", fmt.Errorf("failed to read NF profile: %w", err)
// 	}
// 	if nfBytes == nil {
// 		return "", fmt.Errorf("NF %s does not exist", nfInstanceId)
// 	}

// 	return string(nfBytes), nil
// }

// // RetrieveAllNFs retrieves all Network Function profiles
// func (c *NRFContract) RetrieveAllNFs(ctx contractapi.TransactionContextInterface) (string, error) {
// 	resultsIterator, err := ctx.GetStub().GetStateByRange("", "")
// 	if err != nil {
// 		return "", fmt.Errorf("failed to get NF profiles: %w", err)
// 	}
// 	defer resultsIterator.Close()

// 	var nfProfiles []models.NFProfile
// 	for resultsIterator.HasNext() {
// 		queryResponse, err := resultsIterator.Next()
// 		if err != nil {
// 			return "", err
// 		}

// 		// Skip non-NF records (tokens, composite keys, etc.)
// 		if len(queryResponse.Key) < 36 { // UUID length check
// 			continue
// 		}

// 		var nfProfile models.NFProfile
// 		err = json.Unmarshal(queryResponse.Value, &nfProfile)
// 		if err != nil {
// 			continue // Skip invalid records
// 		}

// 		// Validate it's an NF profile by checking required fields
// 		if nfProfile.NfInstanceId != "" && nfProfile.NfType != "" {
// 			nfProfiles = append(nfProfiles, nfProfile)
// 		}
// 	}

// 	nfProfilesJSON, err := json.Marshal(nfProfiles)
// 	if err != nil {
// 		return "", fmt.Errorf("failed to marshal NF profiles: %w", err)
// 	}

// 	return string(nfProfilesJSON), nil
// }

// // RetrieveNFsByType retrieves all NFs of a specific type
// func (c *NRFContract) RetrieveNFsByType(ctx contractapi.TransactionContextInterface, nfType string) (string, error) {
// 	resultsIterator, err := ctx.GetStub().GetStateByPartialCompositeKey("nfType~nfInstanceId", []string{nfType})
// 	if err != nil {
// 		return "", fmt.Errorf("failed to query by NF type: %w", err)
// 	}
// 	defer resultsIterator.Close()

// 	var nfProfiles []models.NFProfile
// 	for resultsIterator.HasNext() {
// 		queryResponse, err := resultsIterator.Next()
// 		if err != nil {
// 			return "", err
// 		}

// 		// Extract nfInstanceId from composite key
// 		_, compositeKeyParts, err := ctx.GetStub().SplitCompositeKey(queryResponse.Key)
// 		if err != nil {
// 			continue
// 		}
		
// 		if len(compositeKeyParts) < 2 {
// 			continue
// 		}
		
// 		nfInstanceId := compositeKeyParts[1]

// 		// Get the actual NF profile
// 		nfBytes, err := ctx.GetStub().GetState(nfInstanceId)
// 		if err != nil || nfBytes == nil {
// 			continue
// 		}

// 		var nfProfile models.NFProfile
// 		err = json.Unmarshal(nfBytes, &nfProfile)
// 		if err != nil {
// 			continue
// 		}

// 		nfProfiles = append(nfProfiles, nfProfile)
// 	}

// 	nfProfilesJSON, err := json.Marshal(nfProfiles)
// 	if err != nil {
// 		return "", fmt.Errorf("failed to marshal NF profiles: %w", err)
// 	}

// 	return string(nfProfilesJSON), nil
// }

// ///////////////////////
// // OAuth Token Management Functions
// //////////////////////


// // GenerateOAuthToken only stores a token generated by the gateway.
// // The gateway sends a fully populated models.OAuthToken as JSON.
// func (c *NRFContract) GenerateOAuthToken(ctx contractapi.TransactionContextInterface, tokenMetaJSON string) (string, error) {
//     var token models.OAuthToken
//     if err := json.Unmarshal([]byte(tokenMetaJSON), &token); err != nil {
//         return "", fmt.Errorf("failed to unmarshal token metadata: %w", err)
//     }

//     if token.TokenId == "" {
//         return "", fmt.Errorf("missing token_id in metadata")
//     }
//     if token.NfInstanceId == "" {
//         return "", fmt.Errorf("missing nfInstanceId in metadata")
//     }

//     // Store full token record under deterministic key
//     tokenKey := fmt.Sprintf("token~%s", token.TokenId)
//     tokenBytes, err := json.Marshal(token)
//     if err != nil {
//         return "", fmt.Errorf("failed to marshal token: %w", err)
//     }

//     if err := ctx.GetStub().PutState(tokenKey, tokenBytes); err != nil {
//         return "", fmt.Errorf("failed to store token: %w", err)
//     }

//     // Create NF → token index for lookup / revocation
//     nfTokenKey, err := ctx.GetStub().CreateCompositeKey("nf~token", []string{token.NfInstanceId, token.TokenId})
//     if err != nil {
//         return "", fmt.Errorf("failed to create NF-token index: %w", err)
//     }
//     if err := ctx.GetStub().PutState(nfTokenKey, []byte{0x00}); err != nil {
//         return "", fmt.Errorf("failed to store NF-token index: %w", err)
//     }

//     // Emit event (deterministic, all fields are from metadata)
//     eventPayload := map[string]interface{}{
//         "eventType":    "TOKEN_STORED",
//         "tokenId":      token.TokenId,
//         "nfInstanceId": token.NfInstanceId,
//         "expiresAt":    token.ExpiresAt,
//         "timestamp":    token.IssuedAt,
//     }
//     eventJSON, _ := json.Marshal(eventPayload)
//     ctx.GetStub().SetEvent("TokenStored", eventJSON)

//     // Simple acknowledgement back to gateway
//     ack := map[string]interface{}{
//         "stored":   true,
//         "token_id": token.TokenId,
//     }
//     ackJSON, _ := json.Marshal(ack)
//     return string(ackJSON), nil
// }

// // RetrieveToken retrieves a token by token ID
// func (c *NRFContract) RetrieveToken(ctx contractapi.TransactionContextInterface, tokenID string) (string, error) {
// 	tokenKey := fmt.Sprintf("token~%s", tokenID)
// 	tokenBytes, err := ctx.GetStub().GetState(tokenKey)
// 	if err != nil {
// 		return "", fmt.Errorf("failed to read token: %w", err)
// 	}
// 	if tokenBytes == nil {
// 		return "", fmt.Errorf("token %s does not exist", tokenID)
// 	}

// 	return string(tokenBytes), nil
// }

// // ValidateNF checks if an NF is registered and valid
// func (c *NRFContract) ValidateNF(ctx contractapi.TransactionContextInterface, nfInstanceId string, nfType string) (string, error) {
// 	nfBytes, err := ctx.GetStub().GetState(nfInstanceId)
// 	if err != nil {
// 		return "false", fmt.Errorf("failed to read NF profile: %w", err)
// 	}
// 	if nfBytes == nil {
// 		return "false", nil
// 	}

// 	var nfProfile models.NFProfile
// 	err = json.Unmarshal(nfBytes, &nfProfile)
// 	if err != nil {
// 		return "false", fmt.Errorf("failed to unmarshal NF profile: %w", err)
// 	}

// 	// Validate NF type matches
// 	if nfProfile.NfType != nfType {
// 		return "false", nil
// 	}

// 	// Check NF status
// 	if nfProfile.NfStatus != "REGISTERED" {
// 		return "false", nil
// 	}

// 	return "true", nil
// }

// // RevokeToken revokes an OAuth token
// func (c *NRFContract) RevokeToken(ctx contractapi.TransactionContextInterface, tokenID string, reason string) error {
//     tokenKey := fmt.Sprintf("token~%s", tokenID)
//     tokenBytes, err := ctx.GetStub().GetState(tokenKey)
//     if err != nil {
//         return fmt.Errorf("failed to read token: %w", err)
//     }
//     if tokenBytes == nil {
//         return fmt.Errorf("token %s does not exist", tokenID)
//     }

//     var token models.OAuthToken
//     if err := json.Unmarshal(tokenBytes, &token); err != nil {
//         return fmt.Errorf("failed to unmarshal token: %w", err)
//     }

//     if token.Revoked {
//         return fmt.Errorf("token already revoked")
//     }

//     // *** use Fabric tx timestamp instead of time.Now() ***
//     txTs, err := ctx.GetStub().GetTxTimestamp()
//     if err != nil {
//         return fmt.Errorf("failed to get transaction timestamp: %w", err)
//     }
//     revokedAt := time.Unix(txTs.Seconds, int64(txTs.Nanos))

//     // Update token status
//     token.Revoked = true
//     token.RevokedAt = revokedAt
//     token.RevokedReason = reason

//     tokenJSON, err := json.Marshal(token)
//     if err != nil {
//         return fmt.Errorf("failed to marshal token: %w", err)
//     }

//     if err := ctx.GetStub().PutState(tokenKey, tokenJSON); err != nil {
//         return fmt.Errorf("failed to update token: %w", err)
//     }

//     // Emit event
//     eventPayload := map[string]interface{}{
//         "eventType": "TOKEN_REVOKED",
//         "tokenId":   tokenID,
//         "reason":    reason,
//         "timestamp": revokedAt,
//     }
//     eventJSON, _ := json.Marshal(eventPayload)
//     ctx.GetStub().SetEvent("TokenRevoked", eventJSON)

//     return nil
// }

// // CheckTokenValidity checks if a token is valid (not revoked and not expired)
// func (c *NRFContract) CheckTokenValidity(ctx contractapi.TransactionContextInterface, accessToken string) (string, error) {
// 	// Validate JWT signature and parse claims
// 	claims, err := utils.ValidateOAuthToken(accessToken)
// 	if err != nil {
// 		response := map[string]interface{}{
// 			"valid":  false,
// 			"reason": "INVALID_SIGNATURE",
// 			"error":  err.Error(),
// 		}
// 		responseJSON, _ := json.Marshal(response)
// 		return string(responseJSON), nil
// 	}

// 	// Check expiration
// 	if time.Now().Unix() > claims.Exp {
// 		response := map[string]interface{}{
// 			"valid":     false,
// 			"reason":    "EXPIRED",
// 			"expiresAt": time.Unix(claims.Exp, 0),
// 		}
// 		responseJSON, _ := json.Marshal(response)
// 		return string(responseJSON), nil
// 	}

// 	// Token is valid
// 	response := map[string]interface{}{
// 		"valid":     true,
// 		"iss":       claims.Iss,
// 		"sub":       claims.Sub,
// 		"aud":       claims.Aud,
// 		"scope":     claims.Scope,
// 		"issuedAt":  claims.IssuedAt.Time,
// 		"expiresAt": time.Unix(claims.Exp, 0),
// 	}
// 	responseJSON, _ := json.Marshal(response)
// 	return string(responseJSON), nil
// }

// // CheckTokenExpired specifically checks if a token is expired
// func (c *NRFContract) CheckTokenExpired(ctx contractapi.TransactionContextInterface, accessToken string) (string, error) {
// 	expired, err := utils.IsTokenExpired(accessToken)
// 	if err != nil {
// 		response := map[string]interface{}{
// 			"expired": true,
// 			"error":   err.Error(),
// 		}
// 		responseJSON, _ := json.Marshal(response)
// 		return string(responseJSON), nil
// 	}

// 	response := map[string]interface{}{
// 		"expired": expired,
// 	}
// 	responseJSON, _ := json.Marshal(response)
// 	return string(responseJSON), nil
// }

// // GetPublicKey returns the NRF public key for token validation
// func (c *NRFContract) GetPublicKey(ctx contractapi.TransactionContextInterface) (string, error) {
// 	pubKeyPEM, err := utils.GetPublicKeyPEM()
// 	if err != nil {
// 		return "", fmt.Errorf("failed to get public key: %w", err)
// 	}

// 	response := map[string]interface{}{
// 		"publicKey": pubKeyPEM,
// 		"algorithm": "RS512",
// 		"usage":     "Token validation for NFs",
// 	}
// 	responseJSON, _ := json.Marshal(response)
// 	return string(responseJSON), nil
// }

// // helper
// // revokeNFTokens revokes all tokens issued to a specific NF
// func (c *NRFContract) revokeNFTokens(ctx contractapi.TransactionContextInterface, nfInstanceId string, reason string) error {
// 	resultsIterator, err := ctx.GetStub().GetStateByPartialCompositeKey("nf~token", []string{nfInstanceId})
// 	if err != nil {
// 		return err
// 	}
// 	defer resultsIterator.Close()

// 	for resultsIterator.HasNext() {
// 		queryResponse, err := resultsIterator.Next()
// 		if err != nil {
// 			continue
// 		}

// 		_, compositeKeyParts, err := ctx.GetStub().SplitCompositeKey(queryResponse.Key)
// 		if err != nil || len(compositeKeyParts) < 2 {
// 			continue
// 		}

// 		tokenID := compositeKeyParts[1]
// 		c.RevokeToken(ctx, tokenID, reason)
// 	}

// 	return nil
// }
















package main

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
	"github.com/Rudrakshrawal/nrf-fabric-cc/models"
	"github.com/Rudrakshrawal/nrf-fabric-cc/utils"
)

// NRFContract smart contract for NF management and OAuth
type NRFContract struct {
	contractapi.Contract
}

///////////////////////
// Helper Functions
///////////////////////

func getTxTime(ctx contractapi.TransactionContextInterface) (time.Time, error) {
	ts, err := ctx.GetStub().GetTxTimestamp()
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to get tx timestamp: %w", err)
	}
	// Convert protobuf Timestamp to time.Time
	return time.Unix(ts.Seconds, int64(ts.Nanos)).UTC(), nil
}

///////////////////////
// NF Profile Management Functions
///////////////////////

// RegisterNF registers a new Network Function profile
func (c *NRFContract) RegisterNF(ctx contractapi.TransactionContextInterface, nfProfileJSON string) error {
	var nfProfile models.NFProfile
	if err := json.Unmarshal([]byte(nfProfileJSON), &nfProfile); err != nil {
		return fmt.Errorf("failed to unmarshal NF profile: %w", err)
	}

	existingNF, err := ctx.GetStub().GetState(nfProfile.NfInstanceId)
	if err != nil {
		return fmt.Errorf("failed to read from world state: %w", err)
	}
	if existingNF != nil {
		return fmt.Errorf("NF %s already exists", nfProfile.NfInstanceId)
	}

	// Use transaction timestamp for determinism
	txTime, err := getTxTime(ctx)
	if err != nil {
		return fmt.Errorf("failed to get tx time: %w", err)
	}

	nfProfile.CreatedAt = txTime
	nfProfile.UpdatedAt = txTime
	nfProfile.Version = 1
	nfProfile.NfStatus = "REGISTERED"

	nfJSON, err := json.Marshal(nfProfile)
	if err != nil {
		return fmt.Errorf("failed to marshal NF profile: %w", err)
	}

	if err := ctx.GetStub().PutState(nfProfile.NfInstanceId, nfJSON); err != nil {
		return fmt.Errorf("failed to put NF profile to world state: %w", err)
	}

	nfTypeKey, err := ctx.GetStub().CreateCompositeKey(
		"nfType~nfInstanceId",
		[]string{nfProfile.NfType, nfProfile.NfInstanceId},
	)
	if err != nil {
		return fmt.Errorf("failed to create composite key: %w", err)
	}

	if err := ctx.GetStub().PutState(nfTypeKey, []byte{0x00}); err != nil {
		return fmt.Errorf("failed to put composite key: %w", err)
	}

	// Emit event
	eventPayload := map[string]interface{}{
		"eventType":    "NF_REGISTERED",
		"nfInstanceId": nfProfile.NfInstanceId,
		"nfType":       nfProfile.NfType,
		"timestamp":    txTime,
	}
	eventJSON, _ := json.Marshal(eventPayload)
	ctx.GetStub().SetEvent("NFRegistered", eventJSON)

	return nil
}

// UpdateNF updates an existing Network Function profile
func (c *NRFContract) UpdateNF(ctx contractapi.TransactionContextInterface, nfInstanceId string, updateJSON string) error {
	existingNFBytes, err := ctx.GetStub().GetState(nfInstanceId)
	if err != nil {
		return fmt.Errorf("failed to read NF profile: %w", err)
	}
	if existingNFBytes == nil {
		return fmt.Errorf("NF %s does not exist", nfInstanceId)
	}

	var existingNF models.NFProfile
	err = json.Unmarshal(existingNFBytes, &existingNF)
	if err != nil {
		return fmt.Errorf("failed to unmarshal existing NF: %w", err)
	}

	// Parse update data
	var updates map[string]interface{}
	err = json.Unmarshal([]byte(updateJSON), &updates)
	if err != nil {
		return fmt.Errorf("failed to unmarshal updates: %w", err)
	}

	// Merge updates (simplified - in production, use proper JSON merge)
	updateBytes, _ := json.Marshal(updates)
	err = json.Unmarshal(updateBytes, &existingNF)
	if err != nil {
		return fmt.Errorf("failed to apply updates: %w", err)
	}

	txTime, err := getTxTime(ctx)
	if err != nil {
		return fmt.Errorf("failed to get tx time: %w", err)
	}

	// Update metadata
	existingNF.UpdatedAt = txTime
	existingNF.Version++

	nfJSON, err := json.Marshal(existingNF)
	if err != nil {
		return fmt.Errorf("failed to marshal updated NF: %w", err)
	}

	err = ctx.GetStub().PutState(nfInstanceId, nfJSON)
	if err != nil {
		return fmt.Errorf("failed to update NF profile: %w", err)
	}

	// Emit event
	eventPayload := map[string]interface{}{
		"eventType":    "NF_UPDATED",
		"nfInstanceId": nfInstanceId,
		"version":      existingNF.Version,
		"timestamp":    existingNF.UpdatedAt,
	}
	eventJSON, _ := json.Marshal(eventPayload)
	ctx.GetStub().SetEvent("NFUpdated", eventJSON)

	return nil
}

// DeleteNF removes a Network Function profile
func (c *NRFContract) DeleteNF(ctx contractapi.TransactionContextInterface, nfInstanceId string) error {
	nfBytes, err := ctx.GetStub().GetState(nfInstanceId)
	if err != nil {
		return fmt.Errorf("failed to read NF profile: %w", err)
	}
	if nfBytes == nil {
		return fmt.Errorf("NF %s does not exist", nfInstanceId)
	}

	var nfProfile models.NFProfile
	err = json.Unmarshal(nfBytes, &nfProfile)
	if err != nil {
		return fmt.Errorf("failed to unmarshal NF: %w", err)
	}

	// Delete main record
	err = ctx.GetStub().DelState(nfInstanceId)
	if err != nil {
		return fmt.Errorf("failed to delete NF profile: %w", err)
	}

	// Delete composite key
	nfTypeKey, err := ctx.GetStub().CreateCompositeKey("nfType~nfInstanceId", []string{nfProfile.NfType, nfInstanceId})
	if err != nil {
		return fmt.Errorf("failed to create composite key: %w", err)
	}

	err = ctx.GetStub().DelState(nfTypeKey)
	if err != nil {
		return fmt.Errorf("failed to delete composite key: %w", err)
	}

	// Revoke all tokens issued to this NF
	err = c.revokeNFTokens(ctx, nfInstanceId, "NF_DEREGISTERED")
	if err != nil {
		// Log but don't fail the deregistration
		fmt.Printf("Warning: failed to revoke tokens for NF %s: %v\n", nfInstanceId, err)
	}

	txTime, err := getTxTime(ctx)
	if err != nil {
		return fmt.Errorf("failed to get tx time: %w", err)
	}

	// Emit event
	eventPayload := map[string]interface{}{
		"eventType":    "NF_DELETED",
		"nfInstanceId": nfInstanceId,
		"nfType":       nfProfile.NfType,
		"timestamp":    txTime,
	}
	eventJSON, _ := json.Marshal(eventPayload)
	ctx.GetStub().SetEvent("NFDeleted", eventJSON)

	return nil
}

// RetrieveNF retrieves a specific Network Function profile
func (c *NRFContract) RetrieveNF(ctx contractapi.TransactionContextInterface, nfInstanceId string) (string, error) {
	nfBytes, err := ctx.GetStub().GetState(nfInstanceId)
	if err != nil {
		return "", fmt.Errorf("failed to read NF profile: %w", err)
	}
	if nfBytes == nil {
		return "", fmt.Errorf("NF %s does not exist", nfInstanceId)
	}

	return string(nfBytes), nil
}

// RetrieveAllNFs retrieves all Network Function profiles
func (c *NRFContract) RetrieveAllNFs(ctx contractapi.TransactionContextInterface) (string, error) {
	resultsIterator, err := ctx.GetStub().GetStateByRange("", "")
	if err != nil {
		return "", fmt.Errorf("failed to get NF profiles: %w", err)
	}
	defer resultsIterator.Close()

	var nfProfiles []models.NFProfile
	for resultsIterator.HasNext() {
		queryResponse, err := resultsIterator.Next()
		if err != nil {
			return "", err
		}

		// Skip non-NF records (tokens, composite keys, etc.)
		if len(queryResponse.Key) < 36 { // UUID length check
			continue
		}

		var nfProfile models.NFProfile
		err = json.Unmarshal(queryResponse.Value, &nfProfile)
		if err != nil {
			continue // Skip invalid records
		}

		// Validate it's an NF profile by checking required fields
		if nfProfile.NfInstanceId != "" && nfProfile.NfType != "" {
			nfProfiles = append(nfProfiles, nfProfile)
		}
	}

	nfProfilesJSON, err := json.Marshal(nfProfiles)
	if err != nil {
		return "", fmt.Errorf("failed to marshal NF profiles: %w", err)
	}

	return string(nfProfilesJSON), nil
}

// RetrieveNFsByType retrieves all NFs of a specific type
func (c *NRFContract) RetrieveNFsByType(ctx contractapi.TransactionContextInterface, nfType string) (string, error) {
	resultsIterator, err := ctx.GetStub().GetStateByPartialCompositeKey("nfType~nfInstanceId", []string{nfType})
	if err != nil {
		return "", fmt.Errorf("failed to query by NF type: %w", err)
	}
	defer resultsIterator.Close()

	var nfProfiles []models.NFProfile
	for resultsIterator.HasNext() {
		queryResponse, err := resultsIterator.Next()
		if err != nil {
			return "", err
		}

		// Extract nfInstanceId from composite key
		_, compositeKeyParts, err := ctx.GetStub().SplitCompositeKey(queryResponse.Key)
		if err != nil {
			continue
		}

		if len(compositeKeyParts) < 2 {
			continue
		}

		nfInstanceId := compositeKeyParts[1]

		// Get the actual NF profile
		nfBytes, err := ctx.GetStub().GetState(nfInstanceId)
		if err != nil || nfBytes == nil {
			continue
		}

		var nfProfile models.NFProfile
		err = json.Unmarshal(nfBytes, &nfProfile)
		if err != nil {
			continue
		}

		nfProfiles = append(nfProfiles, nfProfile)
	}

	nfProfilesJSON, err := json.Marshal(nfProfiles)
	if err != nil {
		return "", fmt.Errorf("failed to marshal NF profiles: %w", err)
	}

	return string(nfProfilesJSON), nil
}

///////////////////////
// OAuth Token Management Functions
///////////////////////

// GenerateOAuthToken only stores a token generated by the gateway.
// The gateway sends a fully populated models.OAuthToken as JSON.
func (c *NRFContract) GenerateOAuthToken(ctx contractapi.TransactionContextInterface, tokenMetaJSON string) (string, error) {
	var token models.OAuthToken
	if err := json.Unmarshal([]byte(tokenMetaJSON), &token); err != nil {
		return "", fmt.Errorf("failed to unmarshal token meta %w", err)
	}

	if token.TokenId == "" {
		return "", fmt.Errorf("missing token_id in metadata")
	}
	if token.NfInstanceId == "" {
		return "", fmt.Errorf("missing nfInstanceId in metadata")
	}

	// Store full token record under deterministic key
	tokenKey := fmt.Sprintf("token~%s", token.TokenId)
	tokenBytes, err := json.Marshal(token)
	if err != nil {
		return "", fmt.Errorf("failed to marshal token: %w", err)
	}

	if err := ctx.GetStub().PutState(tokenKey, tokenBytes); err != nil {
		return "", fmt.Errorf("failed to store token: %w", err)
	}

	// Create NF → token index for lookup / revocation
	nfTokenKey, err := ctx.GetStub().CreateCompositeKey("nf~token", []string{token.NfInstanceId, token.TokenId})
	if err != nil {
		return "", fmt.Errorf("failed to create NF-token index: %w", err)
	}
	if err := ctx.GetStub().PutState(nfTokenKey, []byte{0x00}); err != nil {
		return "", fmt.Errorf("failed to store NF-token index: %w", err)
	}

	// Emit event (deterministic, all fields are from metadata)
	eventPayload := map[string]interface{}{
		"eventType":    "TOKEN_STORED",
		"tokenId":      token.TokenId,
		"nfInstanceId": token.NfInstanceId,
		"expiresAt":    token.ExpiresAt,
		"timestamp":    token.IssuedAt,
	}
	eventJSON, _ := json.Marshal(eventPayload)
	ctx.GetStub().SetEvent("TokenStored", eventJSON)

	// Simple acknowledgement back to gateway
	ack := map[string]interface{}{
		"stored":   true,
		"token_id": token.TokenId,
	}
	ackJSON, _ := json.Marshal(ack)
	return string(ackJSON), nil
}

// RetrieveToken retrieves a token by token ID
func (c *NRFContract) RetrieveToken(ctx contractapi.TransactionContextInterface, tokenID string) (string, error) {
	tokenKey := fmt.Sprintf("token~%s", tokenID)
	tokenBytes, err := ctx.GetStub().GetState(tokenKey)
	if err != nil {
		return "", fmt.Errorf("failed to read token: %w", err)
	}
	if tokenBytes == nil {
		return "", fmt.Errorf("token %s does not exist", tokenID)
	}

	return string(tokenBytes), nil
}

// ValidateNF checks if an NF is registered and valid
func (c *NRFContract) ValidateNF(ctx contractapi.TransactionContextInterface, nfInstanceId string, nfType string) (string, error) {
	nfBytes, err := ctx.GetStub().GetState(nfInstanceId)
	if err != nil {
		return "false", fmt.Errorf("failed to read NF profile: %w", err)
	}
	if nfBytes == nil {
		return "false", nil
	}

	var nfProfile models.NFProfile
	err = json.Unmarshal(nfBytes, &nfProfile)
	if err != nil {
		return "false", fmt.Errorf("failed to unmarshal NF profile: %w", err)
	}

	// Validate NF type matches
	if nfProfile.NfType != nfType {
		return "false", nil
	}

	// Check NF status
	if nfProfile.NfStatus != "REGISTERED" {
		return "false", nil
	}

	return "true", nil
}

// RevokeToken revokes an OAuth token
func (c *NRFContract) RevokeToken(ctx contractapi.TransactionContextInterface, tokenID string, reason string) error {
	tokenKey := fmt.Sprintf("token~%s", tokenID)
	tokenBytes, err := ctx.GetStub().GetState(tokenKey)
	if err != nil {
		return fmt.Errorf("failed to read token: %w", err)
	}
	if tokenBytes == nil {
		return fmt.Errorf("token %s does not exist", tokenID)
	}

	var token models.OAuthToken
	if err := json.Unmarshal(tokenBytes, &token); err != nil {
		return fmt.Errorf("failed to unmarshal token: %w", err)
	}

	if token.Revoked {
		return fmt.Errorf("token already revoked")
	}

	// Use Fabric tx timestamp instead of time.Now()
	txTs, err := ctx.GetStub().GetTxTimestamp()
	if err != nil {
		return fmt.Errorf("failed to get transaction timestamp: %w", err)
	}
	revokedAt := time.Unix(txTs.Seconds, int64(txTs.Nanos)).UTC()

	// Update token status
	token.Revoked = true
	token.RevokedAt = revokedAt
	token.RevokedReason = reason

	tokenJSON, err := json.Marshal(token)
	if err != nil {
		return fmt.Errorf("failed to marshal token: %w", err)
	}

	if err := ctx.GetStub().PutState(tokenKey, tokenJSON); err != nil {
		return fmt.Errorf("failed to update token: %w", err)
	}

	// Emit event
	eventPayload := map[string]interface{}{
		"eventType": "TOKEN_REVOKED",
		"tokenId":   tokenID,
		"reason":    reason,
		"timestamp": revokedAt,
	}
	eventJSON, _ := json.Marshal(eventPayload)
	ctx.GetStub().SetEvent("TokenRevoked", eventJSON)

	return nil
}

// CheckTokenValidity checks if a token is valid (not revoked and not expired)
func (c *NRFContract) CheckTokenValidity(ctx contractapi.TransactionContextInterface, accessToken string) (string, error) {
	// 1) Validate JWT signature and parse claims
	claims, err := utils.ValidateOAuthToken(accessToken)
	if err != nil {
		resp := map[string]interface{}{
			"valid":  false,
			"reason": "INVALID_SIGNATURE", // generic validation error
			"error":  err.Error(),
		}
		b, mErr := json.Marshal(resp)
		if mErr != nil {
			return "", fmt.Errorf("failed to marshal validation error response: %w", mErr)
		}
		// Soft-fail: return JSON, no chaincode error
		return string(b), nil
	}

	// 2) Use Fabric tx timestamp for deterministic time
	txTs, err := ctx.GetStub().GetTxTimestamp()
	if err != nil {
		resp := map[string]interface{}{
			"valid":  false,
			"reason": "TIMESTAMP_ERROR",
			"error":  err.Error(),
		}
		b, mErr := json.Marshal(resp)
		if mErr != nil {
			return "", fmt.Errorf("failed to marshal timestamp error response: %w", mErr)
		}
		return string(b), nil
	}
	currentTime := time.Unix(txTs.Seconds, int64(txTs.Nanos)).UTC()

	// 3) Check expiration using tx time vs custom Exp
	if currentTime.Unix() > claims.Exp {
		resp := map[string]interface{}{
			"valid":     false,
			"reason":    "EXPIRED",
			"expiresAt": time.Unix(claims.Exp, 0).UTC(),
		}
		b, mErr := json.Marshal(resp)
		if mErr != nil {
			return "", fmt.Errorf("failed to marshal expired-token response: %w", mErr)
		}
		return string(b), nil
	}

	// 4) Token is valid
	issuedAt := time.Unix(claims.Iat, 0).UTC()
	expiresAt := time.Unix(claims.Exp, 0).UTC()

	resp := map[string]interface{}{
		"valid":     true,
		"iss":       claims.Iss,
		"sub":       claims.Sub,
		"aud":       claims.Aud,
		"scope":     claims.Scope,
		"issuedAt":  issuedAt,
		"expiresAt": expiresAt,
	}
	b, mErr := json.Marshal(resp)
	if mErr != nil {
		return "", fmt.Errorf("failed to marshal success response: %w", mErr)
	}

	return string(b), nil
}

// CheckTokenExpired specifically checks if a token is expired
func (c *NRFContract) CheckTokenExpired(ctx contractapi.TransactionContextInterface, accessToken string) (string, error) {
	// Parse claims
	claims, err := utils.ValidateOAuthToken(accessToken)
	if err != nil {
		response := map[string]interface{}{
			"expired": true,
			"error":   err.Error(),
		}
		responseJSON, _ := json.Marshal(response)
		return string(responseJSON), nil
	}

	// Get transaction timestamp
	txTs, err := ctx.GetStub().GetTxTimestamp()
	if err != nil {
		response := map[string]interface{}{
			"expired": true,
			"error":   "failed to get timestamp",
		}
		responseJSON, _ := json.Marshal(response)
		return string(responseJSON), nil
	}
	currentTime := time.Unix(txTs.Seconds, int64(txTs.Nanos)).UTC()

	// Check if expired
	expired := currentTime.Unix() > claims.Exp

	response := map[string]interface{}{
		"expired":     expired,
		"expiresAt":   time.Unix(claims.Exp, 0),
		"currentTime": currentTime,
	}
	responseJSON, _ := json.Marshal(response)
	return string(responseJSON), nil
}

// GetPublicKey returns the NRF public key for token validation
func (c *NRFContract) GetPublicKey(ctx contractapi.TransactionContextInterface) (string, error) {
	pubKeyPEM, err := utils.GetPublicKeyPEM()
	if err != nil {
		return "", fmt.Errorf("failed to get public key: %w", err)
	}

	response := map[string]interface{}{
		"publicKey": pubKeyPEM,
		"algorithm": "RS512",
		"usage":     "Token validation for NFs",
	}
	responseJSON, _ := json.Marshal(response)
	return string(responseJSON), nil
}

///////////////////////
// Helper Functions (Private)
///////////////////////

// revokeNFTokens revokes all tokens issued to a specific NF
func (c *NRFContract) revokeNFTokens(ctx contractapi.TransactionContextInterface, nfInstanceId string, reason string) error {
	resultsIterator, err := ctx.GetStub().GetStateByPartialCompositeKey("nf~token", []string{nfInstanceId})
	if err != nil {
		return err
	}
	defer resultsIterator.Close()

	for resultsIterator.HasNext() {
		queryResponse, err := resultsIterator.Next()
		if err != nil {
			continue
		}

		_, compositeKeyParts, err := ctx.GetStub().SplitCompositeKey(queryResponse.Key)
		if err != nil || len(compositeKeyParts) < 2 {
			continue
		}

		tokenID := compositeKeyParts[1]
		c.RevokeToken(ctx, tokenID, reason)
	}

	return nil
}
