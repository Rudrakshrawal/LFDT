package utils

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// ComputeHash generates SHA256 hash of an object
func ComputeHash(data interface{}) (string, error) {
	bytes, err := json.Marshal(data)
	if err != nil {
		return "", err
	}
	
	hash := sha256.Sum256(bytes)
	return hex.EncodeToString(hash[:]), nil
}

// VerifyIntegrity checks if stored hash matches computed hash
func VerifyIntegrity(data interface{}, storedHash string) (bool, error) {
	computedHash, err := ComputeHash(data)
	if err != nil {
		return false, err
	}
	
	return computedHash == storedHash, nil
}
