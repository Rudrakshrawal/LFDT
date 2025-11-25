package utils

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var (
	nrfPrivateKey *rsa.PrivateKey
	nrfPublicKey  *rsa.PublicKey
)

// InitializeKeys must be called at chaincode startup
func InitializeKeys() error {
	return LoadNRFPrivateKey()
}

// LoadNRFPrivateKey loads the NRF private key from environment or file
func LoadNRFPrivateKey() error {
	keyPEM := os.Getenv("NRF_PRIVATE_KEY")
	
	if keyPEM == "" {
		keyPath := os.Getenv("NRF_PRIVATE_KEY_PATH")
		if keyPath == "" {
			keyPath = "../nrf.key"
		}
		
		keyBytes, err := os.ReadFile(keyPath)
		if err != nil {
			return fmt.Errorf("failed to read private key file from %s: %w", keyPath, err)
		}
		keyPEM = string(keyBytes)
	}

	// Parse PEM block
	block, rest := pem.Decode([]byte(keyPEM))
	if block == nil {
		return errors.New("failed to parse PEM block containing the private key")
	}
	
	if len(rest) > 0 {
		fmt.Println("Warning: Extra data found after private key PEM block")
	}

	var err error
	var parsedKey interface{}

	// Try multiple parsing methods
	switch block.Type {
	case "RSA PRIVATE KEY":
		// PKCS#1 format
		nrfPrivateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return fmt.Errorf("failed to parse PKCS1 private key: %w", err)
		}
		
	case "PRIVATE KEY":
		// PKCS#8 format
		parsedKey, err = x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return fmt.Errorf("failed to parse PKCS8 private key: %w", err)
		}
		
		var ok bool
		nrfPrivateKey, ok = parsedKey.(*rsa.PrivateKey)
		if !ok {
			return errors.New("parsed key is not an RSA private key")
		}
		
	default:
		return fmt.Errorf("unsupported PEM block type: %s (expected 'RSA PRIVATE KEY' or 'PRIVATE KEY')", block.Type)
	}

	if nrfPrivateKey == nil {//key verification
		return errors.New("private key is nil after parsing")
	}

	keySize := nrfPrivateKey.N.BitLen()//key validation
	if keySize < 2048 {
		return fmt.Errorf("RSA key size %d is too small (minimum 2048 bits required)", keySize)
	}

	// Extract and validate public key
	nrfPublicKey = &nrfPrivateKey.PublicKey
	if nrfPublicKey == nil {
		return errors.New("failed to extract public key from private key")
	}

	fmt.Printf("[JWT] Successfully loaded RSA private key (%d bits)\n", keySize)
	return nil
}

// AccessTokenClaims represents the JWT claims for OAuth access token
// Matches the structure expected by free5GC NRF
type AccessTokenClaims struct {
	Iss   string `json:"iss"`   // Issuer (NRF instance ID)
	Sub   string `json:"sub"`   // Subject (consumer NF instance ID)
	Aud   string `json:"aud"`   // Audience (producer NF instance ID)
	Scope string `json:"scope"` // Scope (NF services)
	Exp   int64  `json:"exp"`   // Expiration time (Unix timestamp)
	Iat   int64  `json:"iat"`   // Issued at (Unix timestamp)
	jwt.RegisteredClaims
}

//GenerateOAuthToken: creates a signed JWT token using RS512 algorithm
func GenerateOAuthToken(issuer, subject, audience, scope string, expiresIn int32) (string, error) {
	if nrfPrivateKey == nil {
		return "", errors.New("NRF private key not loaded - call InitializeKeys() first")
	}

	// Validate inputs
	if issuer == "" {
		return "", errors.New("issuer cannot be empty")
	}
	if subject == "" {
		return "", errors.New("subject (consumer NF) cannot be empty")
	}
	if audience == "" {
		return "", errors.New("audience (producer NF) cannot be empty")
	}
	if scope == "" {
		return "", errors.New("scope cannot be empty")
	}
	if expiresIn <= 0 {
		return "", errors.New("expiresIn must be positive")
	}

	now := time.Now()
	expirationTime := now.Add(time.Duration(expiresIn) * time.Second)

	// Create claims
	claims := AccessTokenClaims{
		Iss:   issuer,
		Sub:   subject,
		Aud:   audience,
		Scope: scope,
		Exp:   expirationTime.Unix(),
		Iat:   now.Unix(),
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expirationTime),
		},
	}

	// Create token with RS512 signing method (as per free5GC specification)
	token := jwt.NewWithClaims(jwt.SigningMethodRS512, claims)

	// Sign token
	signedToken, err := token.SignedString(nrfPrivateKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return signedToken, nil
}

// ValidateOAuthToken validates and parses a JWT token
func ValidateOAuthToken(tokenString string) (*AccessTokenClaims, error) {
	if tokenString == "" {
		return nil, errors.New("token string is empty")
	}

	if nrfPublicKey == nil {
		return nil, errors.New("NRF public key not available - call InitializeKeys() first")
	}

	// Parse and validate token
	token, err := jwt.ParseWithClaims(
		tokenString,
		&AccessTokenClaims{},
		func(token *jwt.Token) (interface{}, error) {
			// Verify signing method is RS512
			method, ok := token.Method.(*jwt.SigningMethodRSA)
			if !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			if method.Alg() != jwt.SigningMethodRS512.Alg() {
				return nil, fmt.Errorf(
					"unexpected signing method: expected %s, got %s",
					jwt.SigningMethodRS512.Alg(),
					method.Alg(),
				)
			}
			return nrfPublicKey, nil
		},
	)

	if err != nil {
		// More specific error messages based on jwt/v5 sentinels
		switch {
		case errors.Is(err, jwt.ErrTokenExpired):
			return nil, fmt.Errorf("token expired: %w", err)
		case errors.Is(err, jwt.ErrTokenNotValidYet):
			return nil, fmt.Errorf("token not valid yet: %w", err)
		case errors.Is(err, jwt.ErrTokenMalformed):
			return nil, fmt.Errorf("token malformed: %w", err)
		default:
			return nil, fmt.Errorf("token validation failed: %w", err)
		}
	}

	claims, ok := token.Claims.(*AccessTokenClaims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token claims")
	}

	// Extra semantic checks
	if claims.Iss == "" {
		return nil, errors.New("token missing issuer claim")
	}
	if claims.Sub == "" {
		return nil, errors.New("token missing subject claim")
	}
	if claims.Aud == "" {
		return nil, errors.New("token missing audience claim")
	}
	if claims.Scope == "" {
		return nil, errors.New("token missing scope claim")
	}
	if claims.Exp == 0 {
		return nil, errors.New("token missing expiration claim")
	}
	if claims.Iat == 0 {
		return nil, errors.New("token missing issued-at claim")
	}

	return claims, nil
}

// IsTokenExpired checks if a token is expired without full validation
// Useful for quick checks before full validation
func IsTokenExpired(tokenString string) (bool, error) {
	if tokenString == "" {
		return false, errors.New("token string is empty")
	}

	// Parse without validation to check expiry
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	token, _, err := parser.ParseUnverified(tokenString, &AccessTokenClaims{})
	if err != nil {
		return false, fmt.Errorf("failed to parse token: %w", err)
	}

	claims, ok := token.Claims.(*AccessTokenClaims)
	if !ok {
		return false, errors.New("invalid claims structure")
	}

	if claims.Exp == 0 {
		return false, errors.New("token missing expiration claim")
	}

	// Check if expired
	now := time.Now().Unix()
	isExpired := now > claims.Exp

	return isExpired, nil
}

// VerifyTokenExpiry validates token and checks expiration (combined operation)
func VerifyTokenExpiry(tokenString string) (expired bool, valid bool, err error) {
	claims, err := ValidateOAuthToken(tokenString)
	if err != nil {
		// If error is due to expiration, token structure might still be valid
		if errors.Is(err, jwt.ErrTokenExpired) {
			return true, false, nil
		}
		return false, false, err
	}

	// Token is valid, check if it's about to expire (within 60 seconds)
	now := time.Now().Unix()
	isExpired := now > claims.Exp

	return isExpired, true, nil
}

// GenerateTokenID creates a unique token identifier
func GenerateTokenID() (string, error) {
	bytes := make([]byte, 16) // 128 bits
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}
	return hex.EncodeToString(bytes), nil
}

// GetPublicKeyPEM exports the public key in PEM format for NFs to validate tokens
func GetPublicKeyPEM() (string, error) {
	if nrfPublicKey == nil {
		return "", errors.New("public key not available - call InitializeKeys() first")
	}

	// Marshal public key to PKIX format
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(nrfPublicKey)
	if err != nil {
		return "", fmt.Errorf("failed to marshal public key: %w", err)
	}

	// Encode to PEM
	pubKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	})

	if pubKeyPEM == nil {
		return "", errors.New("failed to encode public key to PEM")
	}

	return string(pubKeyPEM), nil
}

// GetPublicKey returns the raw RSA public key
func GetPublicKey() *rsa.PublicKey {
	return nrfPublicKey
}

// GetPrivateKey returns the raw RSA private key (use with caution)
func GetPrivateKey() *rsa.PrivateKey {
	return nrfPrivateKey
}

// ExtractClaimsWithoutValidation extracts claims without signature verification
// WARNING: Use only for debugging or non-security-critical operations
func ExtractClaimsWithoutValidation(tokenString string) (*AccessTokenClaims, error) {
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	token, _, err := parser.ParseUnverified(tokenString, &AccessTokenClaims{})
	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	claims, ok := token.Claims.(*AccessTokenClaims)
	if !ok {
		return nil, errors.New("invalid claims structure")
	}

	return claims, nil
}

// ValidateTokenForAudience validates token and checks if it's intended for specific audience
func ValidateTokenForAudience(tokenString string, expectedAudience string) error {
	claims, err := ValidateOAuthToken(tokenString)
	if err != nil {
		return err
	}

	if claims.Aud != expectedAudience {
		return fmt.Errorf("token audience mismatch: expected %s, got %s", expectedAudience, claims.Aud)
	}

	return nil
}

// GetTokenTTL returns the remaining time-to-live for a token in seconds
func GetTokenTTL(tokenString string) (int64, error) {
	claims, err := ValidateOAuthToken(tokenString)
	if err != nil {
		return 0, err
	}

	now := time.Now().Unix()
	ttl := claims.Exp - now

	if ttl < 0 {
		return 0, errors.New("token has expired")
	}

	return ttl, nil
}
