package models

import (
	"time"
)

///////////// NFProfile represents NF profile stored on ledegr
type NFProfile struct {
	NfInstanceId       string                 `json:"nfInstanceId"`
	NfType             string                 `json:"nfType"`
	NfStatus           string                 `json:"nfStatus"`
	PlmnList           []PlmnId               `json:"plmnList,omitempty"`
	SNssais            []Snssai               `json:"sNssais,omitempty"`
	NfServices         []NFService            `json:"nfServices,omitempty"`
	DefaultNotificationSubscriptions []DefaultNotificationSubscription `json:"defaultNotificationSubscriptions,omitempty"`
	Ipv4Addresses      []string               `json:"ipv4Addresses,omitempty"`
	Ipv6Addresses      []string               `json:"ipv6Addresses,omitempty"`
	AllowedNfTypes     []string               `json:"allowedNfTypes,omitempty"`
	Priority           int32                  `json:"priority,omitempty"`
	Capacity           int32                  `json:"capacity,omitempty"`
	Load               int32                  `json:"load,omitempty"`
	Locality           string                 `json:"locality,omitempty"`
	UdrInfo            map[string]interface{} `json:"udrInfo,omitempty"`
	UdmInfo            map[string]interface{} `json:"udmInfo,omitempty"`
	AusfInfo           map[string]interface{} `json:"ausfInfo,omitempty"`
	AmfInfo            map[string]interface{} `json:"amfInfo,omitempty"`
	SmfInfo            map[string]interface{} `json:"smfInfo,omitempty"`
	UpfInfo            map[string]interface{} `json:"upfInfo,omitempty"`
	PcfInfo            map[string]interface{} `json:"pcfInfo,omitempty"`
	BsfInfo            map[string]interface{} `json:"bsfInfo,omitempty"`
	ChfInfo            map[string]interface{} `json:"chfInfo,omitempty"`
	NrfInfo            map[string]interface{} `json:"nrfInfo,omitempty"`
	CustomInfo         map[string]interface{} `json:"customInfo,omitempty"`
	RecoveryTime       time.Time              `json:"recoveryTime,omitempty"`
	NfServicePersistence bool                 `json:"nfServicePersistence,omitempty"`
	NfProfileChangesSupportInd bool          `json:"nfProfileChangesSupportInd,omitempty"`
	NfProfileChangesInd bool                   `json:"nfProfileChangesInd,omitempty"`
	HeartBeatTimer     int32                  `json:"heartBeatTimer,omitempty"`
	CreatedAt          time.Time              `json:"createdAt"`
	UpdatedAt          time.Time              `json:"updatedAt"`
	Version            int32                  `json:"version"`
}

type PlmnId struct {
	Mcc string `json:"mcc"`
	Mnc string `json:"mnc"`
}

type Snssai struct {
	Sst int32  `json:"sst"`
	Sd  string `json:"sd,omitempty"`
}

type NFService struct {
	ServiceInstanceId string              `json:"serviceInstanceId"`
	ServiceName       string              `json:"serviceName"`
	Versions          []NFServiceVersion  `json:"versions,omitempty"`
	Scheme            string              `json:"scheme"`
	NfServiceStatus   string              `json:"nfServiceStatus"`
	ApiPrefix         string              `json:"apiPrefix,omitempty"`
	IpEndPoints       []IpEndPoint        `json:"ipEndPoints,omitempty"`
	AllowedNfTypes    []string            `json:"allowedNfTypes,omitempty"`
	Priority          int32               `json:"priority,omitempty"`
	Capacity          int32               `json:"capacity,omitempty"`
	Load              int32               `json:"load,omitempty"`
	RecoveryTime      time.Time           `json:"recoveryTime,omitempty"`
	SupportedFeatures string              `json:"supportedFeatures,omitempty"`
}

type NFServiceVersion struct {
	ApiVersionInUri string `json:"apiVersionInUri"`
	ApiFullVersion  string `json:"apiFullVersion"`
}

type IpEndPoint struct {
	Ipv4Address string `json:"ipv4Address,omitempty"`
	Ipv6Address string `json:"ipv6Address,omitempty"`
	Port        int32  `json:"port,omitempty"`
	Transport   string `json:"transport,omitempty"`
}

type DefaultNotificationSubscription struct {
	NotificationType    string `json:"notificationType"`
	CallbackUri         string `json:"callbackUri"`
	N1MessageClass      string `json:"n1MessageClass,omitempty"`
	N2InformationClass  string `json:"n2InformationClass,omitempty"`
}

///////////// OAuthToken represents an OAuth 2.0 access token on blockchain
type OAuthToken struct {
	TokenId            string    `json:"tokenId"`            // Unique token identifier
	AccessToken        string    `json:"accessToken"`        // JWT token string
	TokenType          string    `json:"tokenType"`          // Bearer
	ExpiresIn          int32     `json:"expiresIn"`          // Expiration in seconds
	Scope              string    `json:"scope"`              // Token scope
	NfInstanceId       string    `json:"nfInstanceId"`       // Consumer NF
	NfType             string    `json:"nfType"`             // Consumer NF type
	TargetNfInstanceId string    `json:"targetNfInstanceId"` // Producer NF
	TargetNfType       string    `json:"targetNfType"`       // Producer NF type
	GrantType          string    `json:"grantType"`          // client_credentials
	Issuer             string    `json:"issuer"`             // NRF instance ID
	IssuedAt           time.Time `json:"issuedAt"`           // Token issue time
	ExpiresAt          time.Time `json:"expiresAt"`          // Token expiry time
	Revoked            bool      `json:"revoked"`            // Revocation status
	RevokedAt          time.Time `json:"revokedAt,omitempty"`
	RevokedReason      string    `json:"revokedReason,omitempty"`
}

///////////// TokenRequest represents OAuth token generation request
type TokenRequest struct {
	GrantType          string `json:"grant_type"`
	NfType             string `json:"nfType"`
	NfInstanceId       string `json:"nfInstanceId"`
	TargetNfType       string `json:"targetNfType"`
	TargetNfInstanceId string `json:"targetNfInstanceId"`
	Scope              string `json:"scope"`
	NrfInstanceId      string `json:"nrfInstanceId"`
	ExpiresIn          int32  `json:"expires_in,omitempty"`
}

///////////// QueryResult structure used for handling result of query
type QueryResult struct {
	Key    string `json:"Key"`
	Record interface{} `json:"Record"`
}
