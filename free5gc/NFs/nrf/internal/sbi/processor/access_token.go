package processor

import (
	"crypto/x509"
	"net/http"
	"strings"
	"time"
	"bytes"
	"encoding/json"
	// "net/url"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"go.mongodb.org/mongo-driver/bson"

	nrf_context "github.com/free5gc/nrf/internal/context"
	"github.com/free5gc/nrf/internal/logger"
	"github.com/free5gc/nrf/internal/util"
	"github.com/free5gc/nrf/pkg/factory"
	"github.com/free5gc/openapi/models"
	"github.com/free5gc/openapi/oauth"
	"github.com/free5gc/util/mapstruct"
	"github.com/free5gc/util/metrics/sbi"
	"github.com/free5gc/util/mongoapi"
)

func (p *Processor) HandleAccessTokenRequest(c *gin.Context, accessTokenReq models.NrfAccessTokenAccessTokenReq) {
	// Param of AccessTokenRsp
	logger.AccTokenLog.Debugln("Handle AccessTokenRequest")


	if factory.NrfConfig.IsFabricEnabled() && factory.NrfConfig.IsFabricOAuthDelegated() {
		logger.AccTokenLog.Infoln("[Fabric OAuth] Delegating token generation to Fabric")
		p.handleAccessTokenViaFabric(c, accessTokenReq)
		return
	}

	

	response, errResponse := p.AccessTokenProcedure(accessTokenReq)
	if errResponse != nil {
		c.Set(sbi.IN_PB_DETAILS_CTX_STR, errResponse.Error)
		c.JSON(http.StatusBadRequest, errResponse)
		return
	} else if response != nil {
		// status code is based on SPEC, and option headers
		c.JSON(http.StatusOK, response)
		return
	}

	logger.AccTokenLog.Errorln("AccessTokenProcedure returned neither an error nor a response")
	problemDetails := &models.ProblemDetails{
		Status: http.StatusInternalServerError,
		Cause:  "UNSPECIFIED",
	}
	util.GinProblemJson(c, problemDetails)
}

func (p *Processor) AccessTokenProcedure(request models.NrfAccessTokenAccessTokenReq) (
	*models.NrfAccessTokenAccessTokenRsp, *models.AccessTokenErr,
) {
	logger.AccTokenLog.Debugln("In AccessTokenProcedure")

	var (
		expiration = int32(1000)
		tokenType  = "Bearer"
	)
	scope := request.Scope
	now := time.Now()
	nowNum := int32(now.Unix())

	errResponse := p.AccessTokenScopeCheck(request)
	if errResponse != nil {
		logger.AccTokenLog.Errorf("AccessTokenScopeCheck error: %v", errResponse.Error)
		return nil, errResponse
	}

	// Create AccessToken
	nrfCtx := nrf_context.GetSelf()
	accessTokenClaims := models.AccessTokenClaims{
		Iss:              nrfCtx.Nrf_NfInstanceID,    // NF instance id of the NRF
		Sub:              request.NfInstanceId,       // nfInstanceId of service consumer
		Aud:              request.TargetNfInstanceId, // nfInstanceId of service producer
		Scope:            request.Scope,              // TODO: the name of the NF services for which the
		Exp:              nowNum + expiration,        // access_token is authorized for use
		RegisteredClaims: jwt.RegisteredClaims{},
	}
	accessTokenClaims.IssuedAt = &jwt.NumericDate{Time: now}

	// Use NRF private key to sign AccessToken
	token := jwt.NewWithClaims(jwt.GetSigningMethod("RS512"), accessTokenClaims)
	accessToken, err := token.SignedString(nrfCtx.NrfPrivKey)
	if err != nil {
		logger.AccTokenLog.Warnln("Signed string error: ", err)
		return nil, &models.AccessTokenErr{
			Error: "invalid_request",
		}
	}

	response := &models.NrfAccessTokenAccessTokenRsp{
		AccessToken: accessToken,
		TokenType:   tokenType,
		ExpiresIn:   expiration,
		Scope:       scope,
	}
	return response, nil
}







// handleAccessTokenViaFabric delegates OAuth token generation to Fabric chaincode
func (p *Processor) handleAccessTokenViaFabric(c *gin.Context, accessTokenReq models.NrfAccessTokenAccessTokenReq) {
	fabricURL := factory.NrfConfig.GetFabricChainCodeURL()
	if fabricURL == "" {
		logger.AccTokenLog.Errorln("[Fabric OAuth] Chaincode URL not configured")
		errResponse := &models.AccessTokenErr{
			Error:            "server_error",
			ErrorDescription: "Fabric chaincode URL is not configured",
		}
		c.JSON(http.StatusInternalServerError, errResponse)
		return
	}

	// Perform local scope validation first
	if err := p.AccessTokenScopeCheck(accessTokenReq); err != nil {
		logger.AccTokenLog.Errorf("[Fabric OAuth] Scope check failed: %v", err.Error)
		c.Set(sbi.IN_PB_DETAILS_CTX_STR, err.Error)
		c.JSON(http.StatusBadRequest, err)
		return
	}

	// Prepare request payload for Fabric chaincode
	fabricRequest := map[string]interface{}{
		"operation":          "generateOAuthToken",
		"grant_type":         accessTokenReq.GrantType,
		"nfType":             string(accessTokenReq.NfType),
		"nfInstanceId":       accessTokenReq.NfInstanceId,
		"targetNfType":       string(accessTokenReq.TargetNfType),
		"targetNfInstanceId": accessTokenReq.TargetNfInstanceId,
		"scope":              accessTokenReq.Scope,
		"timestamp":          time.Now().UTC(),
		"nrfInstanceId":      nrf_context.GetSelf().Nrf_NfInstanceID,
	}

	jsonData, err := json.Marshal(fabricRequest)
	if err != nil {
		logger.AccTokenLog.Errorf("[Fabric OAuth] Failed to marshal request: %v", err)
		errResponse := &models.AccessTokenErr{
			Error: "server_error",
		}
		c.JSON(http.StatusInternalServerError, errResponse)
		return
	}

	logger.AccTokenLog.Infof("[Fabric OAuth] → Requesting token from Fabric for NF: %s [%s]",
		accessTokenReq.NfInstanceId, accessTokenReq.NfType)

	// Send HTTP POST request to Fabric chaincode
	client := &http.Client{
		Timeout: 15 * time.Second,
	}

	resp, err := client.Post(fabricURL+"/oauth/token", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		logger.AccTokenLog.Errorf("[Fabric OAuth] : Failed to contact Fabric: %v", err)
		errResponse := &models.AccessTokenErr{
			Error:            "temporarily_unavailable",
			ErrorDescription: "Fabric service is unavailable",
		}
		c.JSON(http.StatusServiceUnavailable, errResponse)
		return
	}
	defer resp.Body.Close()

	// Check response status from Fabric
	if resp.StatusCode != http.StatusOK {
		logger.AccTokenLog.Errorf("[Fabric OAuth] : Fabric returned error status: %d", resp.StatusCode)
		
		var fabricError models.AccessTokenErr
		if err := json.NewDecoder(resp.Body).Decode(&fabricError); err == nil {
			c.JSON(resp.StatusCode, fabricError)
		} else {
			errResponse := &models.AccessTokenErr{
				Error:            "server_error",
				ErrorDescription: "Fabric token generation failed",
			}
			c.JSON(resp.StatusCode, errResponse)
		}
		return
	}

	// Parse successful token response from Fabric
	var fabricResponse models.NrfAccessTokenAccessTokenRsp
	if err := json.NewDecoder(resp.Body).Decode(&fabricResponse); err != nil {
		logger.AccTokenLog.Errorf("[Fabric OAuth] : Failed to decode Fabric response: %v", err)
		errResponse := &models.AccessTokenErr{
			Error:            "server_error",
			ErrorDescription: "Invalid response from Fabric",
		}
		c.JSON(http.StatusInternalServerError, errResponse)
		return
	}

	logger.AccTokenLog.Infof("[Fabric OAuth] : Token successfully received from Fabric for NF: %s", 
		accessTokenReq.NfInstanceId)
	logger.AccTokenLog.Infof("[Fabric OAuth] : Token Type: %s, Expires In: %d seconds", 
		fabricResponse.TokenType, fabricResponse.ExpiresIn)

	// Return the token to the requesting NF
	c.JSON(http.StatusOK, fabricResponse)
}






func (p *Processor) AccessTokenScopeCheck(req models.NrfAccessTokenAccessTokenReq) *models.AccessTokenErr {
	// Check with nf profile
	collName := nrf_context.NfProfileCollName
	reqGrantType := req.GrantType
	reqNfType := strings.ToUpper(string(req.NfType))
	reqTargetNfType := strings.ToUpper(string(req.TargetNfType))
	reqNfInstanceId := req.NfInstanceId

	if reqGrantType != "client_credentials" {
		return &models.AccessTokenErr{
			Error: "unsupported_grant_type",
		}
	}

	if reqNfType == "" || reqTargetNfType == "" || reqNfInstanceId == "" {
		return &models.AccessTokenErr{
			Error: "invalid_request",
		}
	}

	logger.AccTokenLog.Debugf("reqNfInstanceId: %s", reqNfInstanceId)
	filter := bson.M{"nfInstanceId": reqNfInstanceId}
	consumerNfInfo, err := mongoapi.RestfulAPIGetOne(collName, filter)
	if err != nil {
		logger.AccTokenLog.Errorln("mongoapi RestfulAPIGetOne error: " + err.Error())
		return &models.AccessTokenErr{
			Error: "invalid_client",
		}
	}

	nfProfile := models.NrfNfManagementNfProfile{}

	err = mapstruct.Decode(consumerNfInfo, &nfProfile)
	if err != nil {
		logger.AccTokenLog.Errorln("Certificate verify error: " + err.Error())
		return &models.AccessTokenErr{
			Error: "invalid_client",
		}
	}

	if strings.ToUpper(string(nfProfile.NfType)) != reqNfType {
		return &models.AccessTokenErr{
			Error: "invalid_client",
		}
	}

	// //////////// CERTIFICATE VERIFICATION 
	// Skip certificate verification if Fabric OAuth is enabled
	if !factory.NrfConfig.IsFabricEnabled() || !factory.NrfConfig.IsFabricOAuthDelegated() {
		// Only verify certificate when NOT using Fabric OAuth
		if err := p.verifyCertificate(reqNfType, reqNfInstanceId); err != nil {
			return err
		}
	} else {
		logger.AccTokenLog.Debugln("[Fabric OAuth] Skipping certificate verification")
	}
	// //////////////////////////////////////////////

	// Check scope
	if reqTargetNfType == "NRF" {
		return nil
	}
	filter = bson.M{"nfType": reqTargetNfType}
	producerNfInfo, err := mongoapi.RestfulAPIGetOne(collName, filter)
	if err != nil {
		logger.AccTokenLog.Errorln("mongoapi.RestfulApiGetOne error: " + err.Error())
		return &models.AccessTokenErr{
			Error: "invalid_client",
		}
	}

	if len(producerNfInfo) == 0 {
		logger.AccTokenLog.Errorln("no producerNfInfor for targetNfType " + reqTargetNfType)
		return &models.AccessTokenErr{
			Error: "invalid_client",
		}
	}

	nfProfile = models.NrfNfManagementNfProfile{}
	err = mapstruct.Decode(producerNfInfo, &nfProfile)
	if err != nil {
		logger.AccTokenLog.Errorln("Certificate verify error: " + err.Error())
		return &models.AccessTokenErr{
			Error: "invalid_client",
		}
	}
	nfServices := nfProfile.NfServices

	scopes := strings.Split(req.Scope, " ")

	for _, reqNfService := range scopes {
		found := false
		for _, nfService := range nfServices {
			if string(nfService.ServiceName) == reqNfService {
				if len(nfService.AllowedNfTypes) == 0 {
					found = true
					break
				} else {
					for _, nfType := range nfService.AllowedNfTypes {
						if string(nfType) == reqNfType {
							found = true
							break
						}
					}
					break
				}
			}
		}
		if !found {
			logger.AccTokenLog.Errorln("Certificate verify error: Request out of scope (" + reqNfService + ")")
			return &models.AccessTokenErr{
				Error: "invalid_scope",
			}
		}
	}
	return nil
}

func (p *Processor) verifyCertificate(reqNfType string, reqNfInstanceId string) *models.AccessTokenErr {
	// Verify NF's certificate with root certificate
	roots := x509.NewCertPool()
	nrfCtx := nrf_context.GetSelf()
	roots.AddCert(nrfCtx.RootCert)

	nfCert, err := oauth.ParseCertFromPEM(
		oauth.GetNFCertPath(factory.NrfConfig.GetCertBasePath(), reqNfType, reqNfInstanceId))
	if err != nil {
		logger.AccTokenLog.Errorln("NF Certificate get error: " + err.Error())
		return &models.AccessTokenErr{
			Error: "invalid_client",
		}
	}

	opts := x509.VerifyOptions{
		Roots:   roots,
		DNSName: reqNfType,
	}
	if _, err = nfCert.Verify(opts); err != nil {
		// DEBUG
		// In testing environment, this would leads to follwing error:
		// certificate verify error: x509: certificate signed by unknown authority free5GC
		if strings.Contains(err.Error(), "unknown authority") {
			logger.AccTokenLog.Warnf("Certificate verify: %v", err)
		} else {
			logger.AccTokenLog.Errorf("Certificate verify: %v", err)
			return &models.AccessTokenErr{
				Error: "invalid_client",
			}
		}
	}

	uri := nfCert.URIs[0]
	id := strings.Split(uri.Opaque, ":")[1]
	if id != reqNfInstanceId {
		logger.AccTokenLog.Errorln("Certificate verify error: NF Instance Id mismatch (Expected ID: " +
			reqNfInstanceId + " Received ID: " + id + ")")
		return &models.AccessTokenErr{
			Error: "invalid_client",
		}
	}

	return nil
}

