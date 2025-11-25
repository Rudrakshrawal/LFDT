package processor

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/mitchellh/mapstructure"
	"go.mongodb.org/mongo-driver/bson"

	nrf_context "github.com/free5gc/nrf/internal/context"
	"github.com/free5gc/nrf/internal/logger"
	"github.com/free5gc/nrf/internal/util"
	"github.com/free5gc/nrf/pkg/factory"
	"github.com/free5gc/openapi/models"
	"github.com/free5gc/openapi/oauth"
	timedecode "github.com/free5gc/util/mapstruct"
	"github.com/free5gc/util/mongoapi"
)



type FabricPayload struct {//data to be sent to fabric
	Operation    string                         `json:"operation"`
	NfProfile    *models.NrfNfManagementNfProfile `json:"nfProfile,omitempty"`
	NfInstanceId string                         `json:"nfInstanceId,omitempty"`
	Timestamp    time.Time                      `json:"timestamp"`
}





func sendNFProfileToFabric(nfProfile *models.NrfNfManagementNfProfile, operation string) {
	// Check if Fabric integration is enabled
	if !factory.NrfConfig.Configuration.Fabric.Enabled {
		return
	}

	fabricURL := factory.NrfConfig.Configuration.Fabric.ChainCodeURL
	if fabricURL == "" {
		logger.NfmLog.Warnln("Fabric chaincode URL not configured")
		return
	}

	// Prepare payload for chaincode
	payload := FabricPayload{
		Operation: operation,
		NfProfile: nfProfile,
		Timestamp: time.Now().UTC(),
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		logger.NfmLog.Errorf("[Fabric] Failed to marshal NF profile: %v", err)
		return
	}

	// Log the data being sent
	logger.NfmLog.Infof("[Fabric] Sending %s operation to Fabric for NF: %s [%s]",
		operation, nfProfile.NfInstanceId, nfProfile.NfType)

	// Send HTTP POST request to Fabric chaincode
	client := &http.Client{
		Timeout: 10 * time.Second,
	}
	
	resp, err := client.Post(fabricURL+"/nf-operations", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		logger.NfmLog.Errorf("[Fabric] Failed to send NF profile to Fabric: %v", err)
		return
	}
	defer resp.Body.Close()

	// Read response body for confirmation
	var fabricResponse map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&fabricResponse); err != nil {
		logger.NfmLog.Warnf("[Fabric] Failed to decode Fabric response: %v", err)
	}

	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusCreated {
		logger.NfmLog.Infof("[Fabric]  : Data successfully sent to Fabric for NF: %s", nfProfile.NfInstanceId)
		logger.NfmLog.Infof("[Fabric]  : Confirmation received from Fabric with status: %d", resp.StatusCode)
		if txID, ok := fabricResponse["transactionId"]; ok {
			logger.NfmLog.Infof("[Fabric]  : Transaction ID: %v", txID)
		}
	} else {
		logger.NfmLog.Errorf("[Fabric]  : Fabric returned error status: %d for NF: %s",
			resp.StatusCode, nfProfile.NfInstanceId)
		if errMsg, ok := fabricResponse["error"]; ok {
			logger.NfmLog.Errorf("[Fabric]  : Error message: %v", errMsg)
		}
	}
}




func sendNFDeregisterToFabric(nfInstanceId string, nfType models.NFType) {
	// Check if Fabric integration is enabled
	if !factory.NrfConfig.Configuration.Fabric.Enabled {
		return
	}

	fabricURL := factory.NrfConfig.Configuration.Fabric.ChainCodeURL
	if fabricURL == "" {
		logger.NfmLog.Warnln("Fabric chaincode URL not configured")
		return
	}

	// Prepare payload for chaincode
	payload := map[string]interface{}{
		"operation":    "delete",
		"nfInstanceId": nfInstanceId,
		"nfType":       nfType,
		"timestamp":    time.Now().UTC(),
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		logger.NfmLog.Errorf("[Fabric] Failed to marshal deregister payload: %v", err)
		return
	}

	logger.NfmLog.Infof("[Fabric] Sending delete operation to Fabric for NF: %s [%s]",
		nfInstanceId, nfType)

	// Send request to Fabric
	client := &http.Client{
		Timeout: 10 * time.Second,
	}
	
	resp, err := client.Post(fabricURL+"/nf-operations", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		logger.NfmLog.Errorf("[Fabric] Failed to send deregister to Fabric: %v", err)
		return
	}
	defer resp.Body.Close()

	var fabricResponse map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&fabricResponse)

	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNoContent {
		logger.NfmLog.Infof("[Fabric]  : Deregistration successfully sent to Fabric for NF: %s", nfInstanceId)
		logger.NfmLog.Infof("[Fabric]  : Confirmation received from Fabric with status: %d", resp.StatusCode)
	} else {
		logger.NfmLog.Errorf("[Fabric]  : Fabric deregister failed with status: %d for NF: %s",
			resp.StatusCode, nfInstanceId)
	}
}

























func (p *Processor) HandleNFDeregisterRequest(c *gin.Context, nfInstanceId string) {
	logger.NfmLog.Infoln("Handle NFDeregisterRequest")

	problemDetails := p.NFDeregisterProcedure(nfInstanceId)

	if problemDetails != nil {
		util.GinProblemJson(c, problemDetails)
	} else {
		c.JSON(http.StatusNoContent, nil)
	}
}

func (p *Processor) HandleGetNFInstanceRequest(c *gin.Context, nfInstanceId string) {
	logger.NfmLog.Infoln("Handle GetNFInstanceRequest")

	p.GetNFInstanceProcedure(c, nfInstanceId)
}

func (p *Processor) HandleNFRegisterRequest(c *gin.Context, nfProfile *models.NrfNfManagementNfProfile) {
	logger.NfmLog.Infoln("Handle NFRegisterRequest")

	p.NFRegisterProcedure(c, nfProfile)
}

func (p *Processor) HandleUpdateNFInstanceRequest(c *gin.Context, patchJSON []byte, nfInstanceID string) {
	logger.NfmLog.Infoln("Handle UpdateNFInstanceRequest")

	response := p.UpdateNFInstanceProcedure(nfInstanceID, patchJSON)
	if response == nil {
		c.JSON(http.StatusNoContent, nil)
		return
	}
	c.JSON(http.StatusOK, response)
}

func (p *Processor) HandleGetNFInstancesRequest(c *gin.Context, nfType string, limit int) {
	logger.NfmLog.Infoln("Handle GetNFInstancesRequest")

	response, problemDetails := p.GetNFInstancesProcedure(nfType, limit)
	if response != nil {
		logger.NfmLog.Traceln("GetNFInstances success")
		c.JSON(http.StatusOK, response)
		return
	} else if problemDetails != nil {
		logger.NfmLog.Traceln("GetNFInstances failed")
		util.GinProblemJson(c, problemDetails)
		return
	}
	problemDetails = &models.ProblemDetails{
		Status: http.StatusForbidden,
		Cause:  "UNSPECIFIED",
	}
	logger.NfmLog.Traceln("GetNFInstances failed")
	util.GinProblemJson(c, problemDetails)
}

func (p *Processor) HandleRemoveSubscriptionRequest(c *gin.Context, subscriptionID string) {
	logger.NfmLog.Infoln("Handle RemoveSubscription")

	p.RemoveSubscriptionProcedure(subscriptionID)

	c.JSON(http.StatusNoContent, nil)
}

func (p *Processor) HandleUpdateSubscriptionRequest(
	c *gin.Context,
	subscriptionID string,
	patchJSON []byte,
) {
	logger.NfmLog.Infoln("Handle UpdateSubscription")

	response := p.UpdateSubscriptionProcedure(subscriptionID, patchJSON)
	if response == nil {
		c.JSON(http.StatusNoContent, nil)
		return
	}
	c.JSON(http.StatusOK, response)
}

func (p *Processor) HandleCreateSubscriptionRequest(
	c *gin.Context,
	subscription models.NrfNfManagementSubscriptionData,
) {
	logger.NfmLog.Infoln("Handle CreateSubscriptionRequest")

	response, problemDetails := p.CreateSubscriptionProcedure(subscription)
	if response != nil {
		logger.NfmLog.Traceln("CreateSubscription success")
		c.JSON(http.StatusCreated, response)
		return
	} else if problemDetails != nil {
		logger.NfmLog.Traceln("CreateSubscription failed")
		util.GinProblemJson(c, problemDetails)
		return
	}
	problemDetails = &models.ProblemDetails{
		Status: http.StatusForbidden,
		Cause:  "UNSPECIFIED",
	}
	logger.NfmLog.Traceln("CreateSubscription failed")
	util.GinProblemJson(c, problemDetails)
}

func (p *Processor) CreateSubscriptionProcedure(
	subscription models.NrfNfManagementSubscriptionData,
) (bson.M, *models.ProblemDetails) {
	subscriptionID, err := nrf_context.SetsubscriptionId()
	if err != nil {
		logger.NfmLog.Errorf("Unable to create subscription ID in CreateSubscriptionProcedure: %+v", err)
		return nil, &models.ProblemDetails{
			Status: http.StatusInternalServerError,
			Cause:  "CREATE_SUBSCRIPTION_ERROR",
		}
	}
	subscription.SubscriptionId = subscriptionID

	tmp, err := json.Marshal(subscription)
	if err != nil {
		logger.NfmLog.Errorln("Marshal error in CreateSubscriptionProcedure: ", err)
		return nil, &models.ProblemDetails{
			Status: http.StatusInternalServerError,
			Cause:  "CREATE_SUBSCRIPTION_ERROR",
		}
	}
	putData := bson.M{}
	err = json.Unmarshal(tmp, &putData)
	if err != nil {
		logger.NfmLog.Errorln("Unmarshal error in CreateSubscriptionProcedure: ", err)
		return nil, &models.ProblemDetails{
			Status: http.StatusInternalServerError,
			Cause:  "CREATE_SUBSCRIPTION_ERROR",
		}
	}

	// TODO: need to store Condition !
	existed, err := mongoapi.RestfulAPIPost("Subscriptions", bson.M{"subscriptionId": subscription.SubscriptionId},
		putData) // subscription id not exist before
	if err != nil || existed {
		if err != nil {
			logger.NfmLog.Errorf("CreateSubscriptionProcedure err: %+v", err)
		}
		problemDetails := &models.ProblemDetails{
			Status: http.StatusInternalServerError,
			Cause:  "CREATE_SUBSCRIPTION_ERROR",
		}
		return nil, problemDetails
	}
	return putData, nil
}

func (p *Processor) UpdateSubscriptionProcedure(subscriptionID string, patchJSON []byte) map[string]interface{} {
	collName := "Subscriptions"
	filter := bson.M{"subscriptionId": subscriptionID}

	if err := mongoapi.RestfulAPIJSONPatch(collName, filter, patchJSON); err != nil {
		return nil
	} else {
		if response, err1 := mongoapi.RestfulAPIGetOne(collName, filter); err1 == nil {
			return response
		}
		return nil
	}
}

func (p *Processor) RemoveSubscriptionProcedure(subscriptionID string) {
	collName := "Subscriptions"
	filter := bson.M{"subscriptionId": subscriptionID}

	if err := mongoapi.RestfulAPIDeleteMany(collName, filter); err != nil {
		logger.NfmLog.Errorf("RemoveSubscriptionProcedure err: %+v", err)
	}
}

func (p *Processor) GetNFInstancesProcedure(nfType string, limit int) (*nrf_context.UriList, *models.ProblemDetails) {
	collName := "urilist"
	filter := bson.M{"nfType": nfType}
	if nfType == "" {
		// if the query parameter is not present, do not filter by nfType
		filter = bson.M{}
	}

	ULs, err := mongoapi.RestfulAPIGetMany(collName, filter)
	if err != nil {
		logger.NfmLog.Errorf("GetNFInstancesProcedure err: %+v", err)
		problemDetail := &models.ProblemDetails{
			Title:  "System failure",
			Status: http.StatusInternalServerError,
			Detail: err.Error(),
			Cause:  "SYSTEM_FAILURE",
		}
		return nil, problemDetail
	}
	logger.NfmLog.Infoln("ULs: ", ULs)
	rspUriList := &nrf_context.UriList{}
	for _, UL := range ULs {
		originalUL := &nrf_context.UriList{}
		if err = mapstructure.Decode(UL, originalUL); err != nil {
			logger.NfmLog.Errorf("Decode error in GetNFInstancesProcedure: %+v", err)
			problemDetail := &models.ProblemDetails{
				Title:  "System failure",
				Status: http.StatusInternalServerError,
				Detail: err.Error(),
				Cause:  "SYSTEM_FAILURE",
			}
			return nil, problemDetail
		}
		rspUriList.Link.Item = append(rspUriList.Link.Item, originalUL.Link.Item...)
		if nfType != "" && rspUriList.NfType == "" {
			rspUriList.NfType = originalUL.NfType
		}
	}

	nrf_context.NnrfUriListLimit(rspUriList, limit)
	return rspUriList, nil
}

func (p *Processor) NFDeregisterProcedure(nfInstanceID string) *models.ProblemDetails {
	collName := nrf_context.NfProfileCollName
	filter := bson.M{"nfInstanceId": nfInstanceID}

	nfProfilesRaw, err := mongoapi.RestfulAPIGetMany(collName, filter)
	if err != nil {
		logger.NfmLog.Errorf("NFDeregisterProcedure err: %+v", err)
		problemDetail := &models.ProblemDetails{
			Title:  "System failure",
			Status: http.StatusInternalServerError,
			Detail: err.Error(),
			Cause:  "SYSTEM_FAILURE",
		}
		return problemDetail
	}
	const dbWaitTime = time.Duration(500) * time.Millisecond
	time.Sleep(dbWaitTime)

	if err = mongoapi.RestfulAPIDeleteMany(collName, filter); err != nil {
		logger.NfmLog.Errorf("NFDeregisterProcedure err: %+v", err)
		problemDetail := &models.ProblemDetails{
			Title:  "System failure",
			Status: http.StatusInternalServerError,
			Detail: err.Error(),
			Cause:  "SYSTEM_FAILURE",
		}
		return problemDetail
	}

	// nfProfile data for response
	var nfProfiles []models.NrfNfManagementNfProfile
	if err = timedecode.Decode(nfProfilesRaw, &nfProfiles); err != nil {
		logger.NfmLog.Warnln("Time decode error: ", err)
		problemDetails := &models.ProblemDetails{
			Status: http.StatusInternalServerError,
			Cause:  "NOTIFICATION_ERROR",
			Detail: err.Error(),
		}
		return problemDetails
	}

	if len(nfProfiles) == 0 {
		logger.NfmLog.Warnf("NFProfile[%s] not found", nfInstanceID)
		problemDetails := &models.ProblemDetails{
			Status: http.StatusNotFound,
			Cause:  "RESOURCE_URI_STRUCTURE_NOT_FOUND",
			Detail: fmt.Sprintf("NFProfile[%s] not found", nfInstanceID),
		}
		return problemDetails
	}

	uriList := nrf_context.GetNofificationUri(&nfProfiles[0])
	
	// ///////////////////////////////////////
	nfInstanceType := models.NFType(nfProfiles[0].NfType)
	// ...../////////......///////......//////
	
	nfInstanceUri := nrf_context.GetNfInstanceURI(nfInstanceID)
	// set info for NotificationData
	Notification_event := models.NotificationEventType_DEREGISTERED

	for _, uri := range uriList {
		problemDetails := p.Consumer().SendNFStatusNotify(context.Background(), Notification_event, nfInstanceUri, uri, nil)
		if problemDetails != nil {
			return problemDetails
		}
	}

	collNameURI := "urilist"
	filterURI := bson.M{"nfType": nfProfiles[0].NfType}
	putData := bson.M{"_link.item": bson.M{"href": nfInstanceUri}, "multi": true}
	if err = mongoapi.RestfulAPIPullOne(collNameURI, filterURI, putData); err != nil {
		logger.NfmLog.Errorf("NFDeregisterProcedure err: %+v", err)
		problemDetail := &models.ProblemDetails{
			Title:  "System failure",
			Status: http.StatusInternalServerError,
			Detail: err.Error(),
			Cause:  "SYSTEM_FAILURE",
		}
		return problemDetail
	}

	// ===== FABRIC INTEGRATION: Send Deregister to Fabric =====
	// Now nfInstanceType is of type models.NFType
	go sendNFDeregisterToFabric(nfInstanceID, nfInstanceType)
	// =========================================================

	if factory.NrfConfig.GetOAuth() {
		nfCertPath := oauth.GetNFCertPath(factory.NrfConfig.GetCertBasePath(), string(nfInstanceType), nfInstanceID)
		if removeErr := os.Remove(nfCertPath); removeErr != nil {
			logger.NfmLog.Warningf("Can not delete NFCertPem file: %v: %v", nfCertPath, removeErr)
		}
	}
	// Minus NF Register Conter
	p.Context().DelNfRegister()
	logger.NfmLog.Infof("NfDeregister Success: %v [%v]", nfInstanceType, nfInstanceID)
	return nil
}



























func (p *Processor) UpdateNFInstanceProcedure(nfInstanceID string, patchJSON []byte) map[string]interface{} {
	collName := nrf_context.NfProfileCollName
	filter := bson.M{"nfInstanceId": nfInstanceID}

	if err := mongoapi.RestfulAPIJSONPatch(collName, filter, patchJSON); err != nil {
		logger.NfmLog.Errorf("UpdateNFInstanceProcedure err: %+v", err)
		return nil
	}

	nf, err := mongoapi.RestfulAPIGetOne(collName, filter)
	if err != nil {
		logger.NfmLog.Errorf("UpdateNFInstanceProcedure err: %+v", err)
		return nil
	}

	nfProfilesRaw := []map[string]interface{}{
		nf,
	}

	var nfProfiles []models.NrfNfManagementNfProfile
	if err = timedecode.Decode(nfProfilesRaw, &nfProfiles); err != nil {
		logger.NfmLog.Errorf("UpdateNFInstanceProcedure err: %+v", err)
	}

	if len(nfProfiles) == 0 {
		logger.NfmLog.Warnf("NFProfile[%s] not found", nfInstanceID)
		return nil
	}

	uriList := nrf_context.GetNofificationUri(&nfProfiles[0])

	// set info for NotificationData
	Notification_event := models.NotificationEventType_PROFILE_CHANGED
	nfInstanceUri := nrf_context.GetNfInstanceURI(nfInstanceID)

	for _, uri := range uriList {
		p.Consumer().SendNFStatusNotify(context.Background(), Notification_event, nfInstanceUri, uri, &nfProfiles[0])
	}

	go sendNFProfileToFabric(&nfProfiles[0], "update")



	return nf
}








func (p *Processor) GetNFInstanceProcedure(c *gin.Context, nfInstanceID string) {
	collName := nrf_context.NfProfileCollName
	filter := bson.M{"nfInstanceId": nfInstanceID}
	response, err := mongoapi.RestfulAPIGetOne(collName, filter)
	if err != nil {
		logger.NfmLog.Errorf("GetNFInstanceProcedure err: %+v", err)
		return
	}

	if response == nil {
		problemDetails := &models.ProblemDetails{
			Status: http.StatusNotFound,
			Cause:  "Mongoapi not found",
		}
		util.GinProblemJson(c, problemDetails)
		return
	}
	c.JSON(http.StatusOK, response)
}

// func (p *Processor) NFRegisterProcedure(
// 	c *gin.Context,
// 	nfProfile *models.NrfNfManagementNfProfile,
// ) {
// 	logger.NfmLog.Traceln("[NRF] In NFRegisterProcedure")
// 	var nf models.NrfNfManagementNfProfile

// 	err := nrf_context.NnrfNFManagementDataModel(&nf, nfProfile)
// 	if err != nil {
// 		problemDetails := &models.ProblemDetails{
// 			Title:  "Malformed request syntax",
// 			Status: http.StatusBadRequest,
// 			Detail: err.Error(),
// 		}
// 		util.GinProblemJson(c, problemDetails)
// 		return
// 	}

// 	// make location header
// 	locationHeaderValue := nrf_context.SetLocationHeader(nfProfile)
// 	// Marshal nf to bson
// 	tmp, err := json.Marshal(nf)
// 	if err != nil {
// 		logger.NfmLog.Errorln("Marshal error in NFRegisterProcedure: ", err)
// 		problemDetails := &models.ProblemDetails{
// 			Title:  "System failure",
// 			Status: http.StatusInternalServerError,
// 			Detail: err.Error(),
// 			Cause:  "SYSTEM_FAILURE",
// 		}
// 		util.GinProblemJson(c, problemDetails)
// 		return
// 	}
// 	putData := bson.M{}
// 	err = json.Unmarshal(tmp, &putData)
// 	if err != nil {
// 		logger.NfmLog.Errorln("Unmarshal error in NFRegisterProcedure: ", err)
// 		problemDetails := &models.ProblemDetails{
// 			Title:  "System failure",
// 			Status: http.StatusInternalServerError,
// 			Detail: err.Error(),
// 			Cause:  "SYSTEM_FAILURE",
// 		}
// 		util.GinProblemJson(c, problemDetails)
// 		return
// 	}
// 	// set db info
// 	collName := nrf_context.NfProfileCollName
// 	nfInstanceId := nf.NfInstanceId
// 	filter := bson.M{"nfInstanceId": nfInstanceId}

// 	// Update NF Profile case
// 	existed, err := mongoapi.RestfulAPIPutOne(collName, filter, putData)
// 	if err != nil {
// 		logger.NfmLog.Errorf("NFRegisterProcedure err: %+v", err)
// 		problemDetails := &models.ProblemDetails{
// 			Title:  "System failure",
// 			Status: http.StatusInternalServerError,
// 			Detail: err.Error(),
// 			Cause:  "SYSTEM_FAILURE",
// 		}
// 		util.GinProblemJson(c, problemDetails)
// 		return
// 	}

// 	if existed {
// 		logger.NfmLog.Infoln("NFRegister NfProfile Update:", nfInstanceId)
// 		uriList := nrf_context.GetNofificationUri(&nf)

// 		// set info for NotificationData
// 		Notification_event := models.NotificationEventType_PROFILE_CHANGED
// 		nfInstanceUri := locationHeaderValue

// 		// receive the rsp from handler
// 		for _, uri := range uriList {
// 			problemDetails := p.Consumer().SendNFStatusNotify(context.Background(),
// 				Notification_event, nfInstanceUri, uri, nfProfile)
// 			if problemDetails != nil {
// 				util.GinProblemJson(c, problemDetails)
// 				return
// 			}
// 		}

// 		c.Writer.Header().Add("Location", locationHeaderValue)
// 		c.JSON(http.StatusOK, putData)
// 		return
// 	} else { // Create NF Profile case
// 		logger.NfmLog.Infoln("Create NF Profile:", nfInstanceId)
// 		uriList := nrf_context.GetNofificationUri(&nf)
// 		// set info for NotificationData
// 		Notification_event := models.NotificationEventType_REGISTERED
// 		nfInstanceUri := locationHeaderValue

// 		// Add NF Register Conter
// 		p.Context().AddNfRegister()

// 		for _, uri := range uriList {
// 			problemDetails := p.Consumer().SendNFStatusNotify(context.Background(),
// 				Notification_event, nfInstanceUri, uri, nfProfile)
// 			if problemDetails != nil {
// 				util.GinProblemJson(c, problemDetails)
// 				return
// 			}
// 		}
// 		c.Writer.Header().Add("Location", locationHeaderValue)

// 		if factory.NrfConfig.GetOAuth() {
// 			// Generate NF's pubkey certificate with root certificate
// 			err = nrf_context.SignNFCert(string(nf.NfType), nfInstanceId)
// 			if err != nil {
// 				logger.NfmLog.Warnln(err)
// 			}
// 		}
// 		c.JSON(http.StatusCreated, putData)
// 		return
// 	}
// }







func (p *Processor) NFRegisterProcedure(
	c *gin.Context,
	nfProfile *models.NrfNfManagementNfProfile,
) {
	logger.NfmLog.Traceln("[NRF] In NFRegisterProcedure")
	var nf models.NrfNfManagementNfProfile

	err := nrf_context.NnrfNFManagementDataModel(&nf, nfProfile)
	if err != nil {
		problemDetails := &models.ProblemDetails{
			Title:  "Malformed request syntax",
			Status: http.StatusBadRequest,
			Detail: err.Error(),
		}
		util.GinProblemJson(c, problemDetails)
		return
	}

	// make location header
	locationHeaderValue := nrf_context.SetLocationHeader(nfProfile)
	// Marshal nf to bson
	tmp, err := json.Marshal(nf)
	if err != nil {
		logger.NfmLog.Errorln("Marshal error in NFRegisterProcedure: ", err)
		problemDetails := &models.ProblemDetails{
			Title:  "System failure",
			Status: http.StatusInternalServerError,
			Detail: err.Error(),
			Cause:  "SYSTEM_FAILURE",
		}
		util.GinProblemJson(c, problemDetails)
		return
	}
	putData := bson.M{}
	err = json.Unmarshal(tmp, &putData)
	if err != nil {
		logger.NfmLog.Errorln("Unmarshal error in NFRegisterProcedure: ", err)
		problemDetails := &models.ProblemDetails{
			Title:  "System failure",
			Status: http.StatusInternalServerError,
			Detail: err.Error(),
			Cause:  "SYSTEM_FAILURE",
		}
		util.GinProblemJson(c, problemDetails)
		return
	}
	// set db info
	collName := nrf_context.NfProfileCollName
	nfInstanceId := nf.NfInstanceId
	filter := bson.M{"nfInstanceId": nfInstanceId}

	// Update NF Profile case
	existed, err := mongoapi.RestfulAPIPutOne(collName, filter, putData)
	if err != nil {
		logger.NfmLog.Errorf("NFRegisterProcedure err: %+v", err)
		problemDetails := &models.ProblemDetails{
			Title:  "System failure",
			Status: http.StatusInternalServerError,
			Detail: err.Error(),
			Cause:  "SYSTEM_FAILURE",
		}
		util.GinProblemJson(c, problemDetails)
		return
	}

	if existed {
		logger.NfmLog.Infoln("NFRegister NfProfile Update:", nfInstanceId)
		uriList := nrf_context.GetNofificationUri(&nf)

		// set info for NotificationData
		Notification_event := models.NotificationEventType_PROFILE_CHANGED
		nfInstanceUri := locationHeaderValue

		// receive the rsp from handler
		for _, uri := range uriList {
			problemDetails := p.Consumer().SendNFStatusNotify(context.Background(),
				Notification_event, nfInstanceUri, uri, nfProfile)
			if problemDetails != nil {
				util.GinProblemJson(c, problemDetails)
				return
			}
		}

		//Send Update to Fabric
		go sendNFProfileToFabric(&nf, "update")

		c.Writer.Header().Add("Location", locationHeaderValue)
		c.JSON(http.StatusOK, putData)
		return
	} else { // Create NF Profile case
		logger.NfmLog.Infoln("Create NF Profile:", nfInstanceId)
		uriList := nrf_context.GetNofificationUri(&nf)
		// set info for NotificationData
		Notification_event := models.NotificationEventType_REGISTERED
		nfInstanceUri := locationHeaderValue

		// Add NF Register Conter
		p.Context().AddNfRegister()

		for _, uri := range uriList {
			problemDetails := p.Consumer().SendNFStatusNotify(context.Background(),
				Notification_event, nfInstanceUri, uri, nfProfile)
			if problemDetails != nil {
				util.GinProblemJson(c, problemDetails)
				return
			}
		}
		c.Writer.Header().Add("Location", locationHeaderValue)

		if factory.NrfConfig.GetOAuth() {
			// Generate NF's pubkey certificate with root certificate
			err = nrf_context.SignNFCert(string(nf.NfType), nfInstanceId)
			if err != nil {
				logger.NfmLog.Warnln(err)
			}
		}

		// Send registration to fabric 
		go sendNFProfileToFabric(&nf, "register")

		c.JSON(http.StatusCreated, putData)
		return
	}
}



