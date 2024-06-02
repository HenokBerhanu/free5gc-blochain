// package consumer

// import (
// 	"context"
// 	"encoding/base64"
// 	"fmt"
// 	"net/url"
// 	"strconv"

// 	"github.com/antihax/optional"

// 	amf_context "github.com/free5gc/amf/internal/context"
// 	"github.com/free5gc/amf/internal/logger"
// 	"github.com/free5gc/nas/nasType"
// 	"github.com/free5gc/openapi"
// 	"github.com/free5gc/openapi/Nausf_UEAuthentication"
// 	"github.com/free5gc/openapi/models"
// )

// func SendUEAuthenticationAuthenticateRequest(ue *amf_context.AmfUe,
// 	resynchronizationInfo *models.ResynchronizationInfo,
// ) (*models.UeAuthenticationCtx, *models.ProblemDetails, error) {
// 	configuration := Nausf_UEAuthentication.NewConfiguration()
// 	configuration.SetBasePath(ue.AusfUri)

// 	client := Nausf_UEAuthentication.NewAPIClient(configuration)

// 	amfSelf := amf_context.GetSelf()
// 	servedGuami := amfSelf.ServedGuamiList[0]

// 	var authInfo models.AuthenticationInfo
// 	authInfo.SupiOrSuci = ue.Suci
// 	if mnc, err := strconv.Atoi(servedGuami.PlmnId.Mnc); err != nil {
// 		return nil, nil, err
// 	} else {
// 		authInfo.ServingNetworkName = fmt.Sprintf("5G:mnc%03d.mcc%s.3gppnetwork.org", mnc, servedGuami.PlmnId.Mcc)
// 	}
// 	if resynchronizationInfo != nil {
// 		authInfo.ResynchronizationInfo = resynchronizationInfo
// 	}

// 	ueAuthenticationCtx, httpResponse, err := client.DefaultApi.UeAuthenticationsPost(context.Background(), authInfo)
// 	defer func() {
// 		if httpResponse != nil {
// 			if rspCloseErr := httpResponse.Body.Close(); rspCloseErr != nil {
// 				logger.ConsumerLog.Errorf("UeAuthenticationsPost response body cannot close: %+v",
// 					rspCloseErr)
// 			}
// 		}
// 	}()
// 	if err == nil {
// 		return &ueAuthenticationCtx, nil, nil
// 	} else if httpResponse != nil {
// 		if httpResponse.Status != err.Error() {
// 			return nil, nil, err
// 		}
// 		problem := err.(openapi.GenericOpenAPIError).Model().(models.ProblemDetails)
// 		return nil, &problem, nil
// 	} else {
// 		return nil, nil, openapi.ReportError("server no response")
// 	}
// }

// func SendAuth5gAkaConfirmRequest(ue *amf_context.AmfUe, resStar string) (
// 	*models.ConfirmationDataResponse, *models.ProblemDetails, error,
// ) {
// 	var ausfUri string
// 	if confirmUri, err := url.Parse(ue.AuthenticationCtx.Links["5g-aka"].Href); err != nil {
// 		return nil, nil, err
// 	} else {
// 		ausfUri = fmt.Sprintf("%s://%s", confirmUri.Scheme, confirmUri.Host)
// 	}

// 	configuration := Nausf_UEAuthentication.NewConfiguration()
// 	configuration.SetBasePath(ausfUri)
// 	client := Nausf_UEAuthentication.NewAPIClient(configuration)

// 	confirmData := &Nausf_UEAuthentication.UeAuthenticationsAuthCtxId5gAkaConfirmationPutParamOpts{
// 		ConfirmationData: optional.NewInterface(models.ConfirmationData{
// 			ResStar: resStar,
// 		}),
// 	}

// 	confirmResult, httpResponse, err := client.DefaultApi.UeAuthenticationsAuthCtxId5gAkaConfirmationPut(
// 		context.Background(), ue.Suci, confirmData)
// 	defer func() {
// 		if httpResponse != nil {
// 			if rspCloseErr := httpResponse.Body.Close(); rspCloseErr != nil {
// 				logger.ConsumerLog.Errorf("UeAuthenticationsAuthCtxId5gAkaConfirmationPut response body cannot close: %+v",
// 					rspCloseErr)
// 			}
// 		}
// 	}()
// 	if err == nil {
// 		return &confirmResult, nil, nil
// 	} else if httpResponse != nil {
// 		if httpResponse.Status != err.Error() {
// 			return nil, nil, err
// 		}
// 		switch httpResponse.StatusCode {
// 		case 400, 500:
// 			problem := err.(openapi.GenericOpenAPIError).Model().(models.ProblemDetails)
// 			return nil, &problem, nil
// 		}
// 		return nil, nil, nil
// 	} else {
// 		return nil, nil, openapi.ReportError("server no response")
// 	}
// }

// func SendEapAuthConfirmRequest(ue *amf_context.AmfUe, eapMsg nasType.EAPMessage) (
// 	response *models.EapSession, problemDetails *models.ProblemDetails, err1 error,
// ) {
// 	confirmUri, err := url.Parse(ue.AuthenticationCtx.Links["eap-session"].Href)
// 	if err != nil {
// 		logger.ConsumerLog.Errorf("url Parse failed: %+v", err)
// 	}
// 	ausfUri := fmt.Sprintf("%s://%s", confirmUri.Scheme, confirmUri.Host)

// 	configuration := Nausf_UEAuthentication.NewConfiguration()
// 	configuration.SetBasePath(ausfUri)
// 	client := Nausf_UEAuthentication.NewAPIClient(configuration)

// 	eapSessionReq := &Nausf_UEAuthentication.EapAuthMethodParamOpts{
// 		EapSession: optional.NewInterface(models.EapSession{
// 			EapPayload: base64.StdEncoding.EncodeToString(eapMsg.GetEAPMessage()),
// 		}),
// 	}

// 	eapSession, httpResponse, err := client.DefaultApi.EapAuthMethod(context.Background(), ue.Suci, eapSessionReq)
// 	defer func() {
// 		if httpResponse != nil {
// 			if rspCloseErr := httpResponse.Body.Close(); rspCloseErr != nil {
// 				logger.ConsumerLog.Errorf("EapAuthMethod response body cannot close: %+v",
// 					rspCloseErr)
// 			}
// 		}
// 	}()
// 	if err == nil {
// 		response = &eapSession
// 	} else if httpResponse != nil {
// 		if httpResponse.Status != err.Error() {
// 			err1 = err
// 			return
// 		}
// 		switch httpResponse.StatusCode {
// 		case 400, 500:
// 			problem := err.(openapi.GenericOpenAPIError).Model().(models.ProblemDetails)
// 			problemDetails = &problem
// 		}
// 	} else {
// 		err1 = openapi.ReportError("server no response")
// 	}

// 	return response, problemDetails, err1
// }

package consumer

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net/url"
	"strconv"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"

	"github.com/antihax/optional"

	amf_context "github.com/free5gc/amf/internal/context"
	"github.com/free5gc/amf/internal/logger"
	"github.com/free5gc/nas/nasType"
	"github.com/free5gc/openapi"
	"github.com/free5gc/openapi/Nausf_UEAuthentication"
	"github.com/free5gc/openapi/models"

	guard "github.com/HenokBerhanu/free5gc-blochain/contracts/contracts/guard"
)

// Recover function takes the message and the signature and returns the address, which can be used for query
func Recover(message string, signature string) common.Address {
	data := []byte(message)
	hash := crypto.Keccak256Hash(data)
	sig, err := hexutil.Decode(signature)
	if err != nil {
		log.Fatal(err)
	}
	sigPublicKeyECDSA, err := crypto.SigToPub(hash.Bytes(), sig)
	if err != nil {
		log.Fatal(err)
	}
	addr_hex := crypto.PubkeyToAddress(*sigPublicKeyECDSA).Hex()
	return common.HexToAddress(addr_hex)
}

// // Recover function takes the message and the signature and returns the address, which can be used for query
// func Recover(message string, signature string) common.Address {
//     data := []byte(message)
//     hash := crypto.Keccak256Hash(data)
//     sig, err := hexutil.Decode(signature)
//     if err != nil {
//         log.Fatal(err)
//     }
//     sigPublicKeyECDSA, err := crypto.SigToPub(hash.Bytes(), sig)
//     if err != nil {
//         log.Fatal(err)
//     }
//     addrHex := crypto.PubkeyToAddress(*sigPublicKeyECDSA).Hex()
//     return common.HexToAddress(addrHex)
// }

func SendUEAuthenticationAuthenticateRequest(ue *amf_context.AmfUe,
	resynchronizationInfo *models.ResynchronizationInfo,
) (*models.UeAuthenticationCtx, *models.ProblemDetails, error) {
	ue.GmmLog.Infof("++++++BOHAN: Forward SUCI to AUSF")
	configuration := Nausf_UEAuthentication.NewConfiguration()
	configuration.SetBasePath(ue.AusfUri)

	client := Nausf_UEAuthentication.NewAPIClient(configuration)

	amfSelf := amf_context.GetSelf()
	servedGuami := amfSelf.ServedGuamiList[0]

	var authInfo models.AuthenticationInfo
	authInfo.SupiOrSuci = ue.Suci
	if mnc, err := strconv.Atoi(servedGuami.PlmnId.Mnc); err != nil {
		return nil, nil, err
	} else {
		authInfo.ServingNetworkName = fmt.Sprintf("5G:mnc%03d.mcc%s.3gppnetwork.org", mnc, servedGuami.PlmnId.Mcc)
	}
	if resynchronizationInfo != nil {
		authInfo.ResynchronizationInfo = resynchronizationInfo
	}

	//=======================================BOHAN ADDED CODE============================================

	goodsig := "0x294c2b14680b0ce97e18c6fab7032b3d9e7393bf4487422b0fab5c878f7e12ac41411314dedf6188f8328573607b57e2116d57b98d9a6041d204247a331f94871b"

	badsig := "0x23dc02544f733f8bb945cdb28fe282e3bdc090b14f4532745f86dc3e50f5f1082602cc0c6542e1fd7b803801a96713eae06f3578d9690d4f8f51c6cbd5b1493e1c"

	//=========== PAUL

	// Get the last 5 digits as a substring

	lastFiveDigitsStr := ue.Suci[len(ue.Suci)-5:]

	BlockchainSignature := badsig

	// Convert the substring to an integer

	_, err := strconv.Atoi(lastFiveDigitsStr)

	if err != nil {

		BlockchainSignature = goodsig

	}

	web3url := "http://172.18.0.2:8545"

	contractAddr := "0xeD506d152cf3dbAbe3f87B4468434793dEE60151"

	ue.GmmLog.Infof("++++++BOHAN: Connecting Blockchain")

	clientt, err := ethclient.Dial(web3url)

	if err != nil {

		log.Fatal(err)

	}

	ue.GmmLog.Infof("++++++BOHAN: Connecting Blockchain Success")

	address := common.HexToAddress(contractAddr)

	instance, err := guard.NewGuard(address, clientt)

	if err != nil {

		log.Fatal(err)

	}

	UDMstat, err := instance.GetUDMStatus(nil)

	if err != nil {

		log.Fatal(err)

	}

	ue.GmmLog.Infof("++++++BOHAN: UDM is under attack? %v", UDMstat)

	if UDMstat {

		// The UDM is under attack, requesting information from UE

		randChallenge := "hello"

		// SENDING UE this RAND

		sleepDuration := 50 * time.Millisecond

		time.Sleep(sleepDuration)

		// Receiving encrypted signature from UE

		// Decrypting signature

		SUCI := ""

		SEAFmessage := randChallenge + SUCI

		// decrypt and obtain the signature

		//BlockchainSignature := "0x1dff2866663a164cb9f9458c20bb16cee477e00a63d659c88d6ef697c05362b422953d1fef36c631640cf07504976e21bfcc662578e7ad8175562638f9135d7800"

		UEaddress := Recover(SEAFmessage, BlockchainSignature)

		salt, ban, err := instance.GetSaltStatus(nil, UEaddress)

		if err != nil {

			log.Fatal(err)

		}

		if salt.Cmp(big.NewInt(0)) == 0 {

			return nil, nil, errors.New("registration storm reject: invalid subscriber")

		}

		// check integrity with salt

		if ban {

			return nil, nil, errors.New("registration storm reject: malicious ue from udm")

		}

	}

	//=======================================BOHAN ENDED HERE=============================================

	ueAuthenticationCtx, httpResponse, err := client.DefaultApi.UeAuthenticationsPost(context.Background(), authInfo)
	defer func() {
		if httpResponse != nil {
			if rspCloseErr := httpResponse.Body.Close(); rspCloseErr != nil {
				logger.ConsumerLog.Errorf("UeAuthenticationsPost response body cannot close: %+v",
					rspCloseErr)
			}
		}
	}()
	if err == nil {
		return &ueAuthenticationCtx, nil, nil
	} else if httpResponse != nil {
		if httpResponse.Status != err.Error() {
			return nil, nil, err
		}
		problem := err.(openapi.GenericOpenAPIError).Model().(models.ProblemDetails)
		return nil, &problem, nil
	} else {
		return nil, nil, openapi.ReportError("server no response")
	}
}

func SendAuth5gAkaConfirmRequest(ue *amf_context.AmfUe, resStar string) (
	*models.ConfirmationDataResponse, *models.ProblemDetails, error,
) {
	var ausfUri string
	if confirmUri, err := url.Parse(ue.AuthenticationCtx.Links["5g-aka"].Href); err != nil {
		return nil, nil, err
	} else {
		ausfUri = fmt.Sprintf("%s://%s", confirmUri.Scheme, confirmUri.Host)
	}

	configuration := Nausf_UEAuthentication.NewConfiguration()
	configuration.SetBasePath(ausfUri)
	client := Nausf_UEAuthentication.NewAPIClient(configuration)

	confirmData := &Nausf_UEAuthentication.UeAuthenticationsAuthCtxId5gAkaConfirmationPutParamOpts{
		ConfirmationData: optional.NewInterface(models.ConfirmationData{
			ResStar: resStar,
		}),
	}

	confirmResult, httpResponse, err := client.DefaultApi.UeAuthenticationsAuthCtxId5gAkaConfirmationPut(
		context.Background(), ue.Suci, confirmData)
	defer func() {
		if httpResponse != nil {
			if rspCloseErr := httpResponse.Body.Close(); rspCloseErr != nil {
				logger.ConsumerLog.Errorf("UeAuthenticationsAuthCtxId5gAkaConfirmationPut response body cannot close: %+v",
					rspCloseErr)
			}
		}
	}()
	if err == nil {
		return &confirmResult, nil, nil
	} else if httpResponse != nil {
		if httpResponse.Status != err.Error() {
			return nil, nil, err
		}
		switch httpResponse.StatusCode {
		case 400, 500:
			problem := err.(openapi.GenericOpenAPIError).Model().(models.ProblemDetails)
			return nil, &problem, nil
		}
		return nil, nil, nil
	} else {
		return nil, nil, openapi.ReportError("server no response")
	}
}

func SendEapAuthConfirmRequest(ue *amf_context.AmfUe, eapMsg nasType.EAPMessage) (
	response *models.EapSession, problemDetails *models.ProblemDetails, err1 error,
) {
	confirmUri, err := url.Parse(ue.AuthenticationCtx.Links["eap-session"].Href)
	if err != nil {
		logger.ConsumerLog.Errorf("url Parse failed: %+v", err)
	}
	ausfUri := fmt.Sprintf("%s://%s", confirmUri.Scheme, confirmUri.Host)

	configuration := Nausf_UEAuthentication.NewConfiguration()
	configuration.SetBasePath(ausfUri)
	client := Nausf_UEAuthentication.NewAPIClient(configuration)

	eapSessionReq := &Nausf_UEAuthentication.EapAuthMethodParamOpts{
		EapSession: optional.NewInterface(models.EapSession{
			EapPayload: base64.StdEncoding.EncodeToString(eapMsg.GetEAPMessage()),
		}),
	}

	eapSession, httpResponse, err := client.DefaultApi.EapAuthMethod(context.Background(), ue.Suci, eapSessionReq)
	defer func() {
		if httpResponse != nil {
			if rspCloseErr := httpResponse.Body.Close(); rspCloseErr != nil {
				logger.ConsumerLog.Errorf("EapAuthMethod response body cannot close: %+v",
					rspCloseErr)
			}
		}
	}()
	if err == nil {
		response = &eapSession
	} else if httpResponse != nil {
		if httpResponse.Status != err.Error() {
			err1 = err
			return
		}
		switch httpResponse.StatusCode {
		case 400, 500:
			problem := err.(openapi.GenericOpenAPIError).Model().(models.ProblemDetails)
			problemDetails = &problem
		}
	} else {
		err1 = openapi.ReportError("server no response")
	}

	return response, problemDetails, err1
}
