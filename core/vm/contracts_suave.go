package vm

import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/metrics"
	suave "github.com/ethereum/go-ethereum/suave/core"
	//"github.com/ethereum/go-ethereum/suave/cstore"
)

var (
	confStorePrecompileStoreMeter    = metrics.NewRegisteredMeter("suave/confstore/store", nil)
	confStorePrecompileRetrieveMeter = metrics.NewRegisteredMeter("suave/confstore/retrieve", nil)
)

var (
	isConfidentialAddress = common.HexToAddress("0x42010000")
)

/* General utility precompiles */

func (b *suaveRuntime) confidentialInputs() ([]byte, error) {
	return b.suaveContext.ConfidentialInputs, nil
}

/* Confidential store precompiles */

func (b *suaveRuntime) confidentialStore(bidId types.BidId, key string, data []byte) error {
	bid, err := b.suaveContext.Backend.ConfidentialStore.FetchBidById(bidId)
	if err != nil {
		return suave.ErrBidNotFound
	}

	log.Info("confStore", "bidId", bidId, "key", key)

	caller, err := checkIsPrecompileCallAllowed(b.suaveContext, confidentialStoreAddr, bid)
	if err != nil {
		return err
	}

	if metrics.Enabled {
		confStorePrecompileStoreMeter.Mark(int64(len(data)))
	}

	_, err = b.suaveContext.Backend.ConfidentialStore.Store(bidId, caller, key, data)
	if err != nil {
		return err
	}

	return nil
}

func (b *suaveRuntime) confidentialRetrieve(bidId types.BidId, key string) ([]byte, error) {
	bid, err := b.suaveContext.Backend.ConfidentialStore.FetchBidById(bidId)
	if err != nil {
		return nil, suave.ErrBidNotFound
	}

	caller, err := checkIsPrecompileCallAllowed(b.suaveContext, confidentialRetrieveAddr, bid)
	if err != nil {
		return nil, err
	}

	data, err := b.suaveContext.Backend.ConfidentialStore.Retrieve(bidId, caller, key)
	if err != nil {
		return []byte(err.Error()), err
	}

	if metrics.Enabled {
		confStorePrecompileRetrieveMeter.Mark(int64(len(data)))
	}

	return data, nil
}

/* Bid precompiles */

func (b *suaveRuntime) newBid(decryptionCondition uint64, allowedPeekers []common.Address, allowedStores []common.Address, BidType string) (types.Bid, error) {
	if b.suaveContext.ConfidentialComputeRequestTx == nil {
		panic("newBid: source transaction not present")
	}

	bid, err := b.suaveContext.Backend.ConfidentialStore.InitializeBid(types.Bid{
		Salt:                suave.RandomBidId(),
		DecryptionCondition: decryptionCondition,
		AllowedPeekers:      allowedPeekers,
		AllowedStores:       allowedStores,
		Version:             BidType, // TODO : make generic
	})
	if err != nil {
		return types.Bid{}, err
	}

	return bid, nil
}

func (b *suaveRuntime) fetchBids(targetBlock uint64, namespace string) ([]types.Bid, error) {
	bids1 := b.suaveContext.Backend.ConfidentialStore.FetchBidsByProtocolAndBlock(targetBlock, namespace)

	bids := make([]types.Bid, 0, len(bids1))
	for _, bid := range bids1 {
		bids = append(bids, bid.ToInnerBid())
	}

	return bids, nil
}

func mustParseAbi(data string) abi.ABI {
	inoutAbi, err := abi.JSON(strings.NewReader(data))
	if err != nil {
		panic(err.Error())
	}

	return inoutAbi
}

func mustParseMethodAbi(data string, method string) abi.Method {
	inoutAbi := mustParseAbi(data)
	return inoutAbi.Methods[method]
}

func formatPeekerError(format string, args ...any) ([]byte, error) {
	err := fmt.Errorf(format, args...)
	return []byte(err.Error()), err
}

type suaveRuntime struct {
	suaveContext *SuaveContext
}

var _ SuaveRuntime = &suaveRuntime{}

/* TEEs precompiles */

// genQuote generates a quote, which can be verified in a remote attestation flow.
// The implementation of genQuote will vary greatly depending on which framework/SDK is
// used to run suave-geth in SGX, or some other TEE.
//
// As a starting point we assume Gramine is used to run suave-geth in SGX, and moreover
// that the EPID scheme is used, as this what RAVE verifies right now.
//
// genQuote should take at least two inputs:
//
//   - spid: unique identifier that corresponds the API token to communicate with IAS
//   - reportData: user-specific data that will be included in the quote; typically a
//     public key that binds the producer of the quote to a signing key. This perhaps
//     could be the wallet address of the kettle (execution node address).
//
// TODO: Need to figure out how gramine "handles" the spid; perhaps it reads it from a
//
//	config file. Hence, the spid parameter may not be needed, but leaving it here
//	now as a reminder to handle.
//
// NOTE: This will only generate a quote, which then must be sent for verification to
//
//	Intel Attestation Service (IAS).
//func (b *suaveRuntime) genQuote(spid uint64, reportData uint64) ([]byte, error) {
//
//	kettleAddress, err := KettleAddressFromTransaction(b.suaveContext.ConfidentialComputeRequestTx)
//	if err != nil {
//		return nil, err
//	}
//	f, err := os.OpenFile("/dev/attestation/user_report_data", os.O_RDWR|os.O_CREATE, 0755)
//	if err != nil {
//		return nil, err
//	}
//	if _, err := f.Write(kettleAddress); err != nil {
//		f.Close() // ignore error; Write error takes precedence
//		return nil, err
//	}
//	if err := f.Close(); err != nil {
//		return nil, err
//	}
//
//	quote, err := os.ReadFile("/dev/attestation/quote")
//	if err != nil {
//		return nil, err
//	}
//
//	return quote, nil
//}

// func (b *suaveRuntime) getAttestationVerificationReport(spid uint64, reportData uint64) (types.IASResponseBody, types.IASResponseHeaders, error) {
func (b *suaveRuntime) getAttestationVerificationReport() (types.IASResponse, error) {
	isvEnclaveQuoteBodyBase64 := "AgABAIAMAAANAA0AAAAAAEJhbJjVPJcSY5RHybDnAD8AAAAAAAAAAAAAAAAAAAAAFBQLB/+ADgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABQAAAAAAAAAfAAAAAAAAANCud0d0wgZKYN2SVB/MfLizrN6g15PzsnonpE2/cedfAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACD1xnnferKFHD2uvYqTXdDA8iZ22kCD5xw7h38CMfOngAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACk8eLeQq3kKFam57ApQyJ412rRw+hs7M1vL0ZTKGHCDAYVo7T4o+KD0jwJJV5RNg4AAAAAAAAAAAAAAAAAAAAA"

	//isvEnclaveQuoteBodyHex := "0x02000100800c00000d000d000000000042616c98d53c9712639447c9b0e7003f0000000000000000000000000000000014140b07ff800e000000000000000000000000000000000000000000000000000000000000000000000000000000000005000000000000001f00000000000000d0ae774774c2064a60dd92541fcc7cb8b3acdea0d793f3b27a27a44dbf71e75f000000000000000000000000000000000000000000000000000000000000000083d719e77deaca1470f6baf62a4d774303c899db69020f9c70ee1dfc08c7ce9e00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a4f1e2de42ade42856a6e7b029432278d76ad1c3e86ceccd6f2f46532861c20c0615a3b4f8a3e283d23c09255e51360e00000000000000000000000000000000"

	isvEnclaveQuoteBody, err := base64.StdEncoding.DecodeString(isvEnclaveQuoteBodyBase64)
	if err != nil {
		return types.IASResponse{}, err
	}

	iasResponseBody := types.IASResponseBody{
		Id:                    "142090828149453720542199954221331392599",
		Timestamp:             "2023-02-15T01:24:57.989456",
		Version:               "4",
		EpidPseudonym:         "EbrM6X6YCH3brjPXT23gVh/I2EG5sVfHYh+S54fb0rrAqVRTiRTOSfLsWSVTZc8wrazGG7oooGoMU7Gj5TEhsvsDIV4aYpvkSk/E3Tsb7CaGd+Iy1cEhLO4GPwdmwt/PXNQQ3htLdy3aNb7iQMrNbiFcdkVdV/tepdezMsSB8Go=",
		AdvisoryURL:           "https://security-center.intel.com",
		AdvisoryIDs:           "[\"INTEL-SA-00334\",\"INTEL-SA-00615\"]",
		IsvEnclaveQuoteStatus: "SW_HARDENING_NEEDED",
		IsvEnclaveQuoteBody:   isvEnclaveQuoteBody,
	}

	iasResponseHeaders := types.IASResponseHeaders{
		RequestID:                    "26fece5bc70f4b28a669b9c333c81b44",
		XIASReportSignature:          "TBXIDsg/XrvuIPG+DPH3wYUBeZiEQsugJxUuAbeUdFkvLNUm/IsrKAi5xq/q7WQgYar6m5L/ztx8+8FBi7mGVxnvhsnenwG8Fmz18s45KnDVzSAXM2yIF+qtEprZ/13YjrPswmsNIeBKugHAvzA+1eND6FEE6npuRVFJOBWDWIJb8zn71RFlgSGFdVUUeOScCuz7HrQMhjxEAcRNoqpWNOM1USkVs413x9xpPui5+kHzv52TnBxeOCwBDELaI3ZQwWo/9KxQQ3ayFbH8CPaaPcDD0EBPZD5C4weKcNtdYTBch+kK05loso4zPiSwiHsPAazlXWR4BVdf2WZIwAar4w==",
		XIASReportSigningCertificate: "-----BEGIN CERTIFICATE-----\nMIIEoTCCAwmgAwIBAgIJANEHdl0yo7CWMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNV\nBAYTAlVTMQswCQYDVQQIDAJDQTEUMBIGA1UEBwwLU2FudGEgQ2xhcmExGjAYBgNV\nBAoMEUludGVsIENvcnBvcmF0aW9uMTAwLgYDVQQDDCdJbnRlbCBTR1ggQXR0ZXN0\nYXRpb24gUmVwb3J0IFNpZ25pbmcgQ0EwHhcNMTYxMTIyMDkzNjU4WhcNMjYxMTIw\nMDkzNjU4WjB7MQswCQYDVQQGEwJVUzELMAkGA1UECAwCQ0ExFDASBgNVBAcMC1Nh\nbnRhIENsYXJhMRowGAYDVQQKDBFJbnRlbCBDb3Jwb3JhdGlvbjEtMCsGA1UEAwwk\nSW50ZWwgU0dYIEF0dGVzdGF0aW9uIFJlcG9ydCBTaWduaW5nMIIBIjANBgkqhkiG\n9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqXot4OZuphR8nudFrAFiaGxxkgma/Es/BA+t\nbeCTUR106AL1ENcWA4FX3K+E9BBL0/7X5rj5nIgX/R/1ubhkKWw9gfqPG3KeAtId\ncv/uTO1yXv50vqaPvE1CRChvzdS/ZEBqQ5oVvLTPZ3VEicQjlytKgN9cLnxbwtuv\nLUK7eyRPfJW/ksddOzP8VBBniolYnRCD2jrMRZ8nBM2ZWYwnXnwYeOAHV+W9tOhA\nImwRwKF/95yAsVwd21ryHMJBcGH70qLagZ7Ttyt++qO/6+KAXJuKwZqjRlEtSEz8\ngZQeFfVYgcwSfo96oSMAzVr7V0L6HSDLRnpb6xxmbPdqNol4tQIDAQABo4GkMIGh\nMB8GA1UdIwQYMBaAFHhDe3amfrzQr35CN+s1fDuHAVE8MA4GA1UdDwEB/wQEAwIG\nwDAMBgNVHRMBAf8EAjAAMGAGA1UdHwRZMFcwVaBToFGGT2h0dHA6Ly90cnVzdGVk\nc2VydmljZXMuaW50ZWwuY29tL2NvbnRlbnQvQ1JML1NHWC9BdHRlc3RhdGlvblJl\ncG9ydFNpZ25pbmdDQS5jcmwwDQYJKoZIhvcNAQELBQADggGBAGcIthtcK9IVRz4r\nRq+ZKE+7k50/OxUsmW8aavOzKb0iCx07YQ9rzi5nU73tME2yGRLzhSViFs/LpFa9\nlpQL6JL1aQwmDR74TxYGBAIi5f4I5TJoCCEqRHz91kpG6Uvyn2tLmnIdJbPE4vYv\nWLrtXXfFBSSPD4Afn7+3/XUggAlc7oCTizOfbbtOFlYA4g5KcYgS1J2ZAeMQqbUd\nZseZCcaZZZn65tdqee8UXZlDvx0+NdO0LR+5pFy+juM0wWbu59MvzcmTXbjsi7HY\n6zd53Yq5K244fwFHRQ8eOB0IWB+4PfM7FeAApZvlfqlKOlLcZL2uyVmzRkyR5yW7\n2uo9mehX44CiPJ2fse9Y6eQtcfEhMPkmHXI01sN+KwPbpA39+xOsStjhP9N1Y1a2\ntQAVo+yVgLgV2Hws73Fc0o3wC78qPEA+v2aRs/Be3ZFDgDyghc/1fgU+7C+P6kbq\nd4poyb6IW8KCJbxfMJvkordNOgOUUxndPHEi/tb/U7uLjLOgPA==\n-----END CERTIFICATE-----\n",
		Date:                         "Wed, 13 Dec 2023 04:30:44 GMT",
	}

	iasResponse := types.IASResponse{
		Body:    iasResponseBody,
		Headers: iasResponseHeaders,
	}
	//return iasResponseBody, iasResponseHeader, nil
	return iasResponse, nil
}
