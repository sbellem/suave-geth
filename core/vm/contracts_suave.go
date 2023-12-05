package vm

import (
	"fmt"
	"os"
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
func (b *suaveRuntime) genQuote(spid uint64, reportData uint64) ([]byte, error) {

	kettleAddress, err := KettleAddressFromTransaction(b.suaveContext.ConfidentialComputeRequestTx)
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile("/dev/attestation/user_report_data", os.O_RDWR|os.O_CREATE, 0755)
	if err != nil {
		return nil, err
	}
	if _, err := f.Write(kettleAddress); err != nil {
		f.Close() // ignore error; Write error takes precedence
		return nil, err
	}
	if err := f.Close(); err != nil {
		return nil, err
	}

	quote, err := os.ReadFile("/dev/attestation/quote")
	if err != nil {
		return nil, err
	}

	return quote, nil
}
