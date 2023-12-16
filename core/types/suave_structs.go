// Code generated by suave/gen. DO NOT EDIT.
// Hash: a4de4954765f12ace1598fe2d9d004e3ccdae0014b678af8a068a7117a312d3e
package types

import "github.com/ethereum/go-ethereum/common"

type BidId [16]byte

// Structs

type Bid struct {
	Id                  BidId
	Salt                BidId
	DecryptionCondition uint64
	AllowedPeekers      []common.Address
	AllowedStores       []common.Address
	Version             string
}

type BuildBlockArgs struct {
	Slot           uint64
	ProposerPubkey []byte
	Parent         common.Hash
	Timestamp      uint64
	FeeRecipient   common.Address
	GasLimit       uint64
	Random         common.Hash
	Withdrawals    []*Withdrawal
	Extra          []byte
}

type IASResponse struct {
	Body    IASResponseBody
	Headers IASResponseHeaders
}

type IASResponseBody struct {
	Id                    string
	Timestamp             string
	Version               string
	IsvEnclaveQuoteStatus string
	IsvEnclaveQuoteBody   []byte
	EpidPseudonym         string
	AdvisoryURL           string
	AdvisoryIDs           string
}

type IASResponseHeaders struct {
	RequestID                    string
	XIASReportSignature          []byte
	XIASReportSigningCertificate []byte
	Date                         string
}

type Withdrawal struct {
	Index     uint64
	Validator uint64
	Address   common.Address
	Amount    uint64
}
