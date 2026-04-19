package tsp

import (
	"crypto"
	"encoding/asn1"
	"math/big"
	"sync/atomic"
	"time"

	"github.com/czertainly/signer-poc/internal/tsacrypto"
	"github.com/digitorus/timestamp"
)

var serialCounter atomic.Int64

type Service struct {
	id *tsacrypto.TSAIdentity
}

func NewService(id *tsacrypto.TSAIdentity) *Service {
	return &Service{id: id}
}

func (s *Service) Sign(req *timestamp.Request) ([]byte, error) {
	ts := timestamp.Timestamp{
		HashAlgorithm:     req.HashAlgorithm,
		HashedMessage:     req.HashedMessage,
		Time:              time.Now().UTC().Truncate(time.Second),
		Policy:            asn1.ObjectIdentifier{1, 2, 3, 4, 1},
		Nonce:             req.Nonce,
		SerialNumber:      big.NewInt(serialCounter.Add(1)),
		AddTSACertificate: true,
	}
	return ts.CreateResponseWithOpts(s.id.Certificate, s.id.PrivateKey, crypto.SHA384)
}
