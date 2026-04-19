package tsp

import (
	"crypto"
	"crypto/x509"
	"errors"
	"time"

	"github.com/digitorus/timestamp"
	"github.com/examle.com/timestamping-poc-golang/internal/tsacrypto"
)

var (
	ErrDuplicateNonce   = errors.New("duplicate nonce within replay window")
	ErrUnacceptedPolicy = errors.New("requested policy is not accepted")
	ErrTimeNotAvailable = errors.New("time quality check failed")
)

type Service struct {
	chain      *tsacrypto.TSAChain
	tq         *TimeQualityMonitor
	nonceCache *NonceCache
	snowflake  *Snowflake
	policy     *PolicyValidator
}

func NewService(chain *tsacrypto.TSAChain, cfg Config) *Service {
	return &Service{
		chain:      chain,
		tq:         NewTimeQualityMonitor(),
		nonceCache: NewNonceCache(cfg.NonceTTL),
		snowflake:  NewSnowflake(),
		policy:     NewPolicyValidator(cfg.DefaultPolicyOID, cfg.AllowedPolicyOIDs),
	}
}

func (s *Service) Sign(req *timestamp.Request) ([]byte, error) {
	if s.tq.Status() == TQFailed {
		return nil, ErrTimeNotAvailable
	}

	if !s.nonceCache.CheckAndStore(req.Nonce) {
		return nil, ErrDuplicateNonce
	}

	if err := s.policy.Validate(req.TSAPolicyOID); err != nil {
		return nil, err
	}

	ts := timestamp.Timestamp{
		HashAlgorithm:     req.HashAlgorithm,
		HashedMessage:     req.HashedMessage,
		Time:              time.Now().UTC().Truncate(time.Second),
		Policy:            s.policy.Resolve(req.TSAPolicyOID),
		Nonce:             req.Nonce,
		SerialNumber:      s.snowflake.Generate(),
		AddTSACertificate: true,
		Certificates:      []*x509.Certificate{s.chain.CACert},
	}
	return ts.CreateResponseWithOpts(s.chain.LeafCert, s.chain.LeafKey, crypto.SHA384)
}
