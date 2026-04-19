package tsp

import (
	"encoding/asn1"
	"time"
)

// Config holds runtime configuration for the TSP service.
// All fields have sensible defaults if zero-valued.
type Config struct {
	// DefaultPolicyOID is the TSA policy embedded in tokens when the client
	// does not specify one.
	DefaultPolicyOID asn1.ObjectIdentifier

	// AllowedPolicyOIDs is the set of policy OIDs the server will accept.
	// The DefaultPolicyOID is always accepted regardless of this list.
	AllowedPolicyOIDs []asn1.ObjectIdentifier

	// NonceTTL is the replay-detection window. Default: 5 minutes.
	NonceTTL time.Duration
}

// DefaultConfig returns production-oriented defaults.
func DefaultConfig() Config {
	defaultOID := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1}
	return Config{
		DefaultPolicyOID:  defaultOID,
		AllowedPolicyOIDs: []asn1.ObjectIdentifier{defaultOID},
		NonceTTL:          5 * time.Minute,
	}
}
