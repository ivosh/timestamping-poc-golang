package tsp

import (
	"encoding/asn1"
	"slices"
)

// PolicyValidator holds the set of accepted TSA policy OIDs and a default OID
// used when the client does not request a specific policy.
type PolicyValidator struct {
	defaultOID asn1.ObjectIdentifier
	allowed    []asn1.ObjectIdentifier
}

// NewPolicyValidator constructs a validator. The default OID must be included
// in the allowed list (it is added automatically if missing).
func NewPolicyValidator(defaultOID asn1.ObjectIdentifier, allowed []asn1.ObjectIdentifier) *PolicyValidator {
	found := slices.ContainsFunc(allowed, func(o asn1.ObjectIdentifier) bool {
		return o.Equal(defaultOID)
	})
	if !found {
		allowed = append(allowed, defaultOID)
	}
	return &PolicyValidator{defaultOID: defaultOID, allowed: allowed}
}

// Validate returns nil if the requested OID is acceptable, or ErrUnacceptedPolicy.
// A nil OID (client did not specify a policy) is always accepted.
func (v *PolicyValidator) Validate(requested asn1.ObjectIdentifier) error {
	if len(requested) == 0 {
		return nil
	}
	for _, a := range v.allowed {
		if a.Equal(requested) {
			return nil
		}
	}
	return ErrUnacceptedPolicy
}

// Resolve returns the OID to embed in the token: the requested OID if supplied
// and valid, otherwise the default.
func (v *PolicyValidator) Resolve(requested asn1.ObjectIdentifier) asn1.ObjectIdentifier {
	if len(requested) != 0 {
		return requested
	}
	return v.defaultOID
}
