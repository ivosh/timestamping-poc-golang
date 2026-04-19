package tsp

import (
	"math/big"
	"sync"
	"time"
)

// NonceCache rejects duplicate nonces within a sliding time window.
// The purpose is to prevent an attacker from replaying a valid
// TimeStampReq/TimeStampResp pair within the same time window.
type NonceCache struct {
	mu      sync.Mutex
	entries map[string]time.Time // nonce string → expiry
	ttl     time.Duration
}

func NewNonceCache(ttl time.Duration) *NonceCache {
	nc := &NonceCache{
		entries: make(map[string]time.Time),
		ttl:     ttl,
	}
	go nc.cleanup()
	return nc
}

// CheckAndStore returns true if the nonce is acceptable (first occurrence or
// nil), or false if it has been seen before within the TTL window.
func (nc *NonceCache) CheckAndStore(nonce *big.Int) bool {
	if nonce == nil {
		return true
	}
	key := nonce.String()
	now := time.Now()
	nc.mu.Lock()
	defer nc.mu.Unlock()
	if exp, exists := nc.entries[key]; exists && now.Before(exp) {
		return false
	}
	nc.entries[key] = now.Add(nc.ttl)
	return true
}

// cleanup runs as a background goroutine, removing expired entries every ttl/2.
func (nc *NonceCache) cleanup() {
	ticker := time.NewTicker(nc.ttl / 2)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now()
		nc.mu.Lock()
		for k, exp := range nc.entries {
			if now.After(exp) {
				delete(nc.entries, k)
			}
		}
		nc.mu.Unlock()
	}
}
