package tsp

import (
	"errors"
	"math/big"
	"math/rand"
	"runtime"
	"sync/atomic"
	"time"
)

const (
	snowflakeEpochMs  = int64(1738368000000) // 2026-02-01T00:00:00Z in ms
	snowflakeTickMs   = int64(10)
	snowflakeMaxDrift = int64(100) // ms — reject if clock is behind by more than this
)

// Snowflake generates monotonically increasing, globally-unique serial numbers
// suitable for RFC 3161 timestamp tokens.
//
// Bit layout of the returned int64 value:
//
//	bits 63..24  tick  (40 bits — ms since epoch / 10)
//	bits 23.. 8  instanceID  (16 bits)
//	bits  7.. 0  sequence    (8 bits — up to 256/tick)
type Snowflake struct {
	instanceID int64
	state      atomic.Int64 // (tick << 8) | seq
}

func NewSnowflake() *Snowflake {
	instID := rand.Int63n(0xFFFF + 1)
	return &Snowflake{instanceID: instID}
}

func (s *Snowflake) currentTick() int64 {
	return (time.Now().UnixMilli() - snowflakeEpochMs) / snowflakeTickMs
}

// Generate returns a new unique, monotonically-increasing serial number as a
// *big.Int. It is safe for concurrent use.
func (s *Snowflake) Generate() *big.Int {
	for {
		snapshot := s.state.Load()
		storedTick := snapshot >> 8
		storedSeq := snapshot & 0xFF

		currentTick := s.currentTick()

		if currentTick < storedTick {
			driftMs := (storedTick - currentTick) * snowflakeTickMs
			if driftMs > snowflakeMaxDrift {
				panic(errors.New("snowflake: clock drift exceeds maximum allowed"))
			}
			for s.currentTick() < storedTick {
				runtime.Gosched()
			}
			continue
		}

		var newTick, newSeq int64
		if currentTick > storedTick {
			newTick = currentTick
			newSeq = 0
		} else {
			if storedSeq >= 255 {
				for s.currentTick() <= storedTick {
					runtime.Gosched()
				}
				continue
			}
			newTick = storedTick
			newSeq = storedSeq + 1
		}

		newSnapshot := (newTick << 8) | newSeq
		if s.state.CompareAndSwap(snapshot, newSnapshot) {
			value := (newTick << 24) | (s.instanceID << 8) | newSeq
			return big.NewInt(value)
		}
	}
}
