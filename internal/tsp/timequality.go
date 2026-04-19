package tsp

import (
	"log"
	"math/rand"
	"sync/atomic"
	"time"
)

type TimeQualityStatus int32

const (
	TQOk       TimeQualityStatus = 0
	TQDegraded TimeQualityStatus = 1
	TQFailed   TimeQualityStatus = 2
)

func (s TimeQualityStatus) String() string {
	switch s {
	case TQOk:
		return "OK"
	case TQDegraded:
		return "DEGRADED"
	case TQFailed:
		return "FAILED"
	default:
		return "UNKNOWN"
	}
}

// TimeQualityMonitor periodically simulates an NTP synchronisation check and
// exposes the result as an atomic value readable without any locking.
type TimeQualityMonitor struct {
	status atomic.Int32
}

// NewTimeQualityMonitor creates and starts a monitor with an initial status of
// TQOk. The background goroutine runs until the process exits.
func NewTimeQualityMonitor() *TimeQualityMonitor {
	m := &TimeQualityMonitor{}
	m.status.Store(int32(TQOk))
	go m.run()
	return m
}

// Status returns the current time-quality status without blocking.
func (m *TimeQualityMonitor) Status() TimeQualityStatus {
	return TimeQualityStatus(m.status.Load())
}

func (m *TimeQualityMonitor) run() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		m.check()
	}
}

// check is extracted so it can be called directly from tests.
func (m *TimeQualityMonitor) check() {
	r := rand.Float64()
	var next TimeQualityStatus
	switch {
	case r < 0.01:
		next = TQFailed
	case r < 0.05:
		next = TQDegraded
	default:
		next = TQOk
	}
	prev := TimeQualityStatus(m.status.Swap(int32(next)))
	if prev != next {
		log.Printf("[TimeQuality] status changed: %s → %s", prev, next)
	}
}
