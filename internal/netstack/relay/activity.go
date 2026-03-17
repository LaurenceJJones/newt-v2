package relay

import (
	"sync/atomic"
	"time"
)

// ActivityTracker stores the last-observed activity time using Unix nanos.
type ActivityTracker struct {
	lastUnixNano atomic.Int64
}

func NewActivityTracker(now time.Time) *ActivityTracker {
	t := &ActivityTracker{}
	t.Touch(now)
	return t
}

func (t *ActivityTracker) Touch(now time.Time) {
	if t == nil {
		return
	}
	t.lastUnixNano.Store(now.UnixNano())
}

func (t *ActivityTracker) LastActive() time.Time {
	if t == nil {
		return time.Time{}
	}
	return time.Unix(0, t.lastUnixNano.Load())
}

func (t *ActivityTracker) Expired(now time.Time, timeout time.Duration) bool {
	if t == nil {
		return true
	}
	last := t.LastActive()
	if last.IsZero() {
		return true
	}
	return now.Sub(last) > timeout
}
