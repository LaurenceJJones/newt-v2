package relay

import (
	"testing"
	"time"
)

func TestActivityTrackerTouchAndExpiry(t *testing.T) {
	start := time.Unix(100, 0)
	tracker := NewActivityTracker(start)

	if tracker.Expired(start.Add(5*time.Second), 10*time.Second) {
		t.Fatal("expected tracker to remain active")
	}
	if !tracker.Expired(start.Add(11*time.Second), 10*time.Second) {
		t.Fatal("expected tracker to expire")
	}

	next := start.Add(20 * time.Second)
	tracker.Touch(next)
	if got := tracker.LastActive(); !got.Equal(next) {
		t.Fatalf("unexpected last active time: %v", got)
	}
	if tracker.Expired(next.Add(5*time.Second), 10*time.Second) {
		t.Fatal("expected refreshed tracker to remain active")
	}
}
