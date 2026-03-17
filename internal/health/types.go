// Package health provides HTTP/HTTPS health check monitoring.
package health

import (
	"time"
)

// Status represents the health check status.
type Status int

const (
	StatusUnknown Status = iota
	StatusHealthy
	StatusUnhealthy
)

func (s Status) String() string {
	switch s {
	case StatusHealthy:
		return "healthy"
	case StatusUnhealthy:
		return "unhealthy"
	default:
		return "unknown"
	}
}

// Target represents a health check target configuration.
type Target struct {
	ID                int
	Hostname          string
	Port              int
	Path              string
	Scheme            string // "http" or "https"
	Mode              string
	Method            string
	ExpectedStatus    int
	Headers           map[string]string
	Interval          time.Duration
	UnhealthyInterval time.Duration
	Timeout           time.Duration
	TLSServerName     string
	Enabled           bool
}

// DefaultTarget returns a Target with default values.
func DefaultTarget() Target {
	return Target{
		Scheme:            "http",
		Mode:              "http",
		Method:            "GET",
		Path:              "/",
		ExpectedStatus:    200,
		Interval:          30 * time.Second,
		UnhealthyInterval: 10 * time.Second,
		Timeout:           5 * time.Second,
		Enabled:           true,
	}
}

// TargetStatus holds the current status of a health check target.
type TargetStatus struct {
	ID         int
	Status     Status
	StatusCode int
	Latency    time.Duration
	LastCheck  time.Time
	LastError  string
	CheckCount int
}

// StatusCallback is called when a target's status changes.
type StatusCallback func(statuses []TargetStatus)
