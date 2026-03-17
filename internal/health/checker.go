package health

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Checker performs health checks on a single target.
type Checker struct {
	target Target
	logger *slog.Logger
	client *http.Client

	// Current status
	mu         sync.RWMutex
	status     Status
	statusCode int
	latency    time.Duration
	lastCheck  time.Time
	lastError  string
	checkCount int

	// Callback for status changes
	onChange func(TargetStatus)

	// Lifecycle
	ctx    context.Context
	cancel context.CancelFunc
}

// NewChecker creates a new health checker for the given target.
func NewChecker(target Target, enforceTLS bool, logger *slog.Logger) *Checker {
	if logger == nil {
		logger = slog.Default()
	}

	// Setup HTTP client with TLS config
	tlsConfig := &tls.Config{
		ServerName:         target.TLSServerName,
		InsecureSkipVerify: !enforceTLS,
	}

	client := &http.Client{
		Timeout: target.Timeout,
		Transport: &http.Transport{
			TLSClientConfig:     tlsConfig,
			MaxIdleConns:        1,
			MaxIdleConnsPerHost: 1,
			IdleConnTimeout:     90 * time.Second,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Don't follow redirects
		},
	}

	return &Checker{
		target: target,
		logger: logger,
		client: client,
		status: StatusUnknown,
	}
}

// OnChange sets a callback for when the status changes.
func (c *Checker) OnChange(fn func(TargetStatus)) {
	c.onChange = fn
}

// Start begins performing health checks until ctx is cancelled.
func (c *Checker) Start(ctx context.Context) error {
	c.ctx, c.cancel = context.WithCancel(ctx)

	// Perform initial check
	c.check()
	c.notifyChange()

	// Determine initial interval
	interval := c.target.Interval
	if c.status == StatusUnhealthy {
		interval = c.target.UnhealthyInterval
	}

	timer := time.NewTimer(interval)
	defer timer.Stop()

	for {
		select {
		case <-c.ctx.Done():
			return c.ctx.Err()
		case <-timer.C:
			oldStatus := c.status
			c.check()

			if oldStatus != c.status {
				c.logger.Info("health status changed",
					"target", c.target.ID,
					"old", oldStatus,
					"new", c.status,
				)
				c.notifyChange()
			}

			// Adjust interval based on status
			if c.status == StatusUnhealthy {
				interval = c.target.UnhealthyInterval
			} else {
				interval = c.target.Interval
			}
			timer.Reset(interval)
		}
	}
}

// check performs a single health check.
func (c *Checker) check() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.checkCount++
	c.lastCheck = time.Now()

	url := fmt.Sprintf("%s://%s:%d%s",
		c.target.Scheme,
		c.target.Hostname,
		c.target.Port,
		c.target.Path,
	)

	// Create request
	req, err := http.NewRequestWithContext(c.ctx, c.target.Method, url, nil)
	if err != nil {
		c.status = StatusUnhealthy
		c.lastError = fmt.Sprintf("create request: %v", err)
		return
	}

	// Add custom headers
	for k, v := range c.target.Headers {
		if strings.EqualFold(k, "Host") {
			req.Host = v
			continue
		}
		req.Header.Set(k, v)
	}

	// Perform request
	start := time.Now()
	resp, err := c.client.Do(req)
	c.latency = time.Since(start)

	if err != nil {
		c.status = StatusUnhealthy
		c.lastError = fmt.Sprintf("request failed: %v", err)
		c.statusCode = 0
		return
	}
	defer resp.Body.Close()

	c.statusCode = resp.StatusCode
	c.lastError = ""

	// Check status code
	if c.target.ExpectedStatus > 0 && resp.StatusCode != c.target.ExpectedStatus {
		c.status = StatusUnhealthy
		c.lastError = fmt.Sprintf("unexpected status: got %d, want %d",
			resp.StatusCode, c.target.ExpectedStatus)
		return
	}

	// Success
	c.status = StatusHealthy
}

// notifyChange calls the onChange callback with current status.
func (c *Checker) notifyChange() {
	if c.onChange == nil {
		return
	}

	c.mu.RLock()
	status := TargetStatus{
		ID:         c.target.ID,
		Status:     c.status,
		StatusCode: c.statusCode,
		Latency:    c.latency,
		LastCheck:  c.lastCheck,
		LastError:  c.lastError,
		CheckCount: c.checkCount,
	}
	c.mu.RUnlock()

	c.onChange(status)
}

// Status returns the current target status.
func (c *Checker) Status() TargetStatus {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return TargetStatus{
		ID:         c.target.ID,
		Status:     c.status,
		StatusCode: c.statusCode,
		Latency:    c.latency,
		LastCheck:  c.lastCheck,
		LastError:  c.lastError,
		CheckCount: c.checkCount,
	}
}

// Stop stops the health checker.
func (c *Checker) Stop() {
	if c.cancel != nil {
		c.cancel()
	}
}
