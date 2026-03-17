package health

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/fosrl/newt/internal/control"
	"github.com/fosrl/newt/internal/lifecycle"
)

// Monitor manages health checks for multiple targets.
type Monitor struct {
	logger        *slog.Logger
	controlClient *control.Client
	enforceTLS    bool

	// Targets and checkers
	mu       sync.RWMutex
	checkers map[int]*activeChecker

	// Callback for status changes
	callback StatusCallback

	// Lifecycle
	group *lifecycle.Group
}

// activeChecker tracks a running health checker.
type activeChecker struct {
	target  Target
	checker *Checker
	cancel  context.CancelFunc
	stopped chan struct{}
}

func monitorConfigPayload(target Target) control.HealthCheckData {
	return control.HealthCheckData{
		ID:                target.ID,
		Enabled:           target.Enabled,
		Path:              target.Path,
		Scheme:            target.Scheme,
		Mode:              target.Mode,
		Hostname:          target.Hostname,
		Port:              target.Port,
		Interval:          int(target.Interval / time.Second),
		UnhealthyInterval: int(target.UnhealthyInterval / time.Second),
		Timeout:           int(target.Timeout / time.Second),
		Headers:           target.Headers,
		Method:            target.Method,
		Status:            target.ExpectedStatus,
		TLSServerName:     target.TLSServerName,
	}
}

// NewMonitor creates a new health monitor.
func NewMonitor(controlClient *control.Client, enforceTLS bool, logger *slog.Logger) *Monitor {
	if logger == nil {
		logger = slog.Default()
	}

	return &Monitor{
		logger:        logger,
		controlClient: controlClient,
		enforceTLS:    enforceTLS,
		checkers:      make(map[int]*activeChecker),
	}
}

// OnStatusChange sets a callback for when any target's status changes.
func (m *Monitor) OnStatusChange(fn StatusCallback) {
	m.callback = fn
}

// Name returns the component name.
func (m *Monitor) Name() string {
	return "health"
}

// Start initializes the health monitor and registers handlers.
func (m *Monitor) Start(ctx context.Context) error {
	m.group = lifecycle.NewGroup(ctx)
	m.startPendingCheckers()

	// Register message handlers
	m.controlClient.Register(control.MsgHealthCheckAdd, m.handleAdd)
	m.controlClient.Register(control.MsgHealthCheckRemove, m.handleRemove)
	m.controlClient.Register(control.MsgHealthCheckEnable, m.handleEnable)
	m.controlClient.Register(control.MsgHealthCheckDisable, m.handleDisable)
	m.controlClient.Register(control.MsgHealthCheckStatusReq, m.handleStatusRequest)

	m.logger.Info("health monitor started")

	// Wait for context cancellation
	<-ctx.Done()

	// Stop all checkers
	m.stopAll()

	return ctx.Err()
}

// startPendingCheckers starts any enabled health checks that were added before Start ran.
func (m *Monitor) startPendingCheckers() {
	m.mu.Lock()
	defer m.mu.Unlock()

	for id, ac := range m.checkers {
		if !ac.target.Enabled || ac.cancel != nil {
			continue
		}

		_, cancel := context.WithCancel(m.group.Context())
		stopped := make(chan struct{})
		ac.cancel = cancel
		ac.stopped = stopped

		checker := ac.checker
		target := ac.target
		m.group.Go(func(gctx context.Context) error {
			defer close(stopped)
			return checker.Start(gctx)
		})

		m.logger.Info("health check added",
			"target", id,
			"hostname", target.Hostname,
			"port", target.Port,
		)
	}
}

// handleAdd handles the health check add message.
func (m *Monitor) handleAdd(msg control.Message) error {
	var data struct {
		Targets []control.HealthCheckData `json:"targets"`
	}
	if err := json.Unmarshal(msg.Data, &data); err != nil {
		return fmt.Errorf("unmarshal health check add data: %w", err)
	}

	return m.AddTargets(data.Targets)
}

// handleRemove handles the health check remove message.
func (m *Monitor) handleRemove(msg control.Message) error {
	var data struct {
		IDs []int `json:"ids"`
	}
	if err := json.Unmarshal(msg.Data, &data); err != nil {
		return fmt.Errorf("unmarshal health check remove data: %w", err)
	}

	return m.removeTargets(data.IDs)
}

// handleEnable handles the health check enable message.
func (m *Monitor) handleEnable(msg control.Message) error {
	var data struct {
		ID int `json:"id"`
	}
	if err := json.Unmarshal(msg.Data, &data); err != nil {
		return fmt.Errorf("unmarshal health check enable data: %w", err)
	}

	return m.setEnabled(data.ID, true)
}

// handleDisable handles the health check disable message.
func (m *Monitor) handleDisable(msg control.Message) error {
	var data struct {
		ID int `json:"id"`
	}
	if err := json.Unmarshal(msg.Data, &data); err != nil {
		return fmt.Errorf("unmarshal health check disable data: %w", err)
	}

	return m.setEnabled(data.ID, false)
}

// handleStatusRequest handles the health check status request message.
func (m *Monitor) handleStatusRequest(msg control.Message) error {
	return m.sendStatus()
}

// parseTarget converts control.HealthCheckData to a Target.
func (m *Monitor) parseTarget(data control.HealthCheckData) Target {
	target := DefaultTarget()
	target.ID = data.ID
	target.Hostname = data.Hostname
	target.Port = data.Port
	target.Path = data.Path
	target.Enabled = data.Enabled

	if data.Scheme != "" {
		target.Scheme = data.Scheme
	}
	if data.Mode != "" {
		target.Mode = data.Mode
	}
	if data.Method != "" {
		target.Method = data.Method
	}
	if data.Status > 0 {
		target.ExpectedStatus = data.Status
	}
	if len(data.Headers) > 0 {
		target.Headers = data.Headers
	}
	if data.Interval > 0 {
		target.Interval = time.Duration(data.Interval) * time.Second
	}
	if data.UnhealthyInterval > 0 {
		target.UnhealthyInterval = time.Duration(data.UnhealthyInterval) * time.Second
	}
	if data.Timeout > 0 {
		target.Timeout = time.Duration(data.Timeout) * time.Second
	}
	if data.TLSServerName != "" {
		target.TLSServerName = data.TLSServerName
	}

	return target
}

// addTarget adds a new health check target.
func (m *Monitor) addTarget(target Target) error {
	m.mu.Lock()
	existing := m.checkers[target.ID]
	if existing != nil {
		delete(m.checkers, target.ID)
	}
	group := m.group
	m.mu.Unlock()

	if existing != nil {
		stopActiveChecker(existing)
	}

	// Create checker
	checker := NewChecker(target, m.enforceTLS, m.logger)
	checker.OnChange(func(status TargetStatus) {
		m.onStatusChange(status)
	})

	// Start if enabled and group is running
	if target.Enabled && group != nil {
		_, cancel := context.WithCancel(group.Context())
		stopped := make(chan struct{})

		ac := &activeChecker{
			target:  target,
			checker: checker,
			cancel:  cancel,
			stopped: stopped,
		}

		m.mu.Lock()
		m.checkers[target.ID] = ac
		m.mu.Unlock()

		group.Go(func(gctx context.Context) error {
			defer close(stopped)
			return checker.Start(gctx)
		})

		m.logger.Info("health check added",
			"target", target.ID,
			"hostname", target.Hostname,
			"port", target.Port,
		)
	} else {
		// Store disabled checker
		m.mu.Lock()
		m.checkers[target.ID] = &activeChecker{
			target:  target,
			checker: checker,
			stopped: make(chan struct{}),
		}
		m.mu.Unlock()
	}

	return nil
}

// removeTarget removes a health check target.
func (m *Monitor) removeTarget(id int) error {
	m.mu.Lock()
	ac := m.checkers[id]
	if ac != nil {
		delete(m.checkers, id)
	}
	m.mu.Unlock()

	if ac == nil {
		return nil
	}

	stopActiveChecker(ac)

	m.logger.Info("health check removed", "target", id)
	return nil
}

// setEnabled enables or disables a health check target.
func (m *Monitor) setEnabled(id int, enabled bool) error {
	m.mu.Lock()
	ac, ok := m.checkers[id]
	if !ok {
		m.mu.Unlock()
		return fmt.Errorf("target %d not found", id)
	}
	target := ac.target
	m.mu.Unlock()

	target.Enabled = enabled
	return m.addTarget(target)
}

// onStatusChange handles status change from a checker.
func (m *Monitor) onStatusChange(status TargetStatus) {
	// Send full status set to match legacy control-plane payloads.
	if err := m.sendStatus(); err != nil {
		m.logger.Warn("failed to send health status", "error", err)
	}

	// Call callback
	if m.callback != nil {
		m.callback([]TargetStatus{status})
	}
}

// sendStatus sends health check status to the server.
func (m *Monitor) sendStatus() error {
	if m.controlClient == nil {
		return nil
	}
	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.controlClient.SendData(context.Background(), control.MsgHealthCheckStatus, m.buildStatusPayloadLocked())
}

func (m *Monitor) buildStatusPayloadLocked() map[string]any {
	targets := make(map[int]any, len(m.checkers))
	for id, ac := range m.checkers {
		status := ac.checker.Status()
		targets[id] = map[string]any{
			"status":     status.Status.String(),
			"lastCheck":  status.LastCheck.Format(time.RFC3339),
			"checkCount": status.CheckCount,
			"lastError":  status.LastError,
			"config":     monitorConfigPayload(ac.target),
		}
	}

	return map[string]any{
		"targets": targets,
	}
}

// stopAll stops all health checkers.
func (m *Monitor) stopAll() {
	m.mu.Lock()
	checkers := make([]*activeChecker, 0, len(m.checkers))
	for id, ac := range m.checkers {
		checkers = append(checkers, ac)
		delete(m.checkers, id)
	}
	m.mu.Unlock()

	for _, ac := range checkers {
		stopActiveChecker(ac)
	}
}

// Shutdown gracefully shuts down the health monitor.
func (m *Monitor) Shutdown(ctx context.Context) error {
	m.stopAll()
	return nil
}

// Reset clears all active and pending health checks.
func (m *Monitor) Reset() {
	m.stopAll()
}

// TargetCount returns the number of tracked health check targets.
func (m *Monitor) TargetCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.checkers)
}

func stopActiveChecker(ac *activeChecker) {
	if ac == nil || ac.cancel == nil {
		return
	}

	ac.cancel()
	if ac.stopped != nil {
		<-ac.stopped
	}
}

// AddTargets adds multiple health check targets from initial configuration.
func (m *Monitor) AddTargets(targets []control.HealthCheckData) error {
	for _, data := range targets {
		target := m.parseTarget(data)
		if err := m.addTarget(target); err != nil {
			return fmt.Errorf("add target %d: %w", data.ID, err)
		}
	}
	return nil
}

func (m *Monitor) removeTargets(ids []int) error {
	for _, id := range ids {
		if err := m.removeTarget(id); err != nil {
			return err
		}
	}
	return nil
}

// SyncTargets reconciles the active health checks with the desired target set.
func (m *Monitor) SyncTargets(targets []control.HealthCheckData) error {
	desired := make(map[int]control.HealthCheckData, len(targets))
	for _, target := range targets {
		desired[target.ID] = target
	}

	for _, target := range targets {
		parsed := m.parseTarget(target)
		if err := m.addTarget(parsed); err != nil {
			return fmt.Errorf("sync target %d: %w", target.ID, err)
		}
	}

	m.mu.RLock()
	toRemove := make([]int, 0)
	for id := range m.checkers {
		if _, ok := desired[id]; !ok {
			toRemove = append(toRemove, id)
		}
	}
	m.mu.RUnlock()

	for _, id := range toRemove {
		if err := m.removeTarget(id); err != nil {
			return fmt.Errorf("remove stale target %d: %w", id, err)
		}
	}

	return nil
}
